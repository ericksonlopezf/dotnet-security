# Security & Cryptography Cookbook — EricksonLopez.Security

> **Version**: v1.1.0  
> **Target Frameworks**: .NET 8.0 \| .NET 9.0 \| .NET 10.0  
> **Format**: Problem $\rightarrow$ Solution $\rightarrow$ Code Example $\rightarrow$ Technical Explanation $\rightarrow$ Common Pitfalls.

---

## Recipe Table of Contents

1. [Recipe 1: Encrypting and Decrypting PII with Automatic Key Lifecycle](#recipe-1-encrypting-and-decrypting-pii-with-automatic-key-lifecycle)
2. [Recipe 2: Zero-Downtime Hot Key Rotation with Historical Decryption](#recipe-2-zero-downtime-hot-key-rotation-with-historical-decryption)
3. [Recipe 3: Password Storage and Verification with Argon2id and Auto-Rehash](#recipe-3-password-storage-and-verification-with-argon2id-and-auto-rehash)
4. [Recipe 4: Issuing and Verifying Scoped API Keys](#recipe-4-issuing-and-verifying-scoped-api-keys)
5. [Recipe 5: Multi-Factor Authentication (2FA) with RFC 6238 TOTP](#recipe-5-multi-factor-authentication-2fa-with-rfc-6238-totp)
6. [Recipe 6: Preventing Server-Side Request Forgery (SSRF) in Outbound HTTP](#recipe-6-preventing-server-side-request-forgery-ssrf-in-outbound-http)
7. [Recipe 7: Hardening ASP.NET Core with Security Response Headers](#recipe-7-hardening-aspnet-core-with-security-response-headers)
8. [Recipe 8: Dynamic Zero Trust Attribute-Based Access Control (ABAC)](#recipe-8-dynamic-zero-trust-attribute-based-access-control-abac)
9. [Recipe 9: Zero-Allocation In-Memory Encryption with `SecretBuffer`](#recipe-9-zero-allocation-in-memory-encryption-with-secretbuffer)
10. [Recipe 10: Multi-Cloud KMS Integration (Azure, AWS, HashiCorp Vault & Google Cloud)](#recipe-10-multi-cloud-kms-integration-azure-aws-hashicorp-vault--google-cloud)
11. [Recipe 11: Zero-Downtime Password Hash Algorithm Migration (Argon2id Upgrade)](#recipe-11-zero-downtime-password-hash-algorithm-migration-argon2id-upgrade)
12. [Recipe 12: Multi-Scheme Secret Resolution with CompositeSecretResolver](#recipe-12-multi-scheme-secret-resolution-with-compositesecretresolver)
13. [Recipe 13: Token Hashing for Database-Safe Storage](#recipe-13-token-hashing-for-database-safe-storage)
14. [Recipe 14: Hardened XML Digital Signature Verification with Anti-XSW Defenses](#recipe-14-hardened-xml-digital-signature-verification-with-anti-xsw-defenses)
15. [Recipe 15: Outbound Webhook Security with SafeHttpClientFactory](#recipe-15-outbound-webhook-security-with-safehttpclientfactory)
16. [Recipe 16: Tenant-Scoped Encrypted Fields with `AuthenticatedContext`](#recipe-16-tenant-scoped-encrypted-fields-with-authenticatedcontext)
17. [Recipe 17: Zero-String Password Capture with `SecretBuffer.FromUtf8`](#recipe-17-zero-string-password-capture-with-secretbufferfromutf8)
18. [Recipe 18: SSRF-Safe Hostname Resolution with `SafeDnsResolver`](#recipe-18-ssrf-safe-hostname-resolution-with-safednsresolver)

---

## Recipe 1: Encrypting and Decrypting PII with Automatic Key Lifecycle

### Problem
You need to store Personally Identifiable Information (PII) or credit card tokens complying with PCI-DSS and GDPR, ensuring confidentiality, integrity, and tenant context isolation.

### Solution
Use `ISecretProtector` registered via `AddEricksonLopezSecurity()`. The protector wraps AES-256-GCM and generates a versioned binary security envelope (`SecurityEnvelope`).

### Code Example
```csharp
using System.Text;
using EricksonLopez.Security;
using EricksonLopez.Security.Abstractions.Cryptography;
using EricksonLopez.Security.Abstractions.KeyManagement;
using EricksonLopez.Security.Abstractions.Secrets;
using Microsoft.Extensions.DependencyInjection;

// 1. Configure Dependency Injection
var services = new ServiceCollection();
services.AddEricksonLopezSecurity();
using var provider = services.BuildServiceProvider();

var keyLifecycle = provider.GetRequiredService<IKeyLifecycleManager>();
var protector = provider.GetRequiredService<ISecretProtector>();

// Ensure an active key exists for SecretProtection
await keyLifecycle.GenerateAndActivateKeyAsync(KeyPurpose.SecretProtection);

// 2. Protect sensitive data with tenant context (Associated Data - AAD)
byte[] plaintext = Encoding.UTF8.GetBytes("TaxId: 123-45-6789; Card: 4111-2222-3333-4444");
// AuthenticatedContext is a strongly-typed AAD struct — use ForTenant() to bind the tenant identifier
var tenantContext = AuthenticatedContext.ForTenant("hospital-42");

var protectResult = await protector.ProtectAsync(
    secret: plaintext,
    purpose: KeyPurpose.SecretProtection,
    expectedAssociatedData: tenantContext);
if (protectResult.IsFailure)
{
    Console.WriteLine($"Encryption error: {protectResult.Error.Description}");
    return;
}

byte[] encryptedEnvelope = protectResult.Value;

// 3. Unprotect sensitive data
var unprotectResult = await protector.UnprotectAsync(
    protectedData: encryptedEnvelope,
    expectedAssociatedData: tenantContext);
if (unprotectResult.IsSuccess)
{
    string recovered = Encoding.UTF8.GetString(unprotectResult.Value);
    Console.WriteLine($"Recovered PII: {recovered}");
}

// 4. Zero-allocation synchronous span overload
var syncResult = protector.Protect(
    secret: plaintext.AsSpan(),
    purpose: KeyPurpose.SecretProtection,
    expectedAssociatedData: tenantContext);
```

### Technical Explanation
- The protector binds the `tenantContext` as Authenticated Associated Data (AAD). If an attacker attempts to replay the ciphertext in a different tenant context, decryption fails immediately with `SecurityError.AuthenticationTagMismatch`.
- Nonce generation is guaranteed unique via the system CSPRNG.

### Common Pitfalls
- **Mismatched AAD**: Supplying different AAD bytes during `UnprotectAsync` results in authentication tag mismatch. Always store or reconstruct the exact context.

---

## Recipe 2: Zero-Downtime Hot Key Rotation with Historical Decryption

### Problem
Compliance regulations mandate quarterly cryptographic key rotation without invalidating encrypted historical database records.

### Solution
Invoke `IKeyLifecycleManager.RotateKeyAsync()`. The previous active key transitions to `Retired` (read-only for legacy decryption), while a newly generated version becomes `Active` for all new encryptions.

### Code Example
```csharp
var keyLifecycle = provider.GetRequiredService<IKeyLifecycleManager>();
var protector = provider.GetRequiredService<ISecretProtector>();

// 1. Encrypt payload with Version 1
byte[] v1Envelope = (await protector.ProtectAsync(secret: Encoding.UTF8.GetBytes("Record-V1"), purpose: KeyPurpose.SecretProtection)).Value;

// 2. Perform Hot Key Rotation
var rotateResult = await keyLifecycle.RotateKeyAsync(KeyPurpose.SecretProtection);
Console.WriteLine($"New Active Key Version: {rotateResult.Value.Metadata.Version.Value}");

// 3. Encrypt payload with Version 2
byte[] v2Envelope = (await protector.ProtectAsync(secret: Encoding.UTF8.GetBytes("Record-V2"), purpose: KeyPurpose.SecretProtection)).Value;

// 4. Decrypt both payloads seamlessly
var decryptV1 = await protector.UnprotectAsync(protectedData: v1Envelope);
var decryptV2 = await protector.UnprotectAsync(protectedData: v2Envelope);

// Both succeed: v1 resolves retired key v1; v2 resolves active key v2
```

---

## Recipe 3: Password Storage and Verification with Argon2id and Auto-Rehash

### Problem
You need to upgrade legacy PBKDF2 password hashes to modern memory-hard Argon2id without requiring users to reset their passwords.

### Solution
Inject `IPasswordHasher` (implemented by `CompositePasswordHasher`). It detects algorithm prefixes in Modular Crypt Format (MCF) and returns `PasswordVerificationResult.SuccessRehashNeeded` when an older hash algorithm is encountered.

### Code Example
```csharp
using EricksonLopez.Security.Abstractions.Passwords;

var passwordHasher = provider.GetRequiredService<IPasswordHasher>();

// 1. Simulate existing user verification
string candidatePassword = "UserEnteredPassword!2026";
string storedHashFromDb = userRecord.PasswordHash;

// Constant-time evaluation accepting ReadOnlySpan<char>
var verification = passwordHasher.VerifyPassword(candidatePassword.AsSpan(), storedHashFromDb);

if (verification == PasswordVerificationResult.Success)
{
    // Authenticated with modern parameters
}
else if (verification == PasswordVerificationResult.SuccessRehashNeeded || passwordHasher.NeedsRehash(storedHashFromDb))
{
    // Authenticated! Transparently upgrade hash in database to primary hasher (PBKDF2 default or Argon2id)
    string newHash = passwordHasher.HashPassword(candidatePassword.AsSpan());
    await db.UpdatePasswordHashAsync(userRecord.Id, newHash);
}
else
{
    // Invalid credentials
}
```

---

## Recipe 4: Issuing and Verifying Scoped API Keys

### Problem
You need to issue API keys to microservices or third-party developers with granular scopes (`orders:read`, `payments:write`) and store them securely against database dump exfiltration.

### Solution
Use `IApiKeyGenerator` and `IApiKeyValidator`. The generator returns a structured key `{prefix}_{idHex16}_{secret24}` once, while persisting only the SHA-256 digest.

### Code Example
```csharp
using EricksonLopez.Security.Abstractions.Tokens;

var generator = provider.GetRequiredService<IApiKeyGenerator>();
var validator = provider.GetRequiredService<IApiKeyValidator>();
var store = provider.GetRequiredService<IApiKeyStore>();

// 1. Issue key
var issuance = generator.GenerateApiKey(
    ownerId: "tenant-cust-99",
    name: "Stripe Webhook Worker",
    prefix: "ek_live",
    lifetime: TimeSpan.FromDays(365),
    scopes: new HashSet<string> { "orders:read", "webhooks:receive" });

// Display plaintext key to user ONCE
Console.WriteLine($"Plaintext Key (Copy Now): {issuance.PlaintextApiKey}");

// Persist the hashed entity
await store.SaveAsync(issuance.Key);

// 2. Validate key in API pipeline
var validationResult = await validator.ValidateApiKeyAsync(issuance.PlaintextApiKey);
if (validationResult.IsSuccess)
{
    var apiKey = validationResult.Value;
    bool hasPermission = apiKey.HasScope("orders:read");
}
```

---

## Recipe 5: Multi-Factor Authentication (2FA) with RFC 6238 TOTP

### Problem
Implement two-factor authentication compatible with Google Authenticator, Microsoft Authenticator, and 1Password, including backup single-use recovery codes.

### Solution
Inject `ITotpService` from `EricksonLopez.Security.Mfa` and use the static utility `RecoveryCodeGenerator`.

### Code Example
```csharp
using EricksonLopez.Security.Mfa;

var totpService = provider.GetRequiredService<ITotpService>();
var recoveryGenerator = provider.GetRequiredService<IRecoveryCodeGenerator>();

// 1. Enrollment: Generate secret and URI
string secretKey = totpService.GenerateSecretKey(20);
TotpSetupInfo setupInfo = totpService.GenerateSetupInfo(
    issuer: "MyEnterpriseApp",
    accountName: "user@example.com",
    secretKey: secretKey);

string otpauthUri = setupInfo.AuthenticatorUri;

// Generate 8 emergency recovery codes via injectable service (ADR-029)
string[] recoveryCodes = recoveryGenerator.GenerateCodes(count: 8);

// 2. Verification during login
string userEnteredCode = "123456";
bool isValid = totpService.VerifyCode(secretKey, userEnteredCode);
```

---

## Recipe 6: Preventing Server-Side Request Forgery (SSRF) in Outbound HTTP

### Problem
Your service fetches URLs submitted by users (e.g. webhooks, avatar import). Attackers may submit `http://169.254.169.254/latest/meta-data` or `http://127.0.0.1:5432` to exfiltrate cloud credentials.

### Solution
Configure your outbound `HttpClient` with `SafeSocketsHttpHandler` from `EricksonLopez.Security.Network`.

### Code Example
```csharp
using EricksonLopez.Security.Network;

var ssrfOptions = new SsrfProtectionOptions
{
    BlockLoopback = true,
    BlockPrivateNetworks = true, // RFC 1918 (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
    BlockLinkLocal = true,       // 169.254.0.0/16
    AllowedPorts = { 80, 443 }
};

using var handler = new SafeSocketsHttpHandler(ssrfOptions);
using var client = new HttpClient(handler);

// Outbound request to cloud metadata will be terminated at socket connect time:
var response = await client.GetAsync("https://webhook.customer.com/callback");
```

---

## Recipe 7: Hardening ASP.NET Core with Security Response Headers

### Problem
Ensure all API and MVC responses include strict HTTP security headers (CSP, HSTS, X-Content-Type-Options, Frame-Ancestors) to satisfy OWASP ASVS and browser security audits.

### Solution
Register `AddSecurityAspNetCore()` and invoke `UseSecurityHeaders()`.

### Code Example
```csharp
using EricksonLopez.Security.AspNetCore;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddEricksonLopezSecurity();
// AddSecurityAspNetCore accepts two separate optional action delegates:
// configureHeaders: Action<SecurityHeadersOptions> and configureApiKeyAuth: Action<ApiKeyAuthenticationOptions>
builder.Services.AddSecurityAspNetCore(
    configureHeaders: options =>
    {
        options.ContentSecurityPolicy = "default-src 'self'; frame-ancestors 'none'; object-src 'none';";
        options.StrictTransportSecurity = "max-age=31536000; includeSubDomains; preload";
        options.XContentTypeOptions = "nosniff";
        options.XFrameOptions = "DENY";
        options.ReferrerPolicy = "strict-origin-when-cross-origin";
    });

var app = builder.Build();

app.UseSecurityHeaders();
app.MapGet("/api/health", () => Results.Ok(new { status = "healthy" }));
app.Run();
```

---

## Recipe 8: Dynamic Zero Trust Attribute-Based Access Control (ABAC)

### Problem
Role-Based Access Control (RBAC) is insufficient: authorization decisions depend dynamically on resource sensitivity, classification, time of day, and network security level.

### Solution
Use `AbacPolicyEngine` from `EricksonLopez.Security.ZeroTrust` with Deny-Overrides resolution.

### Code Example
```csharp
using EricksonLopez.Security.ZeroTrust;

var engine = provider.GetRequiredService<IAbacPolicyEngine>();

var context = new AbacContext(
    subjectAttributes: new Dictionary<string, object>
    {
        ["role"] = "FinancialAuditor",
        ["clearanceLevel"] = 3
    },
    resourceAttributes: new Dictionary<string, object>
    {
        ["resourceType"] = "QuarterlyLedger",
        ["confidentiality"] = "High",
        ["tenantId"] = "finance-corp"
    },
    environmentAttributes: new Dictionary<string, object>
    {
        ["networkZone"] = "CorporateVPN",
        ["hourOfDay"] = 14
    });

var decision = engine.Evaluate(context, registeredPolicies);

if (decision == AbacDecision.Permit)
{
    // Access granted
}
```

---

## Recipe 9: Zero-Allocation In-Memory Encryption with `SecretBuffer`

### Problem
High-throughput services encrypting thousands of payloads per second must avoid garbage collection pressure and ensure key material is scrubbed from RAM.

### Solution
Use span overloads of `IAuthenticatedEncryptionEngine` and allocate buffers using stackalloc or `SecretBuffer`.

### Code Example
```csharp
using System.Security.Cryptography;
using EricksonLopez.Security.Abstractions.Cryptography;
using EricksonLopez.Security.Memory;

var engine = provider.GetRequiredService<IAuthenticatedEncryptionEngine>();

// Allocate key in managed pool with guaranteed zeroing on disposal
using var secretKey = new SecretBuffer(32);
RandomNumberGenerator.Fill(secretKey.GetWritableSpan());

ReadOnlySpan<byte> plaintext = stackalloc byte[] { 0x01, 0x02, 0x03, 0x04 };
ReadOnlySpan<byte> nonce = stackalloc byte[12];
Span<byte> ciphertext = stackalloc byte[plaintext.Length];
Span<byte> tag = stackalloc byte[16];

// Direct span encryption - 0 Bytes allocated on GC heap
var result = engine.Encrypt(plaintext, secretKey.Span, default);
```

---

## Recipe 10: Multi-Cloud KMS Integration (Azure, AWS, HashiCorp Vault & Google Cloud)

### Problem
Store master keys in managed cloud HSM services (Azure Key Vault, AWS KMS, HashiCorp Vault, Google Cloud KMS) while keeping the same application code across cloud providers.

### Solution
Swap the satellite adapter package in your service registration without altering business logic.

> [!NOTE]
> **Implementation Status (v1.x)**: In v1.x, the cloud adapters (`EricksonLopez.Security.Azure`, `Aws`, `HashiCorpVault`, `GoogleCloud`) provide high-performance in-memory implementations that model the `IKeyStore` and `ISecretStore` contracts for development, testing, and architecture decoupling. Direct HTTP/gRPC integration with cloud vendor SDKs is scheduled for v2.x.

### Code Example
For Azure Key Vault:
```csharp
using Microsoft.Extensions.DependencyInjection;
using EricksonLopez.Security.Azure;

builder.Services.AddAzureKeyVaultSecurity(options =>
{
    options.VaultUri = new Uri("https://my-company-vault.vault.azure.net/");
    options.SecretPrefix = "app-";
    options.EnableDevelopmentInMemoryStub = true;
});
```

For AWS KMS & Secrets Manager:
```csharp
using Microsoft.Extensions.DependencyInjection;
using EricksonLopez.Security.Aws;

builder.Services.AddAwsSecurity(options =>
{
    options.KmsKeyId = "arn:aws:kms:us-east-1:123456789012:key/4fecdac2-ba87-4e98";
    options.Region = "us-east-1";
    options.SecretPrefix = "prod/";
    options.EnableDevelopmentInMemoryStub = true;
});
```

For HashiCorp Vault (Transit & KV v2):
```csharp
using Microsoft.Extensions.DependencyInjection;
using EricksonLopez.Security.HashiCorpVault;

builder.Services.AddHashiCorpVaultSecurity(options =>
{
    options.VaultUrl = new Uri("https://vault.internal.corp:8200/");
    options.TransitMountPath = "transit";
    options.KvMountPath = "secret";
    options.SecretPathPrefix = "app-security/";
    options.EnableDevelopmentInMemoryStub = true;
});
```

For Google Cloud KMS & Secret Manager:
```csharp
using Microsoft.Extensions.DependencyInjection;
using EricksonLopez.Security.GoogleCloud;

builder.Services.AddGoogleCloudSecurity(options =>
{
    options.ProjectId = "enterprise-sec-prod";
    options.LocationId = "global";
    options.KeyRingId = "banking-keys";
    options.SecretPrefix = "sec_";
    options.EnableDevelopmentInMemoryStub = true;
});
```
Your business logic continues injecting `IKeyStore` or `ISecretProtector` identically.

---

## Recipe 11: Zero-Downtime Password Hash Algorithm Migration (Argon2id Upgrade)

### Problem
You have a production system using PBKDF2 for password hashing and need to migrate to Argon2id without forcing all users to reset their passwords and without a maintenance window.

### Solution
Use `CompositePasswordHasher` to transparently route verification to the correct algorithm based on the modular crypt format prefix. Users with legacy PBKDF2 hashes receive `SuccessRehashNeeded`, which your login handler uses to transparently upgrade the stored hash to Argon2id on the next successful login.

### Code Example
```csharp
using EricksonLopez.Security.Passwords;
using EricksonLopez.Security.Abstractions.Passwords;

// Configure CompositePasswordHasher with Argon2id as primary
var argon2Primary = new Argon2idPasswordHasher(
    memorySizeKb: 65536,  // 64MB
    iterations: 3,
    parallelism: 4);

var passwordHasher = new CompositePasswordHasher(
    primaryHasher: argon2Primary,
    additionalHashers: [Pbkdf2PasswordHasher.Default]);

// Login flow
async Task<bool> AuthenticateAsync(string username, string plainPassword, string storedHash)
{
    var result = passwordHasher.VerifyPassword(plainPassword.AsSpan(), storedHash);

    if (result == PasswordVerificationResult.Failed)
    {
        return false;
    }

    if (result == PasswordVerificationResult.SuccessRehashNeeded)
    {
        // Transparently upgrade hash on successful login
        var newHash = passwordHasher.HashPassword(plainPassword.AsSpan());
        await SaveUpdatedHash(username, newHash);  // persist Argon2id hash
    }

    return true;
}
```

### Common Pitfalls
- **Never delete legacy hashers from the composite** until all users have authenticated at least once after the migration.
- **Don't lock NeedsRehash checks** — `CompositePasswordHasher.NeedsRehash()` always delegates to the primary hasher's criteria.

---

## Recipe 12: Multi-Scheme Secret Resolution with CompositeSecretResolver

### Problem
Your application needs to load secrets from multiple backends — environment variables in local development, and a KMS/Vault store in production — using a single consistent URI-based API.

### Solution
Use `CompositeSecretResolver` with prefixed URI schemes. The resolver automatically dispatches to the correct backend based on the `env:`, `store:`, or `raw:` URI prefix.

### Code Example
```csharp
using EricksonLopez.Security.Secrets;
using EricksonLopez.Security.Abstractions.Secrets;

// Build resolver with env: and store: backends
var envStore = new EnvironmentSecretStore(prefix: "APP_");
var resolver = new CompositeSecretResolver(secretStore: myDatabaseSecretStore, envStore: envStore);

// Resolve from environment variable (local/CI)
var dbPassword = await resolver.ResolveAsync("env:Database:Password");
if (dbPassword.IsSuccess)
{
    Console.WriteLine(dbPassword.Value.UnsafeValue);  // explicit opt-in to access value
}

// Resolve from registered store (production Vault/KMS)
var apiKey = await resolver.ResolveAsync("store:third-party-api-key");

// Resolve inline (unit tests only — never use in production)
var testSecret = await resolver.ResolveAsync("raw:SuperSecretForTestsOnly");
```

### Technical Explanation
- `raw:` — Direct value passthrough. Zero I/O. Dev and test only.
- `env:VAR_NAME` — Reads `APP_VAR_NAME` from environment. Key normalization: `.`, `:`, `-` → `_`, UPPER_CASE.
- `store:SECRET_NAME` — Delegates to the injected `ISecretStore` (Azure Key Vault, AWS Secrets Manager, HashiCorp Vault, etc.).
- Default (no scheme) — Delegates directly to `ISecretStore`.

---

## Recipe 13: Token Hashing for Database-Safe Storage

### Problem
You need to issue opaque security tokens (session tokens, API tokens, etc.) and store them for later validation without exposing the plaintext token if the database is compromised.

### Solution
Use `HmacSha256TokenHasher` with a server-side pepper key. Store only the hash. When validating, rehash the candidate token and compare in constant time.

### Code Example
```csharp
using EricksonLopez.Security.Tokens;
using EricksonLopez.Security.Randomness;

// Initialize with pepper key loaded from KMS (never hardcoded)
var pepperKey = LoadPepperFromKms();  // byte[32]
var tokenHasher = new HmacSha256TokenHasher(pepperKey);

// Issue token
var rawToken = CryptographicRandom.Shared.GenerateHexToken(32);  // 64-char hex string
var tokenHash = tokenHasher.HashToken(rawToken.AsSpan());

// Persist only the hash to database
await db.ExecuteAsync(
    "INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (@hash, @uid, @exp)",
    new { hash = tokenHash, uid = userId, exp = DateTime.UtcNow.AddDays(30) });

// Send rawToken to the user (never the hash)
var cookieValue = $"session={rawToken}";

// Validation flow
var candidateToken = GetTokenFromRequest(httpContext);
var storedHash = await db.QuerySingleAsync<string>(
    "SELECT token_hash FROM sessions WHERE token_hash = @hash",
    new { hash = tokenHasher.HashToken(candidateToken.AsSpan()) });

bool isValid = tokenHasher.VerifyToken(candidateToken.AsSpan(), storedHash);
```

### Technical Explanation
- **Pepper key** (`HmacSha256TokenHasher(pepperKey)`) adds a server-side HMAC secret. Even if the database is dumped, the attacker cannot reverse the hashes without the pepper key.
- **Without pepper** (`new HmacSha256TokenHasher()`) uses plain SHA-256. Adequate for non-credential tokens where no server-side secret is available.
- **Constant-time comparison**: `VerifyToken` uses `ConstantTimeComparer.FixedTimeEquals` — resistant to timing side-channel attacks.
- **Never store or log the raw token**. Only persist the hex hash.

---

## Recipe 14: Hardened XML Digital Signature Verification with Anti-XSW Defenses

### Problem
You need to verify XML documents or SAML 2.0 assertions that include digital signatures (W3C XML-DSig / RFC 3275), but traditional validators are vulnerable to XML Signature Wrapping (XSW) attacks where attackers inject malicious elements outside the signed node.

### Solution
Use `IXmlDigitalSignatureVerifier` / `XmlDigitalSignatureVerifier`. It validates signatures against custom trust anchors and extracts the authentic signed `XmlElement` safely.

### Code Example
```csharp
using System.Security.Cryptography.X509Certificates;
using System.Xml;
using EricksonLopez.Security.Cryptography.XmlDSig;

IXmlDigitalSignatureVerifier verifier = XmlDigitalSignatureService.Instance;

// Load untrusted XML document
var xmlDoc = new XmlDocument { PreserveWhitespace = true };
xmlDoc.LoadXml(rawXmlPayload);

// Configure verification options with custom trust anchors
var options = new XmlVerificationOptions();
options.CustomTrustAnchors.Add(trustedRootCertificate);

// Verify signature and extract genuine signed element
XmlVerificationResult result = verifier.VerifyAndExtractSignedElement(xmlDoc, options);

if (!result.IsValid)
{
    throw new InvalidOperationException($"XML signature verification failed: {result.FailureReason}");
}

// Consume only the securely verified element
XmlElement signedNode = result.SignedElement!;
Console.WriteLine($"Verified node: {signedNode.Name}, Signer: {result.SigningCertificate?.Subject}");
```

### Technical Explanation
- Anti-XSW validation ensures that the signature covers the intended payload and prevents clone/relocation vulnerabilities.
- `XmlVerificationOptions` allows specifying pinned trust anchors (`CustomTrustAnchors`) rather than relying on machine-wide roots.

### Common Pitfalls
- **Ignoring SignedElement**: Consuming nodes from the outer unverified DOM tree rather than `result.SignedElement` allows XSW spoofing. Always process `result.SignedElement`.

---

## Recipe 15: Outbound Webhook Security with SafeHttpClientFactory

### Problem
Your microservice invokes external webhook URLs provided by end-users or third parties. Without strict validation, attackers can supply `http://169.254.169.254/` (cloud metadata) or `http://127.0.0.1:6379` (internal Redis) to execute Server-Side Request Forgery (SSRF) attacks.

### Solution
Use `SafeHttpClientFactory.CreateClient()` with strict hostname allowlists and IP range blocking.

### Code Example
```csharp
using System.Net.Http.Json;
using EricksonLopez.Security.Network;

// Create hardened client with strict hostname filtering
using HttpClient client = SafeHttpClientFactory.CreateClient(options =>
{
    options.RestrictToAllowedHostnames = true;
    options.AllowedHostnames.Add("webhook.trusted-partner.com");
    options.AllowedHostnames.Add("api.partner-service.org");
});

// Outbound request is validated at socket connection time
var response = await client.PostAsJsonAsync("https://webhook.trusted-partner.com/events", new
{
    EventType = "payment.completed",
    Amount = 450.00m
});
```

### Technical Explanation
- `SafeSocketsHttpHandler` hooks into socket creation and validates the resolved IP address immediately prior to connection establishment.
- Mitigates DNS rebinding: Even if a malicious domain points initially to a public IP and rebinds to `127.0.0.1`, the socket validator catches and aborts the connection.

### Common Pitfalls
- **Relying solely on URL string checks**: Attackers use DNS rebinding or alternate representations (`http://0x7f000001/`). Always validate resolved IP addresses at the socket level.

---

## Recipe 16: Real-Time Key Revocation Notification & Immediate Cache Eviction in Clusters

### Problem
When a cryptographic key is compromised, relying on cache TTL expiration leaves a critical vulnerability window where revoked keys can still be used for encryption or decryption until the in-memory cache expires.

### Solution
Use `IKeyRevocationNotifier` and `InProcessKeyRevocationNotifier` combined with `KeyLifecycleManager` and `KeyRing`. When `RevokeKeyAsync()` is called, the manager broadcasts a revocation signal, and all registered `KeyRing` instances immediately scrub sensitive key material with `CryptographicOperations.ZeroMemory()` and evict the key from cache without waiting for TTL expiration.

### Code Example
```csharp
using System;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using EricksonLopez.Security.Abstractions.KeyManagement;
using EricksonLopez.Security.Abstractions.Primitives;
using EricksonLopez.Security.KeyManagement;

// 1. Configure DI with real-time revocation notifier
var services = new ServiceCollection();
services.AddEricksonLopezSecurity(); // Registers IKeyRevocationNotifier and InProcessKeyRevocationNotifier
using var sp = services.BuildServiceProvider();

var keyLifecycle = sp.GetRequiredService<IKeyLifecycleManager>();
var keyRing = sp.GetRequiredService<IKeyRing>();
var notifier = sp.GetRequiredService<IKeyRevocationNotifier>();

// 2. Subscribe an optional distributed bus listener or logging audit
using var subscription = notifier.Subscribe((revokedKeyId, version, purpose) =>
{
    Console.WriteLine($"[EMERGENCY REVOCATION] Key {revokedKeyId}:{version} revoked for purpose {purpose}. Evicting cache.");
});

// 3. Generate and activate key
var key = (await keyLifecycle.GenerateAndActivateKeyAsync(KeyPurpose.SecretProtection)).Value;

// 4. Warm cache in KeyRing
using var activeKey = (await keyRing.GetActiveKeyAsync(KeyPurpose.SecretProtection)).Value;

// 5. Emergency revocation (broadcasts to notifier and evicts cache immediately)
var result = await keyLifecycle.RevokeKeyAsync(
    key.Metadata.KeyId,
    key.Metadata.Version,
    "Compromise suspected in Security Incident #SEC-2026-0042");

// 6. Next attempt to retrieve the active key from KeyRing immediately fails
var check = await keyRing.GetActiveKeyAsync(KeyPurpose.SecretProtection);
// check.IsFailure is true!
```

### Technical Explanation
- `IKeyRevocationNotifier.NotifyRevokedAsync(keyId, version, purpose)` notifies all in-process and distributed listeners.
- `KeyRing` subscribes to the notifier and immediately invokes `InvalidateKey(keyId, version)` and `InvalidateActiveKey(purpose)`.
- `InvalidateKey`, `InvalidateActiveKey`, and `InvalidateAll` ensure zero-memory scrubbing before removing references from the cache dictionary.
- Fully compatible with distributed brokers (Redis Pub/Sub, RabbitMQ, Kafka) by implementing `IKeyRevocationNotifier`.

### Common Pitfalls
- **Relying solely on cache TTL**: Under an active incident, seconds matter. Always configure a notifier when using cached `KeyRing` instances in production.

---

## Recipe 17: Multi-Node Distributed TOTP Replay Prevention using DelegateTotpReplayStore

### Problem
In multi-node load-balanced deployments, an attacker who intercepts a 2FA TOTP code within its valid 30-second window can replay the token against a different backend node if replay state is only tracked in-memory.

### Solution
Use `AddDistributedTotpReplayStore()` or `DelegateTotpReplayStore` to connect your TOTP verification pipeline to a distributed cluster cache (e.g. Redis, distributed memory cache, or database).

### Code Example
```csharp
using System;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using EricksonLopez.Security.Mfa;

var services = new ServiceCollection();
services.AddSecurityMfa();

// Option A: Wire a distributed store handler (e.g., Redis IDatabase.StringSetAsync with NX)
services.AddDistributedTotpReplayStore(
    asyncHandler: async (key, expiresAt, cancellationToken) =>
    {
        var ttl = expiresAt - DateTimeOffset.UtcNow;
        if (ttl <= TimeSpan.Zero) return false;

        // Atomic distributed set-if-not-exists:
        // bool set = await redisDb.StringSetAsync(key, "1", ttl, When.NotExists);
        // return set;
        return await Task.FromResult(true); // simulated distributed atomic set
    },
    syncHandler: (key, expiresAt) =>
    {
        // Optional synchronous handler for non-async callers
        return true;
    });

using var sp = services.BuildServiceProvider();
var totpService = sp.GetRequiredService<ITotpService>();

// Verification with PreventReplay = true
var options = new TotpOptions { PreventReplay = true };
bool isValid = await totpService.VerifyCodeAsync(userSecretKey, candidateToken, DateTimeOffset.UtcNow, options);
```

### Technical Explanation
- `ITotpReplayStore` defines the contract for recording consumed token fingerprints (`user_or_secret:timestamp_step`).
- `DelegateTotpReplayStore` avoids the overhead of creating boilerplate wrapper classes for distributed caches like Redis or Memcached.
- The store records the key with an automatic TTL matching the time-step window, preventing replay across any cluster node.

### Common Pitfalls
- **Forgetting PreventReplay = true**: In `TotpOptions`, `PreventReplay` must be explicitly enabled to trigger store checks.

---

## Recipe 16: Tenant-Scoped Encrypted Fields with `AuthenticatedContext`

### Problem
In a multi-tenant SaaS application, encrypted database fields must be cryptographically bound to their owning tenant. A tenant with access to one ciphertext must not be able to decrypt another tenant's data, even if the underlying encryption key is shared.

### Solution
Use `AuthenticatedContext.ForTenant(tenantId)` to produce tenant-specific Associated Authenticated Data (AAD). Pass the resulting `Span<byte>` as AAD to `ISecretProtector.ProtectAsync`. Any decryption attempt using a different tenant's context will fail with `SecurityError.AuthenticationTagMismatch` — which is the AES-GCM guarantee.

### Code Example
```csharp
using System.Text;
using EricksonLopez.Security;
using EricksonLopez.Security.Abstractions.Cryptography;
using EricksonLopez.Security.Abstractions.KeyManagement;
using EricksonLopez.Security.Abstractions.Secrets;
using Microsoft.Extensions.DependencyInjection;

// DI setup
var services = new ServiceCollection();
services.AddEricksonLopezSecurity();
using var provider = services.BuildServiceProvider();

var keyManager = provider.GetRequiredService<IKeyLifecycleManager>();
await keyManager.GenerateAndActivateKeyAsync(KeyPurpose.SecretProtection);
var protector = provider.GetRequiredService<ISecretProtector>();

// Encrypt a PII field bound to tenant "acme-corp"
string tenantId = "acme-corp";
var ctx = AuthenticatedContext.ForTenant(tenantId);
byte[] plaintext = Encoding.UTF8.GetBytes("john.doe@acme.com");

var protectResult = await protector.ProtectAsync(
    secret: plaintext,
    purpose: KeyPurpose.SecretProtection,
    expectedAssociatedData: ctx);
byte[] envelope = protectResult.Value;

// Correct tenant context: decryption succeeds
var decryptResult = await protector.UnprotectAsync(
    protectedData: envelope,
    expectedAssociatedData: ctx);
byte[] recovered = decryptResult.Value;

// Wrong tenant context: decryption fails with AuthenticationTagMismatch
var wrongCtx = AuthenticatedContext.ForTenant("evil-tenant");
var failedResult = await protector.UnprotectAsync(
    protectedData: envelope,
    expectedAssociatedData: wrongCtx);
Console.WriteLine(failedResult.IsFailure); // true: SecurityError.AuthenticationTagMismatch
```

### Technical Explanation
- `AuthenticatedContext.ForTenant(id)` encodes `"tenant:<id>"` as UTF-8 bytes and wraps them in a `readonly struct`.
- The struct is passed directly as `expectedAssociatedData` to `ProtectAsync`/`UnprotectAsync`. The underlying implementation extracts the AAD bytes for AES-256-GCM authentication tag computation over both ciphertext and AAD.
- If the `AuthenticatedContext` presented during decryption differs from the one used during encryption, the GCM tag is invalid and decryption returns `SecurityError.DecryptionFailed`.
- `AuthenticatedContext` implements constant-time equality (`CryptographicOperations.FixedTimeEquals`) so AAD comparisons in test assertions are also timing-safe.

### Common Pitfalls
- **Changing `tenantId` format**: If you add a namespace prefix (e.g. `"org_"`) after encrypting rows, the AAD bytes change and all existing ciphertexts become permanently undecryptable.
- **Using `AuthenticatedContext.Empty` for tenant-specific data**: Missing AAD allows any caller with the key to decrypt any tenant's ciphertext. Always use `ForTenant` for multi-tenant data.
- **Non-deterministic serialization**: AAD must be bit-for-bit identical between encryption and decryption. Avoid `DateTime.ToString()` or JSON with floating-point values as AAD components.

---

## Recipe 17: Zero-String Password Capture with `SecretBuffer.FromUtf8`

### Problem
When a user submits a password via a form, the typical pattern `var secret = new SecretBuffer(Encoding.UTF8.GetBytes(password))` creates a temporary `byte[]` and references the `password` `string`. In .NET, `string` objects can be interned, reside in Gen2 heap for extended periods, or appear in memory dumps. This contradicts the zero-knowledge principle for password handling.

### Solution
Use `SecretBuffer.FromUtf8(ReadOnlySpan<char>)` to encode the password character span directly into an `ArrayPool<byte>` slot without creating an intermediate `string` or `byte[]`. The buffer is scrubbed with `CryptographicOperations.ZeroMemory` on `Dispose()`.

### Code Example
```csharp
using EricksonLopez.Security.Memory;

// Simulate receiving a password from a UI text control
// (In WinForms: textBox.Text.AsSpan(); In Blazor: ReadOnlySpan<char> from JS interop)
ReadOnlySpan<char> passwordFromUi = "UserEnteredPassword$Ultra#Secure2026".AsSpan();

// Step 1: Capture directly from char span — no managed string allocation
using var passwordBuffer = SecretBuffer.FromUtf8(passwordFromUi);

// Step 2: Use the buffer safely
Console.WriteLine($"Captured: {passwordBuffer.Length} bytes, IsDisposed: {passwordBuffer.IsDisposed}");

// Step 3: The buffer is automatically zeroed upon exiting the using scope
// CryptographicOperations.ZeroMemory(span) called on Dispose()
```

### Technical Explanation
- `SecretBuffer.FromUtf8` uses `System.Text.Encoding.UTF8.GetByteCount(chars)` to compute the required buffer size, then `Encoding.UTF8.GetBytes(chars, span)` to encode directly into the pooled array.
- No `string` object is ever created by the library code. If the caller passes a stack-allocated `Span<char>` or reads from a `char[]` that is also wiped, the entire flow is string-free.
- The Roslyn analyzer `ELS0002` will emit a build-time warning if `SecretBuffer.FromUtf8(...)` is called without a `using` declaration.

### Common Pitfalls
- **Calling `FromUtf8` with a `string` literal**: e.g. `SecretBuffer.FromUtf8("password".AsSpan())` — the `string` itself remains in memory; only the buffer encoding is zero-allocation. Always obtain the `ReadOnlySpan<char>` from a mutable `char[]` that you can wipe, or from a pinned control handle.
- **Not using a `using` block**: The buffer is not zeroed until `Dispose()` is explicitly called. Always use `using var buffer = SecretBuffer.FromUtf8(...)`.

---

## Recipe 18: SSRF-Safe Hostname Resolution with `SafeDnsResolver`

### Problem
Webhook processors, outbound API callers, and multi-tenant integration services accept user-supplied hostname inputs. If those hostnames resolve to internal cloud metadata endpoints (e.g. `169.254.169.254`) or RFC 1918 private addresses, the service becomes vulnerable to Server-Side Request Forgery (SSRF). `SafeSocketsHttpHandler` blocks at connect-time, but if your code calls `Dns.GetHostAddressesAsync` before constructing a connection, SSRF protection is bypassed.

### Solution
Use `SafeDnsResolver.ResolveAndValidateAsync` to validate hostname resolution before using the result for any network operation. Inject `ISafeDnsResolver` via DI for testability.

### Code Example
```csharp
using System.Net;
using EricksonLopez.Security.Network;
using Microsoft.Extensions.DependencyInjection;

// DI registration
var services = new ServiceCollection();
services.AddSingleton<ISafeDnsResolver>(sp =>
    new SafeDnsResolver(new SsrfProtectionOptions()));
services.AddSingleton<WebhookProcessor>();
using var provider = services.BuildServiceProvider();

// Usage
var processor = provider.GetRequiredService<WebhookProcessor>();
await processor.SendAsync("api.partner.com", "{ \"event\": \"order.created\" }");

public sealed class WebhookProcessor(ISafeDnsResolver dnsResolver, HttpClient httpClient)
{
    public async Task SendAsync(string targetHost, string payload)
    {
        // Validate the hostname before creating any connection
        var resolveResult = await dnsResolver.ResolveAndValidateAsync(targetHost);
        if (!resolveResult.IsSuccess)
        {
            // Log SecurityError.SecurityPolicyViolation without leaking internal IP information
            throw new InvalidOperationException($"SSRF protection blocked '{targetHost}': {resolveResult.Error.Code}");
        }

        // Only proceed if DNS resolved to safe IPs
        var requestUri = new Uri($"https://{targetHost}/webhook");
        using var request = new HttpRequestMessage(HttpMethod.Post, requestUri)
        {
            Content = new StringContent(payload, System.Text.Encoding.UTF8, "application/json")
        };
        using var response = await httpClient.SendAsync(request);
        response.EnsureSuccessStatusCode();
    }
}
```

### Technical Explanation
- `SafeDnsResolver` calls `Dns.GetHostAddressesAsync` (or the injected `dnsLookup` delegate in tests) and validates every returned `IPAddress` against:
  - **Blocked cloud metadata hostnames**: exact hostname match list.
  - **Blocked IP ranges**: loopback, link-local (`169.254.0.0/16`), RFC 1918 (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), and any additional ranges in `SsrfProtectionOptions.BlockedRanges`.
- Validating all resolved IPs (not just the first) prevents DNS rebinding attacks where an initial resolution returns a safe IP but subsequent resolutions return a private IP.
- For unit tests, inject a `dnsLookup` delegate returning fixed `IPAddress[]` arrays to test both allowed and blocked scenarios without network.

### Common Pitfalls
- **Skipping DNS validation when using `SafeSocketsHttpHandler`**: `SafeSocketsHttpHandler` blocks at connect-time, but your code may process the hostname in other ways before connecting (e.g. logging, tracing, URL construction). `SafeDnsResolver` validates earlier in the pipeline.
- **Not testing with `dnsLookup` injection**: Production DNS resolution will block in unit test environments. Always inject a mock delegate for deterministic testing.
- **Hostname allowlist too broad**: Setting `RestrictToAllowedHostnames = true` with `AllowedHostnames = ["*"]` defeats the purpose. Use exact FQDNs or narrow wildcard patterns validated against your partner integration contract.

