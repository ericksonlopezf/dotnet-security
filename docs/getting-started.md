# Getting Started — EricksonLopez.Security

> **Version**: v1.0.0  
> **Target Frameworks**: .NET 8.0 | .NET 9.0 | .NET 10.0  
> **Audience**: Software Architects, Security Engineers, and Backend Developers building high-performance, compliant .NET services.

---

## 1. Introduction & Security Philosophy

`EricksonLopez.Security` is the foundational cryptographic and perimeter security ecosystem for modern .NET applications. Unlike standard frameworks that expose low-level, error-prone cryptographic primitives, `EricksonLopez.Security` is designed around the principle of **misuse-resistance**—ensuring that the most secure path is always the easiest, default path to implement.

### Core Architectural Invariants

| Invariant | Implementation Mechanism | Benefit |
|---|---|---|
| **Misuse-Resistance** | Authenticated Encryption (AEAD only: AES-256-GCM, ChaCha20-Poly1305) | Eliminates padding oracle attacks, CBC bit-flipping, and unauthenticated ciphertexts. |
| **Side-Channel Timing Resistance** | `CryptographicOperations.FixedTimeEquals` everywhere | Eliminates byte-by-byte timing leaks during token, password, and signature verification. |
| **Zero Heap Allocations** | `ReadOnlySpan<byte>` overloads, `stackalloc`, `ArrayPool<byte>.Shared` | Sub-microsecond cryptographic hotpaths with **0 B** allocated on execution loops. |
| **Deterministic Memory Scrubbing** | `SecretBuffer`, `Redacted<T>`, `CryptographicOperations.ZeroMemory` | Prevents plaintext keys and passwords from lingering on the GC heap or appearing in logs. |
| **Native AOT & Trimming Safety** | Zero runtime reflection, compile-time metadata, source-generated code | Instant cold starts, minimal binary footprints, and full compatibility with containerized Native AOT. |
| **Functional Resilience** | `EricksonLopez.Result` with typed `SecurityError` codes | Eliminates exception-driven control flow for cryptographic and validation failures. |

---

## 2. Package Ecosystem Matrix

The ecosystem comprises 21 specialized NuGet packages. Choose the packages suited to your deployment scenario:

```
                                  ┌──────────────────────────────┐
                                  │   EricksonLopez.Security     │
                                  │       (Core Engine)          │
                                  └──────────────┬───────────────┘
                                                 │
            ┌───────────────────┬────────────────┼───────────────────┬───────────────────┐
            ▼                   ▼                ▼                   ▼                   ▼
    ┌──────────────┐    ┌──────────────┐ ┌──────────────┐    ┌──────────────┐    ┌──────────────┐
    │  AspNetCore  │    │  ZeroTrust   │ │   Protocols  │    │  Cloud KMS   │    │ Observability│
    │  & Network   │    │  (ABAC PDP)  │ │ (FIDO2/SAML) │    │(Azure/AWS/...)│    │(OpenTelemetry│
    └──────────────┘    └──────────────┘ └──────────────┘    └──────────────┘    └──────────────┘
```

| Workload | Recommended Packages |
|---|---|
| **Core Encryption & Passwords** | `EricksonLopez.Security`, `EricksonLopez.Security.Abstractions` |
| **ASP.NET Core Web APIs** | `EricksonLopez.Security.AspNetCore`, `EricksonLopez.Security.Network` |
| **Zero Trust Authorization** | `EricksonLopez.Security.ZeroTrust` |
| **Multi-Factor & Passwordless** | `EricksonLopez.Security.Mfa`, `EricksonLopez.Security.WebAuthn.Fido2` |
| **Enterprise Federation** | `EricksonLopez.Security.Saml2`, `EricksonLopez.Security.Cryptography.XmlDSig` |
| **Cloud Key & Secret Storage** | `EricksonLopez.Security.Azure`, `Aws`, `HashiCorpVault`, `GoogleCloud` |
| **Observability & Diagnostics** | `EricksonLopez.Security.OpenTelemetry` |
| **Compile-Time Guardrails** | `EricksonLopez.Security.Analyzers` |

---

## 3. Installation & Dependency Injection Setup

### Step 3.1: Install Packages

Install the primary metapackage and core abstractions via the .NET CLI:

```bash
dotnet add package EricksonLopez.Security
dotnet add package EricksonLopez.Security.Abstractions
```

For web applications:

```bash
dotnet add package EricksonLopez.Security.AspNetCore
dotnet add package EricksonLopez.Security.Network
```

### Step 3.2: Configure Services

In your application entry point (`Program.cs`), register the security framework:

```csharp
using EricksonLopez.Security;
using EricksonLopez.Security.AspNetCore;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;

var builder = WebApplication.CreateBuilder(args);

// 1. Register Core Security Framework
builder.Services.AddEricksonLopezSecurity();

// 2. Register ASP.NET Core Perimeter Hardening
//    AddSecurityAspNetCore accepts two separate optional action delegates:
//    - configureHeaders: Action<SecurityHeadersOptions>  (all header values as strings)
//    - configureApiKeyAuth: Action<ApiKeyAuthenticationOptions>
builder.Services.AddSecurityAspNetCore(
    configureHeaders: options =>
    {
        // Override only what you need; secure defaults are pre-configured for all properties
        options.ContentSecurityPolicy = "default-src 'self'; script-src 'self'; frame-ancestors 'none';";
        options.StrictTransportSecurity = "max-age=31536000; includeSubDomains; preload";
        options.XFrameOptions = "DENY";
        options.XContentTypeOptions = "nosniff";
    },
    configureApiKeyAuth: options =>
    {
        options.HeaderName = "X-Api-Key";
    });

var app = builder.Build();

// 3. Activate Pipeline Middleware
app.UseSecurityHeaders();
app.UseApiKeyAuthentication();

app.MapGet("/", () => "Service hardened with EricksonLopez.Security.");

app.Run();
```

---

## 4. Foundational Workflow: Multi-Version Key Management

Cryptographic keys must rotate without breaking the ability to decrypt historical records. `EricksonLopez.Security` manages keys across an explicit state machine:

$$\text{Active} \longrightarrow \text{Retired} \longrightarrow \text{Revoked} \longrightarrow \text{Destroyed}$$

```csharp
using EricksonLopez.Security.Abstractions.KeyManagement;
using EricksonLopez.Security.Abstractions.Primitives;

var keyManager = app.Services.GetRequiredService<IKeyLifecycleManager>();

// 1. Generate and activate an initial key for SecretProtection
var createResult = await keyManager.GenerateAndActivateKeyAsync(KeyPurpose.SecretProtection);
var activeKey = createResult.Value;
Console.WriteLine($"Active Key ID: {activeKey.Metadata.KeyId}, Version: {activeKey.Metadata.Version}");

// 2. Scheduled or triggered key rotation:
// - Retires the existing key (allowing it to decrypt past data)
// - Generates a new active key for future encryptions
var rotateResult = await keyManager.RotateKeyAsync(KeyPurpose.SecretProtection);
var newKey = rotateResult.Value;
Console.WriteLine($"Rotated to new Version: {newKey.Metadata.Version}");

// 3. Emergency revocation (e.g. key compromise):
await keyManager.RevokeKeyAsync(activeKey.Metadata.KeyId, activeKey.Metadata.Version, "Compromise suspected");
```

---

## 5. Authenticated Encryption with Associated Data (AEAD)

### Protecting and Unprotecting Data with Multi-Tenant Context Binding

AEAD binds Authenticated Associated Data (AAD) into the encryption authentication tag. If an attacker attempts to replay an encrypted payload in a different tenant context, decryption fails immediately.

```csharp
using System.Text;
using EricksonLopez.Security.Abstractions.Cryptography;
using EricksonLopez.Security.Abstractions.KeyManagement;
using EricksonLopez.Security.Abstractions.Secrets;

var protector = app.Services.GetRequiredService<ISecretProtector>();

// Plaintext payload to protect
byte[] payload = Encoding.UTF8.GetBytes("AccountBalance: 50000.00; SSN: 000-12-3456");

// Context binding: AuthenticatedContext is a strongly-typed struct — use ForTenant() or FromBytes()
// to bind the tenant identifier into the AEAD authentication tag.
var tenantAad = AuthenticatedContext.ForTenant("enterprise_alpha");

// Encrypt: generates a binary security envelope containing KeyId, Version, Nonce, Tag, and Ciphertext
var protectResult = await protector.ProtectAsync(
    secret: payload,
    purpose: KeyPurpose.SecretProtection,
    expectedAssociatedData: tenantAad);
if (protectResult.IsFailure)
{
    Console.WriteLine($"Encryption failed: {protectResult.Error.Description}");
    return;
}

byte[] encryptedEnvelope = protectResult.Value;

// Decrypt: verifies authentication tag and ensures matching tenant AAD
var unprotectResult = await protector.UnprotectAsync(
    protectedData: encryptedEnvelope,
    expectedAssociatedData: tenantAad);
if (unprotectResult.IsSuccess)
{
    string recovered = Encoding.UTF8.GetString(unprotectResult.Value);
    Console.WriteLine($"Decrypted payload: {recovered}");
}
```

### Zero-Allocation In-Memory Operations with Spans

For ultra-high-throughput hotpaths (e.g. trading engines, packet brokers), use the allocation-free synchronous span overloads:

```csharp
using EricksonLopez.Security.Abstractions.Cryptography;

ReadOnlySpan<byte> plaintextSpan = "SensitiveEphemeralToken"u8;
var aadContext = AuthenticatedContext.FromBytes("context:fast-path"u8);

var spanResult = protector.Protect(
    secret: plaintextSpan,
    purpose: KeyPurpose.SecretProtection,
    expectedAssociatedData: aadContext);
if (spanResult.IsSuccess)
{
    byte[] envelope = spanResult.Value;
    // 0 B heap allocation on encryption engine execution
}
```

---

## 6. Password Security & Automatic Rehash

The library implements NIST SP 800-63B and OWASP 2024 compliant password hashing with transparent hash migration:

```csharp
using EricksonLopez.Security.Abstractions.Passwords;

var passwordHasher = app.Services.GetRequiredService<IPasswordHasher>();

// Hash password using default PBKDF2-HMAC-SHA512 standard ($pbkdf2-sha512$ format, OWASP 2024 compliant; or Argon2id)
string hash = passwordHasher.HashPassword("CorrectHorseBatteryStaple!2026".AsSpan());
Console.WriteLine($"Stored MCF Hash: {hash}");

// Verify password in constant-time
var verifyResult = passwordHasher.VerifyPassword("CorrectHorseBatteryStaple!2026".AsSpan(), hash);

switch (verifyResult)
{
    case PasswordVerificationResult.Success:
        Console.WriteLine("Authentication successful.");
        break;
        
    case PasswordVerificationResult.SuccessRehashNeeded:
        Console.WriteLine("Authentication successful, but password needs rehash (e.g. algorithm upgraded).");
        string updatedHash = passwordHasher.HashPassword("CorrectHorseBatteryStaple!2026".AsSpan());
        // Save updatedHash to database
        break;
        
    case PasswordVerificationResult.Failed:
        Console.WriteLine("Invalid credentials.");
        break;
}
```

---

## 7. Web Perimeter Defense & SSRF Mitigation

### Outbound HTTP SSRF Defense with `SafeHttpClientFactory`

Prevent Server-Side Request Forgery (SSRF) when making outbound HTTP requests to user-supplied webhooks:

```csharp
using EricksonLopez.Security.Network;

// SafeHttpClientFactory blocks RFC 1918 private ranges, 127.0.0.1, link-local, and cloud metadata IPs
using var safeClient = SafeHttpClientFactory.CreateClient(new SsrfProtectionOptions
{
    AllowPrivateNetworks = false,
    EnforceHostnameAllowlist = false
});

try
{
    // Outbound request to an untrusted webhook URL
    var response = await safeClient.GetAsync("https://api.partner.com/webhook");
    Console.WriteLine($"Webhook response: {response.StatusCode}");
}
catch (HttpRequestException ex)
{
    Console.WriteLine($"Request blocked by SSRF defense: {ex.Message}");
}
```

---

## 8. Dynamic Zero Trust ABAC Authorization

Attribute-Based Access Control allows evaluating multidimensional contexts (Subject, Resource, Action, Environment) using XACML-compliant conflict resolution (`DenyOverrides`):

```csharp
using EricksonLopez.Security.ZeroTrust;

var engine = new AbacPolicyEngine();

// 1. Build request context
var context = new AbacContext()
    .WithSubjectAttribute("Role", "SecurityOfficer")
    .WithSubjectAttribute("MfaAuthenticated", true)
    .WithSubjectAttribute("ClearanceLevel", 4)
    .WithResourceAttribute("Classification", "TopSecret")
    .WithResourceAttribute("RequiredClearance", 3)
    .WithActionAttribute("Type", "ReadAuditLog")
    .WithEnvironmentAttribute("NetworkZone", "CorporateLAN");

// 2. Define Policy
var policy = new AbacPolicy("AUDIT_LOG_POLICY", AbacCombiningAlgorithm.DenyOverrides)
    .AddRule(new AbacRule(
        "RULE_REQUIRE_MFA",
        AbacEffect.Deny,
        ctx => !ctx.GetSubjectAttribute<bool>("MfaAuthenticated")))
    .AddRule(new AbacRule(
        "RULE_PERMIT_OFFICER",
        AbacEffect.Permit,
        ctx => ctx.GetSubjectAttribute<string>("Role") == "SecurityOfficer" &&
               ctx.GetSubjectAttribute<int>("ClearanceLevel") >= ctx.GetResourceAttribute<int>("RequiredClearance")));

// 3. Evaluate context against policy
var decision = engine.Evaluate(context, policy);

if (decision.Permitted)
{
    Console.WriteLine("Access Granted under Zero Trust Policy.");
}
else
{
    Console.WriteLine($"Access Denied: {decision.Reason} (Rule: {decision.RuleId})");
}
```

---

## 9. Observability & Distributed Tracing

Export cryptographic metrics and spans natively to OpenTelemetry collectors:

```csharp
using EricksonLopez.Security.OpenTelemetry;
using OpenTelemetry.Metrics;
using OpenTelemetry.Trace;

builder.Services.AddOpenTelemetry()
    .WithTracing(tracing => tracing
        .AddEricksonLopezSecurityInstrumentation() // Subscribes SecurityActivitySource
        .AddOtlpExporter())
    .WithMetrics(metrics => metrics
        .AddEricksonLopezSecurityInstrumentation() // Subscribes SecurityMeter
        .AddOtlpExporter());
```

---

## 10. Production Readiness Checklist

Before deploying applications using `EricksonLopez.Security` to production, verify:

- [ ] **Analyzers Enabled**: Ensure `EricksonLopez.Security.Analyzers` is installed to catch `ELS0001`–`ELS0005` violations during build.
- [ ] **Persistent Key Store**: For multi-instance deployments, configure a persistent `IKeyStore` (such as Azure Key Vault, AWS KMS, HashiCorp Vault, or Google Cloud KMS) rather than in-memory storage.
- [ ] **Rotation Schedules**: Establish automated key rotation policies matching your compliance standards (e.g. quarterly rotation for data protection keys).
- [ ] **AAD Context Binding**: Always provide deterministic, non-sensitive context identifiers (e.g. tenant ID, user ID, or entity UUID) as AAD during encryption.
- [ ] **Constant-Time Verification**: Never use `==` or `string.Equals()` on sensitive tokens, passwords, or hashes.
- [ ] **Memory Redaction**: Avoid converting sensitive credentials into plain `string` objects; utilize `Redacted<T>` and `SecretBuffer` to scrub secrets from RAM upon completion.

---

## Next Steps

- **[Cookbook](./cookbook.md)**: 15 practical recipes for production scenarios.
- **[Architecture Guide](./architecture.md)**: Deep dive into the clean hexagonal architecture and security invariants.
- **[Public API Reference](./api-reference.md)**: Full API specifications in Microsoft Learn format.
- **[Interactive Showcase](../samples/EricksonLopez.Security.Sample/README.md)**: Run the 12-level executable specification on your local machine.
