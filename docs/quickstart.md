# Quickstart: EricksonLopez.Security in 5 Minutes

> **Goal**: From zero to your first working AEAD encryption + password hashing in under 5 minutes.  
> **Prerequisites**: .NET 8.0+ SDK.

---

## Installation

```bash
dotnet add package EricksonLopez.Security
```

For ASP.NET Core projects:

```bash
dotnet add package EricksonLopez.Security.AspNetCore
```

---

## 1. DI Setup (30 seconds)

```csharp
using Microsoft.Extensions.DependencyInjection;
using EricksonLopez.Security;

var services = new ServiceCollection();
services.AddEricksonLopezSecurity();
var sp = services.BuildServiceProvider();
```

That's it. Secure defaults are applied automatically:
- AES-256-GCM encryption (AEAD — no unsafe modes exposed).
- PBKDF2-SHA512 password hashing (210,000 iterations — OWASP 2024 compliant).
- Constant-time token and API key comparison.
- ZeroMemory-on-Dispose for all cryptographic key material.

---

## 2. Encrypt and Decrypt Data (1 minute)

```csharp
using System.Text;
using EricksonLopez.Security.Abstractions.KeyManagement;
using EricksonLopez.Security.Abstractions.Primitives;
using EricksonLopez.Security.Abstractions.Secrets;

var keyLifecycle = sp.GetRequiredService<IKeyLifecycleManager>();
var protector = sp.GetRequiredService<ISecretProtector>();

// Generate an encryption key
await keyLifecycle.GenerateAndActivateKeyAsync(KeyPurpose.SecretProtection);

// Encrypt (async ReadOnlyMemory<byte> overload)
byte[] plaintext = Encoding.UTF8.GetBytes("SSN: 123-45-6789");
var encryptResult = await protector.ProtectAsync(secret: plaintext, purpose: KeyPurpose.SecretProtection);
byte[] ciphertext = encryptResult.Value; // Binary security envelope

// Decrypt (async ReadOnlyMemory<byte> overload)
var decryptResult = await protector.UnprotectAsync(protectedData: ciphertext);
string recovered = Encoding.UTF8.GetString(decryptResult.Value);
// recovered == "SSN: 123-45-6789"

// Zero-allocation synchronous span overload (ReadOnlySpan<byte>)
var syncResult = protector.Protect(plaintext.AsSpan(), KeyPurpose.SecretProtection);
```

**Why it's safe**: The envelope embeds the key identifier and version — decryption automatically
resolves the correct key even after key rotation. You never touch raw key bytes.

---

## 3. Hash and Verify Passwords (1 minute)

```csharp
using EricksonLopez.Security.Abstractions.Passwords;

var hasher = sp.GetRequiredService<IPasswordHasher>();

// Hash (supports ReadOnlySpan<char>)
string hash = hasher.HashPassword("CorrectHorseBatteryStaple!2026".AsSpan());
// Output: $pbkdf2-sha512$i=210000$... (Modular Crypt Format, primary default)
// Note: To use Argon2id ($argon2id$v=19$m=65536,t=3,p=4$...), promote Argon2idPasswordHasher as primary.

// Verify using constant-time comparison
PasswordVerificationResult result = hasher.VerifyPassword("CorrectHorseBatteryStaple!2026".AsSpan(), hash);
// result == PasswordVerificationResult.Success

// Handle rehash (algorithm upgrade or parameter cost change)
if (result == PasswordVerificationResult.SuccessRehashNeeded || hasher.NeedsRehash(hash))
{
    string newHash = hasher.HashPassword("CorrectHorseBatteryStaple!2026".AsSpan());
    // Save newHash to DB
}
```

---

## 4. Generate and Validate API Keys (1 minute)

```csharp
using EricksonLopez.Security.Abstractions.Tokens;

var apiKeyGen = sp.GetRequiredService<IApiKeyGenerator>();
var apiKeyVal = sp.GetRequiredService<IApiKeyValidator>();

// Generate (done once at key creation)
var issuance = apiKeyGen.GenerateApiKey(
    ownerId: "user-123",
    name: "Production App",
    prefix: "ek_live",
    lifetime: TimeSpan.FromDays(90),
    scopes: new HashSet<string> { "read", "write" });

// Return this to the user ONCE — never store it
string rawKey = issuance.PlaintextApiKey; // "ek_live_3f9a1b2c_..."

// Persist this (hashed) — never the plaintext
string hashedKey = issuance.Key.HashedSecret;
string keyId = issuance.Key.Id.ToString();

// On incoming request: validate (constant-time, async — resolved from IApiKeyStore)
var validationResult = await apiKeyVal.ValidateApiKeyAsync(rawKey);
bool isValid = validationResult.IsSuccess;
```

---

## 5. ASP.NET Core Setup (30 seconds)

```csharp
// In Program.cs
var builder = WebApplication.CreateBuilder(args);
builder.Services.AddEricksonLopezSecurity();
builder.Services.AddSecurityAspNetCore();

var app = builder.Build();

// Security headers middleware (CSP, HSTS, X-Frame-Options, etc.)
app.UseSecurityHeaders();

app.MapGet("/", () => "Secure API");
app.Run();
```

---

## What's Next?

| Goal | Guide |
|---|---|
| Migrate from DataProtection | [migration-from-dataprotection.md](./migration-from-dataprotection.md) |
| Migrate from Identity PasswordHasher | [migration-from-identity-passwordhasher.md](./migration-from-identity-passwordhasher.md) |
| Full API key authentication sample | [samples/EricksonLopez.Security.ApiKeys.Sample](../samples/EricksonLopez.Security.ApiKeys.Sample/) |
| TOTP + Recovery codes sample | [samples/EricksonLopez.Security.Totp.Sample](../samples/EricksonLopez.Security.Totp.Sample/) |
| Cloud secrets with Azure Key Vault | [samples/EricksonLopez.Security.Secrets.Sample](../samples/EricksonLopez.Security.Secrets.Sample/) |
| Architecture overview | [architecture.md](./architecture.md) |
| All design decisions | [adr/](./adr/) |
