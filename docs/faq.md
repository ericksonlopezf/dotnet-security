# FAQ — EricksonLopez.Security

> **Version**: v1.0.0  
> **Format**: Frequently Asked Questions derived from the public API inventory.

---

## General

### Q: What is EricksonLopez.Security?
EricksonLopez.Security is a foundational enterprise security and cryptography ecosystem for .NET 8.0/9.0/10.0. It provides Native AOT-compatible, zero-allocation cryptographic primitives, versioned binary security envelopes, multi-version key lifecycle management, password hashing (Argon2id, PBKDF2), API key lifecycle, WebAuthn Passkeys, SAML 2.0, SSRF prevention, and dynamic Attribute-Based Access Control (ABAC) under a single coherent security surface.

### Q: Is this compatible with Native AOT?
Yes. All core cryptographic pipelines are free of `System.Reflection`, runtime code generation, and dynamic dispatch. 17 of the 21 ecosystem packages are explicitly verified with `<IsAotCompatible>true</IsAotCompatible>` and tested via `tests/EricksonLopez.Security.AotSmokeTest`. Only 4 packages set `<IsAotCompatible>false</IsAotCompatible>` due to XML/XPath or dynamic runtime requirements (`Saml2`, `Cryptography.XmlDSig`, `OpenTelemetry`, and `Analyzers`), as documented in [`docs/aot.md`](aot.md).

### Q: Does it depend on the OpenTelemetry SDK?
No. `SecurityActivitySource` and `SecurityMeter` use **only BCL types** (`System.Diagnostics.ActivitySource`, `System.Diagnostics.Metrics.Meter`). The OTel SDK is an optional satellite package (`EricksonLopez.Security.OpenTelemetry`). This ensures zero dependency coupling and Native AOT safety.

### Q: What is the minimum setup?
```csharp
services.AddEricksonLopezSecurity();
```
This registers CSPRNG, AES-256-GCM, KeyLifecycleManager, CompositePasswordHasher, OpaqueTokenGenerator, HmacSha256TokenHasher, ApiKeyGenerator, AesGcmSecretProtector, and EnvironmentSecretStore.

---

## Key Management

### Q: Can I use my own key store backend (Azure Key Vault, AWS KMS, Google Cloud KMS)?
Yes. Replace `InMemoryKeyStore` (the default) with your custom or cloud-backed store:
```csharp
services.AddEricksonLopezSecurity();
services.AddSingleton<IKeyStore>(sp => new CustomProductionKeyStore(connectionString));
```
`IKeyLifecycleManager` automatically uses whatever `IKeyStore` is registered in DI. *(Note: The satellite packages `Azure`, `Aws`, `GoogleCloud`, and `HashiCorpVault` are in-memory stubs/doubles in v1.x per ADR-011/012/013; connect to real cloud endpoints using your cloud provider's official SDKs).*

### Q: What happens when I rotate a key?
`RotateKeyAsync` transitions the current active key to `KeyStatus.Retired` and generates a new active key. Retired keys remain in the store and can be used for **decryption only**. `IKeyLifecycleManager` and `KeyRing` handle multi-version decryption transparently — historical envelopes decrypt with their stored `KeyId + Version`.

### Q: What does `SecurityError.AuthenticationTagMismatch` mean?
The AES-256-GCM or ChaCha20-Poly1305 authentication tag verification failed. Either the ciphertext was modified in transit, the wrong key was used, or the Associated Data (AAD/tenant context) doesn't match what was used during encryption.

### Q: How do I generate a key for a specific purpose?
```csharp
await keyLifecycle.GenerateAndActivateKeyAsync(KeyPurpose.SecretProtection);
await keyLifecycle.GenerateAndActivateKeyAsync(KeyPurpose.TokenProtection);
```
Keys are bound to their purpose — using a `SecretProtection` key for `Signing` is rejected by the engine (misuse resistance).

---

## Password Hashing

### Q: Which algorithm should I use?
`AddEricksonLopezSecurity()` registers `Pbkdf2PasswordHasher` (210,000 iterations default) as primary, with `Argon2idPasswordHasher` as an additional hasher. If your deployment requires Argon2id format hashes for new users, configure `Argon2idPasswordHasher` as the primary hasher in `CompositePasswordHasher`. In v1.x, `Argon2idPasswordHasher` uses PBKDF2-HMAC-SHA512 as its underlying substrate, reserving the format slot for v2.x native RFC 9106 migration per ADR-024.

### Q: How do I migrate from PBKDF2 to Argon2id without a maintenance window?
Use `CompositePasswordHasher` with Argon2id as primary. Users with legacy PBKDF2 hashes receive `SuccessRehashNeeded` on verification — re-hash transparently on their next login:
```csharp
var result = passwordHasher.VerifyPassword(password.AsSpan(), storedHash);
if (result == PasswordVerificationResult.SuccessRehashNeeded)
{
    var newHash = passwordHasher.HashPassword(password.AsSpan());
    await UpdateStoredHash(userId, newHash);
}
```

### Q: What does `PasswordVerificationResult.SuccessRehashNeeded` mean?
The password is **correct**, but the stored hash was produced with different cost parameters (different algorithm, lower iterations, etc.). The application should transparently update the stored hash with the current parameters on the user's next successful login.

### Q: Is `HashPassword` thread-safe?
Yes. All `IPasswordHasher` implementations (`Argon2idPasswordHasher`, `Pbkdf2PasswordHasher`, `CompositePasswordHasher`) are stateless and fully thread-safe.

---

## Tokens & API Keys

### Q: Why does `OpaqueToken.ToString()` return `[REDACTED]`?
Prevents accidental token leakage in structured logs, APM traces, and exception messages. Use `opaqueToken.Value` for authorized access to the underlying string (e.g., to send it to the user in a response).

### Q: How are API keys stored securely?
`ApiKeyGenerator.GenerateApiKey()` returns a `(rawKey, hashedKey)` pair. **Only the hash is stored** (via `IApiKeyStore`). The raw key is sent to the user **once** and never persisted.

### Q: How do I add pepper to token hashing?
```csharp
var pepperKey = LoadFromKms(); // byte[32]
var hasher = new HmacSha256TokenHasher(pepperKey);
```
Without pepper, plain SHA-256 is used. With pepper, HMAC-SHA256 is used — even if the database is compromised, tokens cannot be reversed without the pepper key.

---

## Memory Safety

### Q: What does `SecretBuffer` do on disposal?
Calls `CryptographicOperations.ZeroMemory(buffer)` and returns the array to `ArrayPool<byte>.Shared`. This guarantees no key material lingers in the GC heap after the buffer's `using` scope ends.

### Q: What is `Secret<T>`?
A generic auto-disposing wrapper for sensitive reference types. When the `Secret<T>` is disposed, it calls `Dispose()` on the inner value (if it implements `IDisposable`).

### Q: What is `TimingSafeString`?
A readonly string wrapper where `==` uses constant-time comparison (`ConstantTimeComparer.FixedTimeEquals`). Use it when comparing tokens, API keys, or other credentials where timing side-channel attacks are a concern.

---

## Secrets

### Q: What URI schemes does `CompositeSecretResolver` support?
- `raw:VALUE` — Inline plaintext value. **Dev/test only**, never production.
- `env:VAR_NAME` — Reads from environment variable (normalized to UPPER_CASE with `_`).
- `store:SECRET_NAME` — Delegates to the registered `ISecretStore`.
- Fallback (no scheme) — Delegates to `ISecretStore`.

### Q: How does `EnvironmentSecretStore` normalize key names?
Key `"Database:Connection:String"` becomes env var `"APP_DATABASE_CONNECTION_STRING"` (if prefix `"APP_"` is configured). Dots, colons, and hyphens are all replaced by underscores.

---

## ABAC / Zero Trust

### Q: What combining algorithm should I use?
`DenyOverrides` (the default) is the correct choice for Zero Trust — any Deny decision wins regardless of other Permit decisions. Use `PermitOverrides` only when you explicitly need "opt-in" semantics.

### Q: Can ABAC policies be dynamically loaded?
Yes. `AbacPolicyEngine.Evaluate(context, policies)` accepts any `IEnumerable<AbacPolicy>` — load policies from a database, configuration file, or remote policy service at evaluation time.

---

## Observability

### Q: How do I integrate with OpenTelemetry?
Add the satellite package:
```csharp
services.AddOpenTelemetry()
    .WithTracing(b => b.AddEricksonLopezSecurityInstrumentation())
    .WithMetrics(b => b.AddEricksonLopezSecurityMetrics());
```
Without the satellite, use `ActivityListener` and `MeterListener` directly from BCL.

### Q: What span names are used?
| Operation | Span Name |
|---|---|
| Encrypt | `security.encrypt` |
| Decrypt | `security.decrypt` |
| Hash Password | `security.password.hash` |
| Verify Password | `security.password.verify` |
| Protect Secret | `security.secret.protect` |
| Unprotect Secret | `security.secret.unprotect` |
