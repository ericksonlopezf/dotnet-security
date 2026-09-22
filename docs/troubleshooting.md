# Troubleshooting Guide — EricksonLopez.Security

> **Version**: v1.0.0  
> **Format**: Symptom → Root Cause → Resolution

---

## Key Management

### Problem: `SecurityError.KeyNotFound` when calling `UnprotectAsync`

**Symptom**: Decryption fails with `SecurityError.KeyNotFound` on existing ciphertext.

**Root Cause**: The `SecurityEnvelope` stores a `KeyId + Version`. If `IKeyStore` is `InMemoryKeyStore` and the application was restarted, the in-memory key store was cleared.

**Resolution**:
1. **Development & Testing**: This is expected behavior with `InMemoryKeyStore`.
2. **Production / Architecture**: Configure `AzureKeyVaultKeyStore`, `AwsKmsKeyStore`, `GoogleCloudKmsKeyStore`, or `HashiCorpVaultKeyStore`. Note: In v1.x, these adapters provide contract-compliant in-memory implementations for architectural decoupling; direct HTTP/gRPC remote KMS connectivity is scheduled for v2.x.

---

### Problem: `SecurityError.KeyRevoked` on a key that should be valid

**Symptom**: Decryption fails with `SecurityError.KeyRevoked` on recent ciphertext.

**Root Cause**: `IKeyLifecycleManager.RevokeKeyAsync` was called with this key. Revocation is permanent.

**Resolution**:
1. Verify via `IKeyStore` that the key's `Status` is `Revoked` and the revocation was intentional.
2. If accidental, restore the key by creating a new `CryptographicKey` with `KeyStatus.Active` using the same `KeyId/Version` (only possible if the key material was backed up — not possible with in-memory store).
3. For HSM-backed keys, use the KMS console to restore. `InMemoryKeyStore` revocations are irreversible within a process lifetime.

---

### Problem: Slow first encryption after startup

**Symptom**: First call to `ProtectAsync` takes 300–500ms; subsequent calls are fast.

**Root Cause**: `KeyRing` uses lazy loading — the first access queries `IKeyStore` to populate the cache.

**Resolution**: Warm up the key ring during application startup:
```csharp
// In IHostedService.StartAsync or Program.cs startup
var keyRing = app.Services.GetRequiredService<IKeyRing>();
await keyRing.GetActiveKeyAsync(KeyPurpose.SecretProtection);
```

---

## Password Hashing

### Problem: Password verification always returns `Failed`

**Symptom**: `VerifyPassword` returns `Failed` for a known correct password.

**Root Causes**:
1. Hash stored as a different encoding (e.g., base64 of the hash instead of the MCF string).
2. Hash generated with a different `IPasswordHasher` implementation not registered in `CompositePasswordHasher`.
3. `ReadOnlySpan<char>` vs `string` encoding issue — ensure `password.AsSpan()` is passed, not a differently encoded form.

**Resolution**:
1. Verify the stored hash starts with `$argon2id$` or `$pbkdf2-sha512$` — store the MCF string directly.
2. Check that all legacy hashers are registered in `CompositePasswordHasher.additionalHashers`.

---

### Problem: Argon2id hashing is too slow (>2000ms)

**Symptom**: `HashPassword` takes several seconds, causing request timeouts.

**Root Cause**: `memorySizeKb` is too high for the available server memory, or `parallelism` exceeds logical CPU count.

**Resolution**: Tune cost parameters for your hardware. Target 300–500ms:
```csharp
// Start with these and adjust upward until you hit the target
var hasher = new Argon2idPasswordHasher(
    memorySizeKb: 65536,  // 64MB — reduce if <500ms isn't achievable
    iterations: 3,
    parallelism: Environment.ProcessorCount);
```
Monitor `SecurityMeter.Argon2HashingDurationMs` histogram in production.

---

## Token & API Key Issues

### Problem: `ApiKeyValidator` always returns `SecurityError.TokenInvalid`

**Symptom**: Valid raw keys fail validation.

**Root Cause**:
1. Different `HmacSha256TokenHasher` instances used for generation vs validation (different pepper keys).
2. Raw key was trimmed/URL-decoded before validation (extra whitespace or encoding change).
3. API key was revoked via `IApiKeyStore.RevokeAsync`.

**Resolution**:
1. Register `ITokenHasher` as a singleton — it's reused across `ApiKeyGenerator` and `ApiKeyValidator`.
2. Pass the exact raw key string from the HTTP request to `ValidateApiKeyAsync` without transformation.
3. Check `apiKey.IsRevoked` before attempting validation.

---

### Problem: `OpaqueToken.Value` is inaccessible in logs

**Symptom**: Token value shows `[REDACTED]` in all log sinks.

**Root Cause**: This is the **intended behavior** — `OpaqueToken.ToString()` always returns `[REDACTED]`.

**Resolution**: Access `.Value` property explicitly at the HTTP response boundary:
```csharp
var token = tokenGenerator.GenerateToken(32);
// In HTTP response handler:
response.Headers.Add("X-Session-Token", token.Value); // authorized access point
// Everywhere else: token.ToString() = "[REDACTED]"
```

---

## Memory & Disposal

### Problem: `ObjectDisposedException` on `SecretBuffer.Span`

**Symptom**: `ObjectDisposedException` when reading from a `SecretBuffer` after it's been used.

**Root Cause**: The `SecretBuffer` was disposed (either explicitly via `using` or by `Dispose()`) before the span was read.

**Resolution**: Only access `Span` and `Memory` within the `using` scope:
```csharp
using var buffer = SecretBuffer.CreateRandom(32);
var encrypted = engine.Encrypt(plaintext, buffer.Span, aad); // OK — within scope
// After using block: buffer.IsDisposed == true
```

---

### Problem: `Redacted<T>.UnsafeValue` is `null`

**Symptom**: Accessing `.UnsafeValue` returns `null` when a value is expected.

**Root Cause**: `Redacted<T>` was created from a `null` value (`default(Redacted<T>)` or `new Redacted<T>(null)`).

**Resolution**: Check `HasValue` before accessing `UnsafeValue`:
```csharp
if (redacted.HasValue)
{
    var value = redacted.UnsafeValue;
}
```

---

## Secret Resolution

### Problem: `CompositeSecretResolver` returns `SecretNotFound` for `env:` reference

**Symptom**: `ResolveAsync("env:Database:Password")` returns `IsSuccess=false`.

**Root Cause**: Environment variable name normalization. The key `"Database:Password"` maps to env var `"DATABASE_PASSWORD"` (or `"APP_DATABASE_PASSWORD"` with prefix `"APP_"`).

**Resolution**: Verify the environment variable name:
```csharp
// With EnvironmentSecretStore(prefix: "APP_"):
// "Database:Password" → looks for "APP_DATABASE_PASSWORD"
Console.WriteLine(Environment.GetEnvironmentVariable("APP_DATABASE_PASSWORD"));
```
Colons, dots, and hyphens are all replaced by underscores and uppercased.

---

## Build & Compilation

### Problem: Showcase fails to compile after library update

**Symptom**: Build errors in `samples/EricksonLopez.Security.Sample` after updating library.

**Resolution**:
1. Check `Level2_FullConfiguration.cs` for removed/renamed types.
2. Run: `dotnet build --configuration Release 2>&1` to see exact errors.
3. Refer to `CHANGELOG.md` for breaking API changes.
4. The Showcase is the executable contract — update it to match the new API, never invent compatibility shims.

### Problem: Native AOT publish fails with `IL2` warnings from security library

**Symptom**: `ILLINK` or `IL2xxx` warnings when publishing with `<PublishAot>true>`.

**Root Cause**: Third-party dependency (e.g., `Konscious.Security.Cryptography` for Argon2id) may have reflection usage.

**Resolution**: File an issue on the library repository. As a workaround, use `<TrimmerRootDescriptor>` for the affected assembly, or use `Pbkdf2PasswordHasher` (fully AOT-safe) as the primary hasher until the dependency is updated.

---

## Diagnostics

### Problem: No traces appear in Jaeger/Zipkin from `SecurityActivitySource`

**Symptom**: Encryption operations complete successfully but produce no spans in distributed tracing.

**Root Cause**: `ActivityListener` was not registered before the operations ran. OTel SDK must subscribe to `SecurityActivitySource.SourceName` during startup.

**Resolution**:
```csharp
// With EricksonLopez.Security.OpenTelemetry:
builder.Services.AddOpenTelemetry()
    .WithTracing(t => t.AddEricksonLopezSecurityInstrumentation());

// Without OTel SDK (BCL listener):
ActivitySource.AddActivityListener(new ActivityListener
{
    ShouldListenTo = source => source.Name == SecurityActivitySource.SourceName,
    Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded,
});
```
Register listeners **before** any `ISecretProtector` or `IPasswordHasher` calls.
