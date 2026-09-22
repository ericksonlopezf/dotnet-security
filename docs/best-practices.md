# Best Practices — EricksonLopez.Security

> **Version**: v1.0.0  
> **Format**: Actionable security and implementation guidelines derived from the public API.

---

## 1. Key Management

### ✅ DO: Generate keys with explicit purpose binding
```csharp
await keyLifecycle.GenerateAndActivateKeyAsync(KeyPurpose.SecretProtection);
await keyLifecycle.GenerateAndActivateKeyAsync(KeyPurpose.TokenProtection);
```
Each purpose has an isolated key. This prevents key reuse attacks between subsystems.

### ❌ DON'T: Reuse a single key for all operations
A compromised `SecretProtection` key must not expose `TokenProtection` data and vice versa.

### ✅ DO: Automate key rotation with `KeyRotationPolicy`
```csharp
var policy = new KeyRotationPolicy(ValidityPeriod: TimeSpan.FromDays(90), GracePeriod: TimeSpan.FromDays(7));
```
Set `ValidityPeriod` based on your threat model. Rotate at least every 90 days for production PII data.

### ✅ DO: Use a persistent `IKeyStore` backend in production
`InMemoryKeyStore` is designed for development, testing, and transient workloads. In multi-instance production environments, replace it with a persistent or distributed key store.

> [!IMPORTANT]
> **Cloud Adapter Status in v1.x (ADR-011/012/013/028)**: The satellite packages `EricksonLopez.Security.Azure`, `Aws`, `HashiCorpVault`, and `GoogleCloud` currently provide in-memory `ConcurrentDictionary` test doubles and stubs to preserve Native AOT and eliminate third-party SDK dependencies in v1.x. For production deployments requiring real cloud KMS/Secret endpoints, connect via audited cloud SDKs or implement custom `IKeyStore` / `ISecretStore` implementations using your cloud provider's official libraries.

---

## 2. Password Hashing

### ✅ DO: Use Argon2id for all new deployments
```csharp
// Configure CompositePasswordHasher with Argon2id as primary:
services.AddSingleton<IPasswordHasher>(sp =>
    new CompositePasswordHasher(
        primaryHasher: sp.GetRequiredService<Argon2idPasswordHasher>(),
        additionalHashers: [sp.GetRequiredService<Pbkdf2PasswordHasher>()]));
```
Argon2id format prefix reserves the migration slot for future native memory-hard upgrades (ADR-024).

> [!NOTE]
> `AddPasswordSecurity()` registers `Pbkdf2PasswordHasher` (210,000 iterations) as primary by default. To designate `Argon2idPasswordHasher` as primary for new user credentials, configure `CompositePasswordHasher` as shown above.

### ✅ DO: Check `NeedsRehash()` and transparently rehash on login
```csharp
var result = passwordHasher.VerifyPassword(password.AsSpan(), storedHash);
if (result == PasswordVerificationResult.SuccessRehashNeeded)
{
    await db.UpdateHashAsync(userId, passwordHasher.HashPassword(password.AsSpan()));
}
```

### ✅ DO: Tune Argon2id cost parameters to target 300–500ms hash time
```csharp
var hasher = new Argon2idPasswordHasher(memorySizeKb: 131072, iterations: 4, parallelism: 8);
```
Measure on production hardware. Increase `memorySizeKb` until hash time is in target range.

### ❌ DON'T: Use SHA-256/SHA-512 directly for password hashing
These are not KDFs — they don't include salts, iterations, or memory-hardening. Always use `IPasswordHasher`.

### ❌ DON'T: Pass `PasswordHash.Value` to logging frameworks
`PasswordHash.ToString()` is safe (returns `[REDACTED PASSWORD HASH]`). Accessing `.Value` should be limited to storage operations.

---

## 3. Token & API Key Security

### ✅ DO: Store only token hashes, never plaintext tokens
```csharp
var tokenHash = tokenHasher.HashToken(rawToken.AsSpan());
await db.SaveAsync(tokenHash); // Store hash only
// Send rawToken to user in HTTP response — never persist it
```

### ✅ DO: Use HMAC-SHA256 with a pepper key for token hashing
```csharp
var pepperKey = await keyVault.GetKeyAsync("token-pepper-key"); // byte[32]
var hasher = new HmacSha256TokenHasher(pepperKey);
```
Without pepper, a DB dump exposes all token hashes to offline attacks (rainbow tables).

### ✅ DO: Use `OpaqueToken` for log-safe token handling
`OpaqueToken.ToString()` returns `[REDACTED]`. Pass `OpaqueToken` through the call stack; access `.Value` only at the HTTP response boundary.

### ✅ DO: Revoke API keys immediately when compromised
```csharp
await apiKeyStore.RevokeAsync(keyId);
```
`ApiKeyValidator` checks `IsActive()` on every validation — revoked keys are immediately rejected.

### ❌ DON'T: Compare token strings with `==` or `string.Equals`
Always use `ConstantTimeComparer.FixedTimeEquals` or `HmacSha256TokenHasher.VerifyToken` for token comparison.

---

## 4. Memory Safety

### ✅ DO: Always wrap key material in `using` scopes
```csharp
using (var secretBuffer = SecretBuffer.CreateRandom(32))
{
    // Use secretBuffer.Span for cryptographic operations
} // CryptographicOperations.ZeroMemory called here
```

### ✅ DO: Use `Redacted<T>` for all sensitive fields in DTOs
```csharp
public record UserDto(string UserId, Redacted<string> ApiKey, Redacted<string> Password);
```
Prevents accidental logging of sensitive data through ASP.NET serialization or structured logging.

### ❌ DON'T: Store plaintext secrets in `string` variables beyond their immediate scope
Strings are immutable and GC-managed — their memory cannot be reliably zeroed. Use `SecretBuffer` for key material and `Redacted<T>` for strings.

---

## 5. Dependency Injection

### ✅ DO: Use granular DI methods when you don't need all services
```csharp
// Password-only service (no key management overhead)
services.AddPasswordSecurity();
services.AddTokenSecurity();
```

### ✅ DO: Replace `InMemoryApiKeyStore` with a persistent store in production
```csharp
services.AddSingleton<IApiKeyStore>(sp => new DatabaseApiKeyStore(connectionString));
```

### ✅ DO: Replace `InMemoryKeyStore` with a persistent store in production
```csharp
// Example: Custom database or cloud-backed store
services.AddSingleton<IKeyStore>(sp => new DatabaseKeyStore(connectionString));
```
*(Note: As documented in ADR-011, `AzureKeyVaultKeyStore` in v1.x is an in-memory stub; implement against Azure.Security.KeyVault.Keys for real cloud endpoints).*

---

## 6. Secret Resolution

### ✅ DO: Use URI-scheme references in configuration, not raw values
```json
{
  "DatabasePassword": "env:Database:Password",
  "ThirdPartyApiKey": "store:third-party-api-key"
}
```
Load with `CompositeSecretResolver.ResolveAsync()`. This allows switching between backends (env in dev, vault in prod) without code changes.

### ❌ DON'T: Use `raw:` scheme in production
`raw:VALUE` embeds the secret inline. Reserve it for unit tests and local development only.

---

## 7. Zero Trust ABAC

### ✅ DO: Default to `DenyOverrides` combining algorithm
In Zero Trust, explicit Deny should always win over any number of Permit rules. `DenyOverrides` is the default and the correct choice.

### ✅ DO: Include all relevant subject attributes in `AbacContext`
```csharp
var context = new AbacContext()
    .WithSubject("Role", "Manager")
    .WithSubject("MfaVerified", true)
    .WithSubject("ClearanceLevel", 3)
    .WithResource("Classification", "Confidential")
    .WithAction("Export");
```
Incomplete contexts may result in incorrect Deny decisions due to missing attributes.

### ❌ DON'T: Rely solely on role-based access control
Combine role attributes (`Role == "Admin"`) with context attributes (`MfaVerified == true`, `SourceIP in TrustedRange`) for true Zero Trust enforcement.

---

## 8. Observability

### ✅ DO: Subscribe to `SecurityActivitySource` before any operations
```csharp
using var listener = new ActivityListener
{
    ShouldListenTo = source => source.Name == SecurityActivitySource.SourceName,
    Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded,
    ActivityStarted = activity => Console.WriteLine($"[TRACE] {activity.OperationName}"),
};
ActivitySource.AddActivityListener(listener);
```

### ✅ DO: Monitor `Argon2HashingDurationMs` histogram in production
A sudden increase signals server overload or a DoS attack targeting the password hashing endpoint. Alert on P99 > 2000ms.

### ✅ DO: Alert on spikes in `PasswordVerificationsTotal` with `result=Failed` tag
Unusual volumes of failed verifications indicate a credential stuffing attack.

---

## 9. Native AOT

### ✅ DO: Use the Span-based API overloads in AOT-published applications
```csharp
// Zero-allocation, AOT-safe
engine.Encrypt(plaintextSpan, keySpan, aadSpan);
comparer.FixedTimeEquals(left, right);
hasher.HashPassword(password.AsSpan());
```

### ❌ DON'T: Use reflection-based serialization of `SecurityEnvelope`
Use `BinarySecurityEnvelopeSerializer` — it uses deterministic binary format with no reflection.
