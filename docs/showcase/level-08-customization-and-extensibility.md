# Level 08: Customization, Extensibility & Testing Utilities

> **Showcase Level**: Level 8  
> **Source Code**: [`samples/EricksonLopez.Security.Sample/Levels/Level8_CustomizationAndExtensibility.cs`](../../samples/EricksonLopez.Security.Sample/Levels/Level8_CustomizationAndExtensibility.cs)  
> **Packages**: `EricksonLopez.Security`, `EricksonLopez.Security.Abstractions`, `EricksonLopez.Security.ZeroTrust`, `EricksonLopez.Security.Testing`

---

## 1. Overview & Architectural Role

Level 8 demonstrates how to customize, extend, and replace core contracts within the ecosystem without breaking clean architecture boundaries:

- **Custom `IKeyStore` Decorator**: Wrapping key storage operations with audit logging.
- **Dynamic Domain ABAC Rules**: Authoring fine-grained attribute-based access control policies.
- **Transparent Multi-Algorithm Password Migration**: `CompositePasswordHasher` orchestrating legacy PBKDF2 → Argon2id migration.
- **Environment & Multi-Scheme Secret Resolvers**: Resolving secrets across `raw:`, `env:`, and `store:` backends.
- **Custom `IApiKeyStore`**: Managing full API key CRUD and revocation lifecycles.
- **Testing Utilities**: Complete coverage of `EricksonLopez.Security.Testing` test doubles and assertion helpers.

---

## 2. Implementing a Custom `IKeyStore` Decorator

```csharp
using EricksonLopez.Security.Abstractions.KeyManagement;
using EricksonLopez.Security.Abstractions.Primitives;
using EricksonLopez.Security.KeyManagement;
using Microsoft.Extensions.DependencyInjection;

public sealed class CustomAuditedKeyStore : IKeyStore
{
    private readonly IKeyStore _inner;
    public CustomAuditedKeyStore(IKeyStore inner) => _inner = inner;

    public async ValueTask<Result> SaveKeyAsync(CryptographicKey key, CancellationToken ct = default)
    {
        Console.WriteLine($"[AUDIT] Persisting key {key.Metadata.KeyId} (v{key.Metadata.Version})");
        return await _inner.SaveKeyAsync(key, ct);
    }

    public async ValueTask<Result<CryptographicKey>> GetKeyAsync(KeyIdentifier id, KeyVersion version, CancellationToken ct = default)
    {
        Console.WriteLine($"[AUDIT] Reading key {id} (v{version})");
        return await _inner.GetKeyAsync(id, version, ct);
    }

    public ValueTask<Result<IReadOnlyList<KeyMetadata>>> ListMetadataAsync(KeyPurpose? purpose = null, CancellationToken ct = default)
        => _inner.ListMetadataAsync(purpose, ct);

    public ValueTask<Result> UpdateStatusAsync(KeyIdentifier id, KeyVersion version, KeyStatus newStatus, CancellationToken ct = default)
        => _inner.UpdateStatusAsync(id, version, newStatus, ct);
}

// DI Registration:
services.AddEricksonLopezSecurity();
services.AddSingleton<IKeyStore>(sp => new CustomAuditedKeyStore(new InMemoryKeyStore()));
```

---

## 3. Dynamic Domain ABAC Rules

```csharp
using EricksonLopez.Security.ZeroTrust;

var wireTransferRule = AbacRule.PermitIf(
    ruleId: "RULE_FINANCIAL_WIRE_TRANSFER",
    condition: ctx =>
    {
        var role = ctx.Get<string>(AbacAttributeCategory.Subject, "Role");
        var mfa = ctx.Get<bool>(AbacAttributeCategory.Subject, "MfaVerified");
        var amount = ctx.Get<decimal>(AbacAttributeCategory.Resource, "TransferAmount");
        return role == "CFO" && mfa && amount < 1000000m;
    },
    description: "Permits wire transfers under $1M for MFA-verified CFO users.");

var policy = new AbacPolicy(
    policyId: "POLICY_FINANCIAL_OPERATIONS",
    rules: new[] { wireTransferRule },
    combiningAlgorithm: AbacCombiningAlgorithm.DenyOverrides);

var context = new AbacContext()
    .WithSubject("Role", "CFO")
    .WithSubject("MfaVerified", true)
    .WithResource("TransferAmount", 250000m)
    .WithAction("TransferFunds");

var decision = new AbacPolicyEngine().Evaluate(context, new[] { policy });
// decision.IsPermitted == true
```

---

## 4. Multi-Algorithm Password Migration (`CompositePasswordHasher`)

```csharp
using EricksonLopez.Security.Abstractions.Passwords;
using EricksonLopez.Security.Passwords;

var compositeHasher = new CompositePasswordHasher(); // Argon2id primary, PBKDF2 fallback

var hash = compositeHasher.HashPassword("UserPassword123!".AsSpan());
var result = compositeHasher.VerifyPassword("UserPassword123!".AsSpan(), hash);

if (result == PasswordVerificationResult.SuccessRehashNeeded)
{
    var upgraded = compositeHasher.HashPassword("UserPassword123!".AsSpan());
    // Persist upgraded hash to database
}
```

---

## 5. Multi-Scheme Secret Resolution (`CompositeSecretResolver`)

```csharp
using EricksonLopez.Security.Abstractions.Secrets;
using EricksonLopez.Security.Secrets;

var services = new ServiceCollection();
services.AddEricksonLopezSecurity();
using var provider = services.BuildServiceProvider();
var resolver = provider.GetRequiredService<ISecretResolver>();

var rawResult  = await resolver.ResolveAsync("raw:InlineConfigValue123");
var envResult  = await resolver.ResolveAsync("env:DATABASE_CONNECTION");
var storeResult = await resolver.ResolveAsync("store:NonExistent");
```

---

## 6. Testing Utilities (`EricksonLopez.Security.Testing`)

### 6a. `FakePasswordHasher` — Zero-Cost `IPasswordHasher` Test Double

```csharp
using EricksonLopez.Security.Testing.Fakes;

var fakeHasher = new FakePasswordHasher(); // SHA-256 based, no KDF cost

var hash = fakeHasher.HashPassword("TestPassword!".AsSpan());
var isValid = fakeHasher.VerifyPassword("TestPassword!".AsSpan(), hash); // true

// Simulate "needs-rehash" scenario:
fakeHasher.SimulateNeedsRehash = true;
var needsRehash = fakeHasher.NeedsRehash(hash); // true
```

### 6b. `FakeSecretProtector` — XOR-Masking `ISecretProtector` Test Double

```csharp
using EricksonLopez.Security.Testing.Fakes;

var fakeProtector = new FakeSecretProtector();
var payload = Encoding.UTF8.GetBytes("SensitiveTestData");

var protected_ = await fakeProtector.ProtectAsync(payload);
var restored = await fakeProtector.UnprotectAsync(protected_.Value);
// Encoding.UTF8.GetString(restored.Value) == "SensitiveTestData"

// Inject failure to test error-handling paths:
fakeProtector.InjectedError = SecurityError.InvalidCiphertext("Simulated");
var failed = await fakeProtector.ProtectAsync(payload);
// failed.IsSuccess == false, failed.Error.Code == "Security.InvalidCiphertext"
```

### 6c. `FakeKeyStore` — In-Memory `IKeyStore` Test Double

```csharp
using EricksonLopez.Security.Testing.Fakes;

var fakeKeyStore = new FakeKeyStore();
await fakeKeyStore.SaveKeyAsync(cryptographicKey);

var key = await fakeKeyStore.GetKeyAsync(keyId, version);
var list = await fakeKeyStore.ListMetadataAsync();
await fakeKeyStore.UpdateStatusAsync(keyId, version, KeyStatus.Retired);

// Inject error for error-path tests:
fakeKeyStore.InjectedError = SecurityError.KeyNotFound("test", "not found");
var failedGet = await fakeKeyStore.GetKeyAsync(keyId, version);
// failedGet.IsSuccess == false
```

### 6d. `DeterministicRandomNumberGenerator` — Seeded Reproducible RNG

```csharp
using EricksonLopez.Security.Testing.Fakes;

var rng1 = new DeterministicRandomNumberGenerator(seed: 42);
var buf1 = new byte[16];
rng1.Fill(buf1);

var rng2 = new DeterministicRandomNumberGenerator(seed: 42);
var buf2 = new byte[16];
rng2.Fill(buf2);

// Same seed → same output (reproducible tests guaranteed)
Assert.True(buf1.AsSpan().SequenceEqual(buf2));
var n = rng1.GetInt32(0, 100); // deterministic int in [0, 100)
```

### 6e. `TestHttpMessageHandler` — Configurable HTTP Mock

```csharp
using EricksonLopez.Security.Testing.Http;
using System.Net;

var handler = new TestHttpMessageHandler(
    responseContent: "1234567890:5\r\nABCDEF0123:12\r\n",
    statusCode: HttpStatusCode.OK,
    mediaType: "text/plain");

using var client = new HttpClient(handler);
var response = await client.GetAsync("https://api.pwnedpasswords.com/range/ABC12");

Assert.Equal(HttpStatusCode.OK, response.StatusCode);
Assert.Equal(1, handler.RequestCount);
Assert.NotNull(handler.LastRequest?.RequestUri);
```

### 6f. `FakeLogger<T>` & `FakeLogRecord` — Structured Log Capture

```csharp
using EricksonLopez.Security.Testing.Logging;
using Microsoft.Extensions.Logging;

var logger = new FakeLogger<MyService>(minLevel: LogLevel.Debug);

logger.LogInformation("Key rotation completed for KeyId={KeyId}", "key_abc123");
logger.LogWarning("Key approaching expiration in {Days} days", 7);
logger.LogError("Decryption failed — authentication tag mismatch");

// Count and substring assertions
Assert.Equal(3, logger.Count);
Assert.True(logger.HasMessage("rotation"));   // case-insensitive
Assert.False(logger.HasMessage("NotPresent"));

// Typed record access
IReadOnlyList<FakeLogRecord> entries = logger.Entries;
Assert.Equal(LogLevel.Information, entries[0].LogLevel);
Assert.Contains("rotation", entries[0].Message);
Assert.Null(entries[0].Exception);

// String-only snapshot for simple assertions
IReadOnlyList<string> messages = logger.Messages;
Assert.Equal(3, messages.Count);
```

---

## 7. Architecture Notes

| Utility | Interface | Production Use? |
|---|---|---|
| `FakePasswordHasher` | `IPasswordHasher` | ❌ Tests only — no real KDF |
| `FakeSecretProtector` | `ISecretProtector` | ❌ Tests only — XOR mask |
| `FakeKeyStore` | `IKeyStore` | ❌ Tests only — no persistence |
| `DeterministicRandomNumberGenerator` | `ICryptographicRandomNumberGenerator` | ❌ Tests only — not secure |
| `TestHttpMessageHandler` | `HttpMessageHandler` | ❌ Tests only |
| `FakeLogger<T>` | `ILogger<T>` | ❌ Tests only |

All test doubles implement the same production interfaces — direct injection without type casting.
`FakeLogger<T>` is thread-safe (`ConcurrentQueue` backed) — safe for concurrent async test scenarios.


