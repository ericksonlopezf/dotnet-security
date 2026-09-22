# Level 03: Production Use Cases — Key Rotation, Scoped API Keys & MFA

## 1. Multi-Version Key Lifecycle & Automatic Rotation

Keys advance through strict lifecycle states (`Active` $\rightarrow$ `Retired` $\rightarrow$ `Revoked` $\rightarrow$ `Destroyed`). New data encrypts with the active version, while historical data decrypts seamlessly with retired versions:

```csharp
using EricksonLopez.Security.Abstractions.KeyManagement;
using EricksonLopez.Security.Abstractions.Primitives;

var lifecycle = serviceProvider.GetRequiredService<IKeyLifecycleManager>();

// 1. Initial active key creation
var initialKey = await lifecycle.GenerateAndActivateKeyAsync(KeyPurpose.DataProtection);

// 2. Automated or manual key rotation (retires v1, activates v2)
var rotateResult = await lifecycle.RotateKeyAsync(initialKey.Value.Metadata.KeyId);
var activeKeyV2 = rotateResult.Value;

// 3. Historical decryption remains functional via IKeyRing
var keyRing = serviceProvider.GetRequiredService<IKeyRing>();
var keyV1 = await keyRing.GetKeyAsync(initialKey.Value.Metadata.KeyId, KeyVersion.FromInt32(1));
```

---

## 2. Scoped High-Entropy API Key Management

API key issuance separates the high-entropy plaintext presented once to the client from the SHA-256 hash stored in the persistence tier:

```csharp
using EricksonLopez.Security.Abstractions.Tokens;
using EricksonLopez.Security.Tokens;

var keyGen = serviceProvider.GetRequiredService<IApiKeyGenerator>();
var validator = serviceProvider.GetRequiredService<IApiKeyValidator>();

// 1. Generate API key — returns ApiKeyIssuanceResult with Key (ApiKey entity) and PlaintextApiKey
var issuance = keyGen.GenerateApiKey(
    ownerId: "enterprise_tenant_01",
    name: "Payments Integration Key",
    prefix: "ek_live",
    lifetime: TimeSpan.FromDays(90),
    scopes: new HashSet<string> { "payments:read", "payments:write" });

string plaintextKey = issuance.PlaintextApiKey; // Return to caller once; never persist
ApiKey storedKey = issuance.Key;               // Persist to database

// 2. Validate incoming HTTP header credentials (constant-time, async)
var validationResult = await validator.ValidateApiKeyAsync(plaintextKey);
if (validationResult.IsSuccess && validationResult.Value.HasScope("payments:write"))
{
    // Request authorized
}
```

---

## 3. RFC 6238 TOTP Multi-Factor Authentication

Full support for Time-Based One-Time Passwords with time-step drift tolerance, QR code URI generation, and custom algorithms (SHA-1, SHA-256, SHA-512):

```csharp
using EricksonLopez.Security.Mfa;

var totpService = serviceProvider.GetRequiredService<ITotpService>();

// 1. Setup new authenticator for user
var setupInfo = totpService.CreateSetupInfo("payments-portal", "user@enterprise.com");
string qrUri = setupInfo.QrCodeUri;
string manualKey = setupInfo.FormattedSecretKey;

// 2. Verify candidate 6-digit code with window tolerance
bool isValid = totpService.ValidateCode(setupInfo.SecretKey, candidateCode);
```

---

## 4. Single-Use Emergency Recovery Codes

The `IRecoveryCodeGenerator` interface and `RecoveryCodeGenerator` provide secure code generation, SHA-256 hashing for database persistence, and constant-time verification:

```csharp
using EricksonLopez.Security.Mfa;

IRecoveryCodeGenerator recoveryGen = new RecoveryCodeGenerator();

// 1. Generate set of formatted codes (e.g. "A3F2-99B1-C4E5")
IReadOnlyList<string> codes = recoveryGen.GenerateCodes(count: 8, codeLength: 10);

// 2. Hash code before storing in database (AUTH-010 pattern)
string firstCode = codes[0];
string storedHash = RecoveryCodeGenerator.HashCode(firstCode);

// 3. Constant-time verification against candidate input
bool isMatch = RecoveryCodeGenerator.VerifyCode(firstCode, storedHash);
```

---

## 5. Distributed Multi-Node TOTP Replay Prevention

When deploying TOTP authentication in load-balanced clusters, `DelegateTotpReplayStore` connects the verification pipeline to a distributed backing store (such as Redis or SQL) to prevent tokens from being replayed across different nodes:

```csharp
using System.Collections.Concurrent;
using EricksonLopez.Security.Mfa;

var clusterStorage = new ConcurrentDictionary<string, DateTimeOffset>();
var distributedStore = new DelegateTotpReplayStore(
    asyncHandler: (key, expiry, ct) => ValueTask.FromResult(clusterStorage.TryAdd(key, expiry)),
    syncHandler: (key, expiry) => clusterStorage.TryAdd(key, expiry));

var nodeA = new TotpService(TimeProvider.System, distributedStore);
var nodeB = new TotpService(TimeProvider.System, distributedStore);

var options = new TotpOptions { PreventReplay = true };
var code = nodeA.ComputeCode(userSecret, DateTimeOffset.UtcNow, options);

// First presentation on Node A succeeds
bool nodeAOk = await nodeA.VerifyCodeAsync(userSecret, code, DateTimeOffset.UtcNow, options);

// Replay attempt on Node B within the same time window fails closed
bool nodeBOk = await nodeB.VerifyCodeAsync(userSecret, code, DateTimeOffset.UtcNow, options); // False!
```

