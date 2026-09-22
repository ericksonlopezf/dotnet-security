# Level 06: Error Handling, Resilience & Tamper Detection

> **Showcase Level**: Level 6  
> **Source Code**: [`samples/EricksonLopez.Security.Sample/Levels/Level6_ErrorHandlingAndResilience.cs`](../../samples/EricksonLopez.Security.Sample/Levels/Level6_ErrorHandlingAndResilience.cs)  
> **Packages**: `EricksonLopez.Security.Abstractions`, `EricksonLopez.Security`

---

## 1. Overview & Architectural Role

Level 6 demonstrates how `EricksonLopez.Security` handles security failures, tampering, and attacks:
- **Functional Result Pattern**: Operations return `Result<T>` instead of throwing costly or leaky exceptions.
- **Cryptographic Tamper Detection**: AEAD authentication tag validation detects ciphertext modification, header tampering, or AAD tenant mismatches.
- **Emergency Key Revocation**: Instantaneous cryptographic kill-switch rendering compromised keys immediately unusable.
- **Side-Channel Timing Resistance**: Constant-time byte and string comparisons prevent remote timing attacks.
- **`SecurityError` Taxonomy**: Strongly-typed error codes covering all domain security failure modes.

---

## 2. Tamper Detection & AEAD Tag Mismatch

When an attacker attempts to flip a bit in transit or storage, decryption fails safely:

```csharp
var originalData = Encoding.UTF8.GetBytes("FinancialTransfer: $1,000,000 to Account #998877");
var envelope = (await secretProtector.ProtectAsync(originalData, KeyPurpose.SecretProtection)).Value;

// Simulate Man-In-The-Middle bit flipping
var tamperedEnvelope = (byte[])envelope.Clone();
tamperedEnvelope[^1] ^= 0xFF; // Corrupt authentication tag byte

var tamperResult = await secretProtector.UnprotectAsync(tamperedEnvelope);

// tamperResult.IsSuccess == false
// tamperResult.Error.Code == "Security.AuthenticationTagMismatch"
// tamperResult.Error.Description == "Authentication tag verification failed; ciphertext or associated data has been tampered with."
```

---

## 3. Emergency Key Revocation & Real-Time Cache Eviction (Kill-Switch)

In the event of key compromise, revocation immediately prevents any further decryption and broadcasts real-time cache eviction signals via `IKeyRevocationNotifier`:

```csharp
var revocationNotifier = serviceProvider.GetRequiredService<IKeyRevocationNotifier>();
var keyRing = serviceProvider.GetRequiredService<IKeyRing>();

// 1. Subscribe real-time cluster/in-process listener
using var subscription = revocationNotifier.Subscribe((revokedId, revokedVer, revokedPurpose) =>
{
    Console.WriteLine($"[REVOCATION BROADCAST] KeyId={revokedId}, Version={revokedVer}, Purpose={revokedPurpose}");
});

// 2. Emergency Incident: Revoke active key (broadcasts to notifier & evicts KeyRing cache immediately)
var revokeResult = await keyLifecycle.RevokeKeyAsync(
    activeKey.Metadata.KeyId,
    activeKey.Metadata.Version,
    "Compromise suspected in Security Incident #SEC-2026-0042");

// 3. Attempting to decrypt with revoked key fails immediately:
var decryptRevokedResult = await secretProtector.UnprotectAsync(encryptedWithRevokableKey);
// decryptRevokedResult.IsSuccess == false
// decryptRevokedResult.Error.Code == "Security.KeyRevoked"

// 4. Explicit cache invalidation methods for manual lifecycle events:
keyRing.InvalidateKey(activeKey.Metadata.KeyId, activeKey.Metadata.Version);
keyRing.InvalidateActiveKey(KeyPurpose.SecretProtection);
keyRing.InvalidateAll();
```

---

## 4. Constant-Time Comparison

Mitigating remote timing side-channel attacks on hashes, HMACs, and signatures:

```csharp
using EricksonLopez.Security.Randomness;

byte[] expectedSignature = GetExpectedHmac();
byte[] clientSignature = GetClientHmac();

// Fixed-time comparison executes in identical CPU cycles regardless of match offset
bool isValid = ConstantTimeComparer.Shared.FixedTimeEquals(expectedSignature, clientSignature);
```

---

## 5. Structured `SecurityError` Catalog

The library provides standardized error factory methods:

```csharp
using EricksonLopez.Security.Abstractions.Errors;

Error err1 = SecurityError.InvalidCiphertext("Envelope header magic bytes mismatch (expected 0xECSEC01).");
Error err2 = SecurityError.AuthenticationTagMismatch();
Error err3 = SecurityError.KeyRevoked("key_abc123", "Compromised during Security Incident #SEC-2026-0042.");
Error err4 = SecurityError.KeyExpired("key_abc123");
Error err5 = SecurityError.KeyPurposeMismatch("Signing", "SecretProtection");
Error err6 = SecurityError.SecretNotFound("Database:ConnectionString");
```
