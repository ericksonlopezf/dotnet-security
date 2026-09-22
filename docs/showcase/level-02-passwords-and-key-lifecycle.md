# Level 02: Password Security & Multi-Version Key Lifecycle

## 1. Password Hashing with Auto-Rehash Detection

`EricksonLopez.Security` provides `IPasswordHasher` and `CompositePasswordHasher` for automated password hash verification and algorithm upgrades:

```csharp
using EricksonLopez.Security.Abstractions.Passwords;
using Microsoft.Extensions.DependencyInjection;

var hasher = serviceProvider.GetRequiredService<IPasswordHasher>();

// Hash password
string hash = hasher.HashPassword("SecurePassword2026!");

// Verify password
PasswordVerificationResult verification = hasher.VerifyPassword("SecurePassword2026!", hash);

if (verification == PasswordVerificationResult.Success)
{
    Console.WriteLine("Authentication successful.");
}
else if (verification == PasswordVerificationResult.SuccessRehashNeeded)
{
    // Re-hash with latest parameters/algorithm and update database
    string upgradedHash = hasher.HashPassword("SecurePassword2026!");
    UpdateUserHash(upgradedHash);
}
```

---

## 2. Multi-Version Key Lifecycle Management

Keys advance through strict lifecycle states:
1. **Active**: Used for both encryption and decryption.
2. **Retired**: Used only for decryption of existing data; never used for new encryptions.
3. **Revoked / Compromised**: Blocked from further use.
4. **Destroyed**: Cryptographically purged from storage.

```csharp
var lifecycle = serviceProvider.GetRequiredService<IKeyLifecycleManager>();

// 1. Generate new active encryption key
var keyResult = await lifecycle.GenerateAndActivateKeyAsync(KeyPurpose.Encryption);
var activeKey = keyResult.Value;

// 2. Rotate keys (retires existing active key and generates a new active version)
var rotateResult = await lifecycle.RotateKeyAsync(activeKey.Metadata.KeyId);

// 3. Historical decryption works transparently
var keyRing = serviceProvider.GetRequiredService<IKeyRing>();
var historicalKey = await keyRing.GetKeyAsync(activeKey.Metadata.KeyId, activeKey.Metadata.Version);
```

---

## 3. Direct AEAD Ciphers & HKDF Ephemeral Subkey Derivation

The library offers hardware-accelerated and software-fallback AEAD cipher engines:

```csharp
using EricksonLopez.Security.Abstractions.Cryptography;
using EricksonLopez.Security.Cryptography;

// 1. Hardware AES-256-GCM
var aesEngine = AesGcmEncryptionEngine.Shared;

// 2. ChaCha20-Poly1305 (RFC 8439)
var chachaEngine = ChaCha20Poly1305EncryptionEngine.Shared;

// 3. HKDF-AES-256-GCM (Ephemeral Subkey Derivation per message)
var hkdfEngine = HkdfAesGcmEncryptionEngine.Shared;
// Derives unique subkey using HKDF-SHA256 with domain context:
var encResult = hkdfEngine.Encrypt(plaintextBytes, masterKeySecret, associatedData);
```

---

## 4. Cryptographic Domain Error Factories

Pre-fabricated error instances avoid allocation while enforcing strict domain contracts:

```csharp
using EricksonLopez.Security.Abstractions.Errors;

// Rejects invalid nonce lengths (< 12 bytes)
// SecurityError.InvalidNonce accepts an optional string details description
var invalidNonce = SecurityError.InvalidNonce("Nonce must be exactly 12 bytes; received 8 bytes.");
// code: "Security.InvalidNonce"

// Rejects undersized destination buffers
var bufferTooSmall = SecurityError.BufferTooSmall("Destination buffer is 32 bytes; 64 bytes required.");
// code: "Security.BufferTooSmall"
```

