# Cryptography & Authenticated Envelopes

## 1. Supported AEAD Algorithms

`EricksonLopez.Security` strictly implements Authenticated Encryption with Associated Data (AEAD):

1. **AES-256-GCM (NIST SP 800-38D)**:
   - **Key Size**: 256 bits (32 bytes).
   - **Nonce / IV Size**: 96 bits (12 bytes) uniquely generated per encryption via CSPRNG.
   - **Tag Size**: 128 bits (16 bytes).
   - **Hardware Acceleration**: Automatically utilizes CPU instructions (AES-NI, VAES, ARMv8 Crypto).

2. **ChaCha20-Poly1305 (RFC 8439)**:
   - **Key Size**: 256 bits (32 bytes).
   - **Nonce Size**: 96 bits (12 bytes).
   - **Tag Size**: 128 bits (16 bytes).
   - **Platform Availability**: Available on Linux, macOS, and Windows with compatible crypto providers via `ChaCha20Poly1305.IsSupported`.

3. **HKDF-Enhanced Scheme & Post-Quantum Foundation (ADR-025)**:
   - **Identifier**: `AeadAlgorithm.HkdfAes256Gcm = 3`.
   - **v1.x Implementation**: Implemented by `HkdfAesGcmEncryptionEngine` using per-operation ephemeral key derivation via HKDF-SHA512 combined with AES-256-GCM AEAD encryption. This guarantees cryptographic key isolation per operation.
   - **Post-Quantum Roadmap**: The identifier and byte slot (`0x03`) reserve the format slot for full NIST FIPS 203 ML-KEM-768 encapsulation planned for v2.x (see [ADR-025](./adr/adr-025-hkdf-enhanced-encryption-engine-pqc-roadmap.md)).

---

## 2. Binary Security Envelope Specification

Encrypted payloads produced by `AesGcmSecretProtector` are formatted as versioned binary streams via `BinarySecurityEnvelopeSerializer`:

```text
+--------+--------+----------------+----------------+----------------+----------------+----------------+----------------+----------------+----------------+
| Ver(1) | Alg(1) | KeyIdLen(2 LE) | KeyId (UTF-8)  | KeyVer(4 LE)   | Nonce (12)     | Tag (16)       | AADLen(4 LE)   | AAD (Bytes)    | Ciphertext (N) |
+--------+--------+----------------+----------------+----------------+----------------+----------------+----------------+----------------+----------------+
```

### Byte Layout Breakdown

| Field | Size (Bytes) | Description |
|---|---|---|
| `FormatVersion` | 1 | Envelope layout format version (`0x01`). |
| `Algorithm` | 1 | Algorithm ID (`0x01` = AES-256-GCM, `0x02` = ChaCha20-Poly1305, `0x03` = HkdfAes256Gcm). |
| `KeyIdLength` | 2 (ushort, LE) | Byte length of the UTF-8 encoded KeyIdentifier string. |
| `KeyIdentifier` | N | UTF-8 string bytes identifying the key lineage. |
| `KeyVersion` | 4 (int32, LE) | Sequential integer version of the cryptographic key. |
| `Nonce` | 12 | 96-bit initialization vector. |
| `Tag` | 16 | 128-bit Poly1305/GHASH authentication tag. |
| `AssociatedDataLength` | 4 (int32, LE) | Length of authenticated associated data (0 if omitted). |
| `AssociatedData` | M | Contextual metadata bytes bound to the ciphertext. |
| `CiphertextLength` | 4 (int32, LE) | Byte length of encrypted data. |
| `Ciphertext` | K | Encrypted payload bytes. |

---

## 3. Usage Example: Authenticated Envelope Encryption

```csharp
using System.Text;
using EricksonLopez.Security.Abstractions.Cryptography;
using EricksonLopez.Security.Abstractions.Primitives;
using EricksonLopez.Security.Abstractions.Secrets;

// Protect confidential payload
byte[] sensitiveData = Encoding.UTF8.GetBytes("Confidential Patient Record");
// AuthenticatedContext is a strongly-typed AAD struct — use ForTenant() or FromBytes()
var tenantContext = AuthenticatedContext.ForTenant("hospital-42");

var protectResult = await secretProtector.ProtectAsync(
    secret: sensitiveData,
    purpose: KeyPurpose.SecretProtection,
    expectedAssociatedData: tenantContext);

if (protectResult.IsSuccess)
{
    byte[] encryptedEnvelope = protectResult.Value;
    // Persist encryptedEnvelope into database...
}

// Unprotect confidential payload (verifies authentication tag and AAD tenant context)
var unprotectResult = await secretProtector.UnprotectAsync(
    protectedData: encryptedEnvelope,
    expectedAssociatedData: tenantContext);

if (unprotectResult.IsSuccess)
{
    byte[] originalPlaintext = unprotectResult.Value;
}
```
