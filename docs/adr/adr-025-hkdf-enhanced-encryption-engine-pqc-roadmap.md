# ADR-025: HKDF-Enhanced Encryption Engine — PQC Implementation Status and ML-KEM-768 Roadmap

## Status
Accepted (Supersedes ADR-014)

## Date
2026-09-02

## Context
ADR-014 described `HybridPostQuantumEncryptionEngine` as implementing NIST FIPS 203 ML-KEM-768 key encapsulation combined with AES-256-GCM. The 2026-09-02 coherence audit verified that the actual implementation uses HKDF-SHA512 key derivation only — no Module-Lattice Key Encapsulation operations are performed.

The root cause is that `System.Security.Cryptography.MLKem` is not available as a stable, FIPS-validated inbox API in .NET as of .NET 10 Preview. Third-party ML-KEM libraries are not yet Native AOT compatible to the standard required by this ecosystem.

## Decision

### 1. Current Implementation (v1.x — Accepted)
The engine is implemented as `HkdfAesGcmEncryptionEngine` (`EricksonLopez.Security.Cryptography.HkdfAesGcmEncryptionEngine`) and implements:
- **Per-operation HKDF-SHA512 key derivation**: For each `Encrypt` call, a 256-bit ephemeral key is derived from the root key (IKM), the fresh 12-byte nonce (salt), and a fixed domain-separation label (info): `"EricksonLopez.Security.HKDF.AES-256-GCM.v1"`.
- **AES-256-GCM authenticated encryption** using the derived ephemeral key.
- **ZeroMemory on derived key** after each operation.

This provides:
- Per-operation key isolation (compromise of one ephemeral key does not expose root key or other operation keys).
- Replay resistance (unique nonce + derived key per operation).
- Authentication tag binding (AES-GCM).

This does NOT provide:
- Quantum resistance (a quantum adversary with root key access can derive all ephemeral keys).
- ML-KEM-768 key encapsulation or post-quantum forward secrecy in the cryptographic sense.

### 2. Algorithm Identifier & Compatibility Alias
- **Canonical Identifier**: `AeadAlgorithm.HkdfAes256Gcm = 3` accurately reflects the HKDF-enhanced AES-256-GCM scheme.
- **Backward Compatibility**: `AeadAlgorithm.HybridAes256GcmMlKem = 3` is retained as an `[Obsolete]` alias to maintain source and binary compatibility with existing `SecurityEnvelope` records.

### 3. ML-KEM-768 Upgrade Path (v2.x — Planned)
When any of the following conditions are met, a true ML-KEM-768 implementation will be introduced:

| Condition | Target |
|---|---|
| `System.Security.Cryptography.MLKem` reaches stable release with FIPS 140-3 validation in .NET | .NET 10 or later |
| A Native AOT-compatible ML-KEM-768 NuGet package passes a security audit | If condition 1 is unmet by v2.0 milestone |

When implemented:
- A dedicated `HybridPostQuantumEncryptionEngine` will perform a genuine ML-KEM-768 encapsulation to produce a shared secret, combine it with the classical HKDF-derived key via XOR or concatenated HKDF, and use the combined key for AES-256-GCM.
- Existing envelopes encrypted with the v1 HKDF-only engine can be decrypted without changes (format backward compatibility via byte `0x03`).

## Consequences
- **Positive**: No breaking changes; honest security posture clearly communicated; format slot reserved.
- **Negative**: Data encrypted with v1 engine is not quantum-resistant. Users with HNDL threat models should use `AesGcmEncryptionEngine` or `ChaCha20Poly1305EncryptionEngine` until a genuine ML-KEM implementation is available, and plan re-encryption upon v2.x release.

## See Also
- [ADR-014](adr-014-hybrid-post-quantum-cryptography-pqc.md): Original (superseded) decision.
- [ADR-002](adr-002-authenticated-encryption-aead-default.md): AEAD algorithm selection baseline.
- NIST FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism Standard.
- dotnet/runtime#84530: .NET MLKem tracking issue.
