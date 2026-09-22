# ADR-014: Hybrid Post-Quantum Cryptography (PQC) Key Encapsulation & AEAD

## Status
Superseded by [ADR-025](adr-025-hkdf-enhanced-encryption-engine-pqc-roadmap.md)

## Date
2026-09-04

> _Historical record — this ADR described the intended architecture. The implementation diverged from the original ML-KEM-768 claim. See ADR-025 for the corrected technical status and upgrade roadmap._

## Context
Anticipated advancements in cryptanalytic quantum computing (Shor's algorithm) threaten classical asymmetric key exchange (RSA, ECDH) and create "Harvest Now, Decrypt Later" (HNDL) exposure for sensitive long-term archival data.

## Original Decision (Intent)
1. **Hybrid Key Derivation Model**: Implement `HybridPostQuantumEncryptionEngine` combining classical key material stretching with NIST FIPS 203 ML-KEM-768 (Module-Lattice Key Encapsulation Mechanism) domain separation and HKDF-SHA512 key expansion.
2. **Algorithm Identifier**: Register as `AeadAlgorithm.HybridAes256GcmMlKem` in `EricksonLopez.Security.Abstractions`.
3. **Quantum-Resistant Forward Secrecy**: Derive ephemeral 256-bit keys per encryption pass.

## Implementation Status (Audit Finding)
The actual implementation of `HybridPostQuantumEncryptionEngine` uses **HKDF-SHA512 only** (not ML-KEM-768). The `m=` ML-KEM domain separation label appears in the KDF `info` parameter but no Module-Lattice Key Encapsulation operations are performed. See ADR-025 for the corrected decision and upgrade roadmap.

## Consequences (Historical)
- The format slot (`AeadAlgorithm.HybridAes256GcmMlKem`) is preserved for binary compatibility.
- Hashes created under this engine are NOT quantum-resistant in the cryptographic sense.
