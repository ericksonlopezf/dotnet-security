# ADR-031: Genuine RFC 9106 Argon2id Cryptographic Substrate Adoption via Konscious.Security.Cryptography

## Status
Accepted (Supersedes ADR-024)

## Date
2026-09-08

**Date**: 2026-09-08  
**Status**: Accepted (Supersedes ADR-024)  
**Deciders**: EricksonLopez.Security Core Team

---

## Context
In [ADR-024](./adr-024-argon2id-hasher-implementation-strategy.md), an interim design decision was formalized in which `Argon2idPasswordHasher` utilized PBKDF2-HMAC-SHA512 because the .NET runtime Base Class Library (BCL) did not include `System.Security.Cryptography.Argon2id`. However, this compromise prevented delivering a genuine memory-hard key derivation function, leaving resultant hashes vulnerable to offline brute-force attacks optimized for GPUs and ASICs.

To satisfy banking-grade security requirements and OWASP / NIST SP 800-63B standards for password cracking resistance, integration of the high-performance managed library `Konscious.Security.Cryptography.Argon2` (version 1.3.1) was evaluated and adopted.

---

## Decision

### 1. Genuine RFC 9106 Cryptographic Substrate
Adopt `Konscious.Security.Cryptography.Argon2` within `EricksonLopez.Security` to back `Argon2idPasswordHasher`.
- **Algorithm**: Argon2id (RFC 9106).
- **Default Parameters**:
  - Memory Cost (`m`): 65,536 KiB (64 MiB).
  - Time Cost (`t`): 3 iterations.
  - Parallelism (`p`): 4 concurrent execution lanes.
  - Salt Size: 16 bytes cryptographically generated via `RandomNumberGenerator`.
- **Modular Crypt Format**:
  `$argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>`

### 2. Architectural Invariant Compliance
- **Memory Attack Resistance**: `IsMemoryHard => true` guarantees that each verification and hashing operation actively allocates and manipulates the required 64 MiB, nullifying massive acceleration on GPU clusters.
- **Native AOT & Trimming**: The `Konscious.Security.Cryptography.Argon2` library is written in pure C# with no external unmanaged P/Invoke dependencies, maintaining full compatibility with Native AOT compilation across Linux, macOS, and Windows.
- **Unicode Normalization**: All password inputs are normalized to Unicode Form C (NIST SP 800-63B) prior to UTF-8 encoding.

### 3. Automatic Migration and Transparent Rehashing
Pre-existing hashes generated with PBKDF2 or legacy schemes continue to be verified transparently by `CompositePasswordHasher`. When successful authentication is verified against a legacy hash format, `NeedsRehash` returns `true`, triggering a transparent upgrade to the new RFC 9106 Argon2id format upon next successful login.

---

## Consequences

- **Positive**:
  - Industry-standard maximum password protection (RFC 9106).
  - Elimination of the substitute substrate risk documented in ADR-024.
  - Full compatibility with Native AOT and trimming preserved.
  - Transparent, zero-downtime migration path for existing hashes via `CompositePasswordHasher`.
- **Negative**:
  - Introduces an external managed dependency (`Konscious.Security.Cryptography.Argon2 Version="1.3.1"`).
  - Higher transient memory consumption (64 MiB per hashing operation) under high-concurrency authentication scenarios (mitigated by perimeter rate limiting and authentication concurrency semaphores).

---

## References

- [ADR-005: Password Hashing Baseline and Auto-Rehash](./adr-005-password-hashing-pbkdf2-argon2-and-auto-rehash.md)
- [ADR-024: Argon2idPasswordHasher Cryptographic Substrate and Upgrade Strategy](./adr-024-argon2id-hasher-implementation-strategy.md) (Superseded)
- [ADR-030: Explicit Legacy PBKDF2 Password Hasher Format Segregation](./adr-030-explicit-legacy-pbkdf2-password-hasher-format-segregation.md)
- RFC 9106: Argon2 Memory-Hard Function for Password Hashing and Proof-of-Work Applications
