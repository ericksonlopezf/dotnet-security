# ADR-023: Dual PBKDF2 Password Hasher Archetypes and Format Segregation

## Status
Accepted

## Date
2026-09-02

**Date**: 2026-09-02  
**Status**: Accepted  
**Deciders**: EricksonLopez.Security Core Team  

---

## Context

The `EricksonLopez.Security` ecosystem contains two distinct implementations of the `IPasswordHasher` abstraction for PBKDF2-HMAC-SHA512:

1. **`EricksonLopez.Security.Passwords.Pbkdf2PasswordHasher`** (located in `EricksonLopez.Security`):
   - Modular crypt format: `$pbkdf2-sha512$i=210000$s=<salt>$<hash>`.
   - Default iterations: `210,000` (OWASP HMAC-SHA512 standard).
   - Designed to participate in `CompositePasswordHasher` alongside `Argon2idPasswordHasher` for transparent credential re-hashing and algorithm migration.

2. **`EricksonLopez.Security.Cryptography.Passwords.Pbkdf2PasswordHasher`** (located in `EricksonLopez.Security.Cryptography`):
   - Standalone delimited format: `PBKDF2.V1$<iterations>$<salt>$<hash>`.
   - Default iterations: `600,000` (maximum-security single-hasher profile).
   - Designed for low-level cryptographic micro-services, CLI tools, and embedded environments that reference only `EricksonLopez.Security.Cryptography` without pulling the full `EricksonLopez.Security` engine.

During the repository consistency audit, this dual implementation was flagged for potential ambiguity, as documentation previously referenced PBKDF2 without explicitly segregating the package tier responsibilities.

---

## Decision

1. **Formal Tier Segregation**:
   - Both implementations are **formally retained** and assigned strictly separated architectural roles:
     - **Tier 1 (Primitives)**: `EricksonLopez.Security.Cryptography.Passwords.Pbkdf2PasswordHasher` is the standalone, dependency-free hasher registered via `services.AddEricksonLopezCryptographyCore()`.
     - **Tier 2 (Full Engine)**: `EricksonLopez.Security.Passwords.Pbkdf2PasswordHasher` is the modular crypt hasher registered via `services.AddPasswordSecurity()` and `services.AddEricksonLopezSecurity()`.

2. **Format Incompatibility by Design**:
   - The two format prefixes (`PBKDF2.V1$` vs `$pbkdf2-sha512$`) remain distinct to prevent cross-tier format collisions and ensure that hashes produced in a standalone crypto context are never mistakenly parsed with differing iteration assumptions.

3. **Guidance and Recommended Path**:
   - For modern web and enterprise applications, the Tier 2 engine (`EricksonLopez.Security`) with `CompositePasswordHasher` is the normative recommendation. It allows applications to transparently upgrade legacy PBKDF2 hashes to Argon2id upon successful authentication.
   - For standalone libraries, cryptographic utilities, or resource-constrained micro-services that do not use `Argon2id` or `KeyRing`, the Tier 1 primitive is recommended.

4. **Documentation & XML Parity**:
   - Both classes must document their exact hash format, iteration defaults, and bounded context in XML documentation and the Public API Reference (`docs/api-reference.md`).

---

## Consequences

- **Positive**:
  - `EricksonLopez.Security.Cryptography` remains a completely standalone, Native AOT, zero-dependency package with its own functional password hasher.
  - Consumers of `EricksonLopez.Security` continue to benefit from modular crypt formatting and multi-algorithm auto-rehashing.
  - Eliminates ambiguity regarding the existence and purpose of both implementations.
- **Negative**:
  - Hashes stored using `PBKDF2.V1` cannot be verified directly by `EricksonLopez.Security.Passwords.Pbkdf2PasswordHasher` without adding an adapter or migrating credentials.

---

## References

- [ADR-001: Bounded Context, Responsibilities, and Package Segregation](./adr-001-bounded-context-and-package-strategy.md)
- [ADR-005: Password Hashing with In-Box PBKDF2, Argon2id, and Auto-Rehash](./adr-005-password-hashing-pbkdf2-argon2-and-auto-rehash.md)
- [RFC 8018: PKCS #5: Password-Based Cryptography Specification Version 2.1](https://datatracker.ietf.org/doc/html/rfc8018)
- [NIST SP 800-63B: Digital Identity Guidelines — Authentication and Lifecycle Management](https://pages.nist.gov/800-63-3/sp800-63b.html)
