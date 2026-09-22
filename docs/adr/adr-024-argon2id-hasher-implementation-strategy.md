# ADR-024: Argon2idPasswordHasher Cryptographic Substrate and Upgrade Strategy

## Status
Superseded by ADR-031

## Date
2026-09-02

## Context
The coherence audit (2026-09-02) identified that `Argon2idPasswordHasher` produces hashes in the Argon2id modular crypt format (`=19=...,t=...,p=...$...`) but uses `Rfc2898DeriveBytes.Pbkdf2` with HMAC-SHA512 internally, not the Argon2id memory-hard function defined by RFC 9106.

The root cause is that .NET's `System.Security.Cryptography` namespace does not include a native Argon2id implementation (as of .NET 10 Preview). All available in-box KDF options are PBKDF2 variants. Implementing Argon2id via P/Invoke to `libargon2` would violate the Native AOT, zero-native-binary, and cross-platform constraints established in ADR-005.

## Decision

### 1. Current Substrate (v1.x — Accepted)
`Argon2idPasswordHasher` uses **PBKDF2-HMAC-SHA512** as its derivation function:
- Effective iterations = `time_cost_parameter x 70,000` (default: `3 x 70,000 = 210,000`)
- `memorySizeKb` and `parallelism` parameters are stored as format metadata only; they do not affect the derivation.
- The `$` format prefix is used to:
  1. Reserve the algorithm slot for future native Argon2id migration.
  2. Enable `CompositePasswordHasher` routing and transparent rehashing.
  3. Differentiate from PBKDF2 hashes in the stored hash database.

### 2. Documentation Correction
All documentation, XML comments, and ADRs must accurately state that the current cryptographic substrate is PBKDF2-HMAC-SHA512, not RFC 9106 Argon2id. The security posture (OWASP-compliant, GPU-resistant, but not memory-hard) must be clearly communicated.

### 3. Future Upgrade Path (v2.x — Planned)
When any of the following conditions are met, a native Argon2id implementation will replace the PBKDF2 substrate:

| Condition | Target |
|---|---|
| .NET ships System.Security.Cryptography.Argon2id inbox | TBD (tracked in dotnet/runtime) |
| A Native AOT-compatible, zero-P/Invoke Argon2id is available in an audited NuGet package | If condition 1 is unmet by v2.0 milestone |

When the upgrade is implemented:
- A new `Argon2idPasswordHasher.V2` implementation will be introduced.
- The existing PBKDF2-based implementation will be renamed internally (format prefix unchanged for backward compatibility).
- `CompositePasswordHasher` will transparently rehash existing `$` hashes to the real Argon2id format via `SuccessRehashNeeded`.
- The `$` format prefix will be retained to preserve stored hashes without migration.

## Consequences
- **Positive**: Native AOT, zero external dependencies, cross-platform compatibility maintained; no breaking changes to stored hash format.
- **Negative**: Current hashes are not memory-hard; offline GPU attacks are more feasible than against true Argon2id (mitigated by OWASP-minimum 210,000 SHA-512 PBKDF2 iterations).

## See Also
- [ADR-005](adr-005-password-hashing-pbkdf2-argon2-and-auto-rehash.md): Original password hashing architecture decision.
- [ADR-023](adr-023-dual-pbkdf2-hasher-architecture.md): Dual-PBKDF2 hasher architecture.
