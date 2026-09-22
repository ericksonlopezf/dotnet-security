# ADR-005: Password Hashing with In-Box PBKDF2-HMAC-SHA512, Modular Crypt Format, and Auto-Rehash

## Status
Accepted

## Date
2026-09-04

## Context
Password storage requires robust resistance against offline GPU and ASIC brute-force attacks while remaining strictly compatible with Native AOT compilation, trimming, and cross-platform runtimes without requiring native C/C++ P/Invoke binaries.

## Decision
1. **Primary Default Algorithm**: **PBKDF2 with HMAC-SHA512** (RFC 8018) with a minimum of 210,000 iterations and 128-bit cryptographically random salt per OWASP Password Storage Guidelines.
2. **Standard Modular Crypt Format**: Password hashes are encoded using standard MCF prefixes:
   - PBKDF2: `$pbkdf2-sha512$i=210000$s=<base64-salt>$<base64-hash>`
   - Argon2id: `$argon2id$v=19$m=65536,t=3,p=4$<base64-salt>$<base64-hash>`
3. **Composite Dispatcher and Automatic Rehashing**:
   - `CompositePasswordHasher` inspects incoming hash prefixes and delegates verification to the matching algorithm.
   - If verification succeeds with a legacy algorithm or lower iteration parameter, it returns `PasswordVerificationResult.SuccessRehashNeeded`.
   - Applications authenticate the user and immediately update the database with the current primary algorithm hash without requiring a manual password reset.

## Consequences
- **Positive**: Native AOT compatibility, zero external native binaries, seamless transparent password hash upgrades as computing hardware evolves.
- **Negative**: PBKDF2 is less memory-hard than Argon2id, but HMAC-SHA512 provides significant GPU resistance and universal in-box Native AOT support.

## See Also
- [ADR-023](adr-023-dual-pbkdf2-hasher-architecture.md): Documents the dual-hasher architecture introducing `EricksonLopez.Security.Cryptography.Passwords.Pbkdf2PasswordHasher` as a standalone Tier-1 cryptographic primitive alongside the main `EricksonLopez.Security.Passwords.Pbkdf2PasswordHasher`.
- [ADR-024](adr-024-argon2id-hasher-implementation-strategy.md): Documents the current cryptographic substrate of `Argon2idPasswordHasher` (PBKDF2) and the upgrade roadmap to a native Argon2id implementation.
