# Project Governance

## Overview

`EricksonLopez.Security` is maintained as a foundational Tier-1 security ecosystem within the `EricksonLopez.*` enterprise framework portfolio. Its mandate is to provide misuse-resistant, zero-allocation, and Native AOT-first cryptographic, identity, and access control primitives.

---

## Roles & Responsibilities

### Project Lead & Maintainers
- Review and approve pull requests across all 21 packages.
- Ensure strict adherence to Clean Architecture, Native AOT trimming, and zero-allocation performance invariants.
- Manage security disclosures and emergency patch releases in coordination with the security team.
- Maintain the authoritative Architecture Decision Records (ADRs) in `docs/adr/`.

### Contributors
- Submit bug reports, documentation improvements, test suites, and feature proposals adhering to [CONTRIBUTING.md](./CONTRIBUTING.md).
- Follow Conventional Commits and ensure all quality gates (unit tests, architecture tests, Stryker mutation score, and AOT smoke tests) pass.

---

## Architectural Decision-Making Process

1. **Architecture Decision Records (ADRs)**: Any architectural modification, scope change, or algorithm addition/rejection must be documented via an ADR in `docs/adr/`.
2. **Authoritative Cryptographic Standards**: Algorithm selections and parameter configurations must be grounded in peer-reviewed recommendations from:
   - **NIST**: Special Publications (SP 800-38D, SP 800-63B, SP 800-162, FIPS 203).
   - **IETF**: RFC 8439 (ChaCha20-Poly1305), RFC 6238 (TOTP), RFC 4226 (HOTP).
   - **OWASP**: Cheat Sheet Series and password storage standards.
3. **Rejection of Proprietary Cryptography**: Proprietary ciphers, custom hashing schemes, or unauthenticated modes (AES-CBC, ECB) are explicitly prohibited (see ADR-002 and ADR-020).
4. **Breaking Changes & SemVer**: All public API changes strictly follow Semantic Versioning 2.0.0. Deprecations must be signaled at least one minor release prior to removal with `[Obsolete]` attributes and clear migration pathways.
