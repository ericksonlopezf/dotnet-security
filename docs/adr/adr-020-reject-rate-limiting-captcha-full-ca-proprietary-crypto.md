# ADR-020: Reject Rate Limiting, CAPTCHA / Bot Detection, Full Certificate Authority, and Proprietary Cryptographic Algorithms

## Status
Rejected

## Date
2026-09-01

**Date**: 2026-09-01  
**Status**: Accepted (Decision to Reject Scope)  
**Deciders**: EricksonLopez.Security Core Team

---

## Context

As `EricksonLopez.Security` grows in adoption, feature requests have been received for:

1. **Rate limiting** — Throttle API endpoints to prevent brute force attacks.
2. **CAPTCHA / Bot detection** — Integrate with reCAPTCHA, hCaptcha, or Cloudflare Turnstile to distinguish humans from bots.
3. **Full Certificate Authority (CA)** — Issue X.509 certificates, manage Certificate Revocation Lists (CRLs), and act as an ACME-compatible CA.
4. **Proprietary / Custom cryptographic algorithms** — Implement custom symmetric or asymmetric encryption algorithms.

All four requests were formally evaluated against the library's bounded context (ADR-001) and security principles.

---

## Decision

### 1. Rate Limiting — **Permanently Rejected**

**Reason**: Rate limiting is traffic infrastructure, not cryptographic security.

- ASP.NET Core 7+ ships `System.Threading.RateLimiting` natively with `FixedWindowRateLimiter`, `SlidingWindowRateLimiter`, `TokenBucketRateLimiter`, and `ConcurrencyLimiter`. It requires zero additional dependencies.
- API Gateways (Azure API Management, AWS API Gateway, Kong, Nginx) handle rate limiting at the network layer, where it is more effective than application-layer limiting.
- Adding rate limiting to EricksonLopez.Security would couple the library to HTTP request context and middleware concepts that belong in the web tier, not in a crypto primitives library.
- **Invariant**: If a user needs rate limiting against brute-force attacks on password verification, they should use `System.Threading.RateLimiting` at the controller/middleware level, combined with EricksonLopez.Security's constant-time `PasswordHasher.VerifyPassword()` to prevent timing oracles.

### 2. CAPTCHA / Bot Detection — **Permanently Rejected**

**Reason**: CAPTCHA is a UX mechanism, not a cryptographic security primitive.

- CAPTCHA serves to distinguish human users from automated bots, which is a UX/accessibility/behavioral concern.
- Integrating with reCAPTCHA, hCaptcha, or Cloudflare Turnstile requires sending user behavioral data to third-party services — this conflicts with the privacy-first design of EricksonLopez.Security (see `EricksonLopez.Security.Privacy.Hibp` for the k-anonymity precedent on privacy-preserving third-party calls).
- CAPTCHA adds no protection against the attacks EricksonLopez.Security is designed to prevent: timing attacks, cryptographic oracle attacks, memory leakage, or SSRF.
- Teams that need CAPTCHA should integrate Google reCAPTCHA (`Google.Cloud.RecaptchaEnterprise`), Cloudflare Turnstile, or similar purpose-built services directly.

### 3. Full Certificate Authority (CA) — **Permanently Rejected**

**Reason**: PKI issuance is a separate product domain with extreme security requirements.

- Operating a Certificate Authority requires: certificate issuance logic, CRL management, OCSP responder, key ceremony procedures, Hardware Security Module (HSM) integration for root CA key storage, and potentially ACME protocol server implementation. This is a multi-year, dedicated product effort.
- The existing `EricksonLopez.Security.Pki` package provides **certificate validation** (`CertificateChainValidator`) and **certificate pinning** (`CertificatePinningHandler`). This is the correct bounded context boundary: validating certificates, not issuing them.
- Teams that need automated certificate issuance should use Let's Encrypt via `Certbot` or ASP.NET Core's built-in ACME client, or HashiCorp Vault's PKI engine (configurable via `EricksonLopez.Security.HashiCorpVault`).
- **Boundary statement**: `EricksonLopez.Security.Pki` = certificate *validation*. Certificate *issuance* is explicitly out of scope and will never enter the bounded context.

### 4. Proprietary / Custom Cryptographic Algorithms — **Permanently Rejected**

**Reason**: Implementing custom cryptographic algorithms is a fundamental security anti-pattern.

- The cryptographic community's consensus, supported by decades of research and incident analysis, is unambiguous: **do not roll your own crypto**. Even cryptographers at major research institutions avoid implementing new cryptographic primitives for production use without years of public peer review and third-party cryptanalysis.
- EricksonLopez.Security exclusively uses:
  - NIST-approved algorithms: AES-256-GCM (NIST SP 800-38D), ChaCha20-Poly1305 (RFC 8439), PBKDF2 (NIST SP 800-132), SHA-2 (FIPS 180-4), ML-KEM-768 (NIST FIPS 203).
  - IETF-standardized algorithms: HKDF (RFC 5869), Argon2id (RFC 9106), HMAC-SHA256 (RFC 2104).
  - Only BCL implementations: `System.Security.Cryptography.*`, `Microsoft.AspNetCore.Cryptography.KeyDerivation`. No third-party cryptographic implementations in core.
- Any request to implement "a faster version of AES," "a custom key derivation function," or "a proprietary signing algorithm" will be rejected without review.
- **If a legitimate need for a new algorithm arises** (e.g., a NIST-standardized post-quantum algorithm added to FIPS 203/204/205 that BCL does not yet support), the approach is: wait for BCL support, or use a FIPS-validated third-party library while it is not yet in BCL.

---

## Consequences

- **Positive**: Feature Bloat remains at 0%. Team bandwidth stays focused on differentiating work. The "impossible to do it wrong" invariant is maintained — no rate limiting or CAPTCHA hooks introduce misuse surface. No proprietary crypto CVEs possible.
- **Negative**: Some feature requests will be closed as `wont-fix` with a reference to this ADR. This may create friction with users who expect a "security kitchen sink." The library's positioning ("security primitive layer, not a security platform") must be communicated clearly in the README and documentation.

---

## References

- [ADR-001: Bounded Context and Package Strategy](./adr-001-bounded-context-and-package-strategy.md)
- [ADR-002: Authenticated Encryption (AEAD) Default — Reject CBC/ECB](./adr-002-authenticated-encryption-aead-default.md)
- [product-strategy.md §9 — What NOT to Build](../product-strategy.md)
- [NIST SP 800-38D — AES-GCM](https://csrc.nist.gov/publications/detail/sp/800-38d/final)
- [NIST FIPS 203 — ML-KEM (Kyber)](https://csrc.nist.gov/publications/detail/fips/203/final)
- [System.Threading.RateLimiting — Microsoft Docs](https://learn.microsoft.com/en-us/dotnet/core/extensions/rate-limiting)
