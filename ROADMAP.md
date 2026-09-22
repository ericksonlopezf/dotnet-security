# Technology & Architecture Roadmap

## Status: v1.0.0 Baseline — v1.1.0 Planned

The roadmap for `EricksonLopez.Security` is derived directly from the verified implementation, product strategy, and Architecture Decision Records (ADRs).

---

## Version 1.0.0 — Released 2026-09-22 ✅

All foundational, satellite, and post-quantum security deliverables are fully implemented, tested, and verified across .NET 8.0, .NET 9.0, and .NET 10.0:

### Core Architecture & Abstractions
- [x] Full Clean Architecture and Ports & Adapters segregation (`Abstractions`, `Core`, `AspNetCore`, `Testing`).
- [x] Functional error handling via `EricksonLopez.Result` and standardized error catalogs (`SecurityError`).
- [x] Immutable strongly-typed domain primitives (`KeyIdentifier`, `KeyVersion`, `Redacted<T>`, `Nonce`, `Salt`, `Fingerprint`, `SecurityStamp`, `ApiKeyId`, `OpaqueToken`).
- [x] Memory scrubbing with `CryptographicOperations.ZeroMemory` upon `Dispose()` for `SecretBuffer` and `CryptographicKey`.
- [x] Type-safe redaction preventing credential leakage in `ToString()` and debugger displays.

### Authenticated Encryption & Cryptography
- [x] AEAD encryption: **AES-256-GCM** (NIST SP 800-38D) and **ChaCha20-Poly1305** (RFC 8439).
- [x] **HKDF-Enhanced Cryptography & Post-Quantum (PQC) Foundation**: HKDF-SHA512 ephemeral key isolation with AES-256-GCM (`HkdfAesGcmEncryptionEngine`). Format slot identifier `HkdfAes256Gcm` (with backward-compatible alias `HybridAes256GcmMlKem`) reserved for future NIST FIPS 203 ML-KEM-768 integration on .NET 10+ (see ADR-025).
- [x] Compact versioned binary security envelope serialization with Associated Data (AAD) tenant binding (`BinarySecurityEnvelopeSerializer`).
- [x] AES-CBC and AES-ECB rejected by API design — no unsafe modes exposed (ADR-002).

### Key Lifecycle Management
- [x] Multi-version key management and automated state machine (`Active → Retired → Revoked → Destroyed`).
- [x] Transparent key rotation (`KeyLifecycleManager`) allowing new encryptions with active keys while seamlessly decrypting legacy envelopes.
- [x] KeyRing resolution with purpose isolation (`KeyPurpose`).

### Password Security & Rehash Migration
- [x] PBKDF2-HMAC-SHA512 (210,000 iterations default) — OWASP 2024 compliant.
- [x] Argon2id with modular crypt format (MCF) serialization.
- [x] `CompositePasswordHasher` dispatcher with automatic rehash detection (`SuccessRehashNeeded`).
- [x] NIST SP 800-63B compliant zero-allocation span `PasswordPolicy`.

### Token Security & API Keys
- [x] High-entropy opaque tokens (256-bit entropy) and numeric verification OTP codes.
- [x] Structured API key issuance (`{prefix}_{idHex16}_{secret24}`) with single-use plaintext, SHA-256 hashed persistence, and constant-time validation.

### Cloud & Enterprise Key Vault Satellite Adapters
- [x] **`EricksonLopez.Security.Azure`** — Azure Key Vault Keys + Secrets adapter.
- [x] **`EricksonLopez.Security.Aws`** — AWS KMS + Secrets Manager adapter.
- [x] **`EricksonLopez.Security.HashiCorpVault`** — HashiCorp Vault Transit + KV v2 adapter.
- [x] **`EricksonLopez.Security.Network`** — SSRF prevention (`SafeSocketsHttpHandler`) with DNS rebinding protection.
- [x] **`EricksonLopez.Security.Mfa`** — TOTP (RFC 6238), HOTP (RFC 4226), recovery codes, QR URI generation.
- [x] **`EricksonLopez.Security.ZeroTrust`** — ABAC Zero Trust policy engine (NIST SP 800-162 / XACML).
- [x] **`EricksonLopez.Security.Pki`** — X.509 certificate chain validation and custom trust anchors.
- [x] **`EricksonLopez.Security.Privacy.Hibp`** — HIBP k-anonymity password breach checking.
- [x] **`EricksonLopez.Security.Cryptography`** — Constant-time primitives and direct encryption engines.
- [x] **`EricksonLopez.Security.Cryptography.Pkcs11`** — PKCS#11 Hardware Security Module (HSM) adapter.
- [x] **`EricksonLopez.Security.Cryptography.XmlDSig`** — W3C XML Digital Signatures (RFC 3275).
- [x] **`EricksonLopez.Security.Testing`** — Test doubles, assertion kit, deterministic random.

---

### Enterprise Federation, Observability & Developer Experience (v1.0.0)

### Documentation Sprint
- [x] **Migration Guide**: `Microsoft.AspNetCore.DataProtection` → EL.Security (`docs/migration-from-dataprotection.md`).
- [x] **Migration Guide**: `ASP.NET Identity PasswordHasher` → EL.Security Passwords (`docs/migration-from-identity-passwordhasher.md`).
- [x] **Quickstart** — 5-minute guide: install, DI setup, first AEAD encryption (`docs/quickstart.md`).
- [x] **Reference Showcase**: 11 progressive levels (Level 0 through 10) in `samples/EricksonLopez.Security.Sample`.
- [x] **Dedicated Sample Applications**:
  - `samples/EricksonLopez.Security.ApiKeys.Sample` (API Key lifecycle in Minimal APIs).
  - `samples/EricksonLopez.Security.Totp.Sample` (MFA TOTP enrollment and recovery codes).
  - `samples/EricksonLopez.Security.Secrets.Sample` (AES-256-GCM envelope and key rotation).

### Enterprise SAML 2.0 & WebAuthn
- [x] **IdP-initiated SSO**: `ISaml2Service.ProcessIdpInitiatedResponseAsync()` with replay attack protection.
- [x] **SP-initiated Single Logout (SLO)**: `CreateLogoutRequest`, `ProcessLogoutResponseAsync`, `CreateLogoutResponse`.
- [x] **SP Metadata Generation**: Standards-compliant `<md:EntityDescriptor>` XML generation.
- [x] **Advanced WebAuthn Attestation Verifiers**:
  - `AndroidSafetyNetAttestationVerifier` (Google Play Integrity / SafetyNet JWS).
  - `TpmAttestationVerifier` (TPM 2.0 hardware trust attestation).
  - `FidoU2FAttestationVerifier` (FIDO-U2F attestation format).

### Satellites & Static Analysis
- [x] **`EricksonLopez.Security.OpenTelemetry`**: Satellite package with `ActivitySource` and `Meter` registration (zero OTel dependency in core).
- [x] **`EricksonLopez.Security.WebAuthn.Fido2.Mds3`**: FIDO Alliance Metadata Service v3 HTTP client and BLOB validator.
- [x] **`EricksonLopez.Security.Analyzers`**: Roslyn Diagnostic Analyzers (`ELS0001`–`ELS0005`) for compile-time security enforcement.

### CI/CD, Quality Infrastructure & Benchmarks
- [x] **Continuous Integration Matrix**: GitHub Actions `.github/workflows/ci.yml` (Ubuntu & Windows, .NET 8/9/10).
- [x] **Automated Publishing Pipeline**: `.github/workflows/publish.yml` with Strong Name verification, symbol packaging, and Sigstore provenance attestation.
- [x] **Centralized Dependency Automation**: `.github/dependabot.yml` for weekly NuGet and GitHub Actions updates.
- [x] **Root Environment Pinning**: `global.json` (pinned to .NET SDK 10.0.400), `NuGet.config`, and `.codecov.yml`.
- [x] **Expanded Benchmarks**: Comparative Argon2id vs. PBKDF2, CompositePasswordHasher, binary envelope, and concurrent throughput benchmarks.

---

## [Unreleased] — Completed in Source (Pending Release)

Features verified in the current commit history and source code (post-v1.0.0), prepared for next release:

### Application Password Integration
- [x] **`ISimplePasswordHasher`** — Application-layer password hasher interface designed for ASP.NET Identity bridge scenarios. Exposes `HashPassword(string)`, `VerifyPassword(string, string)`, and `NeedsRehash(string)`.
- [x] **`NeedsRehash` BCrypt/PHP delegation** — `CompositePasswordHasher.NeedsRehash()` delegates to the primary hasher when the stored hash uses BCrypt PHP/BSD prefixes (`$2y$`, `$2b$`, `$2a$`), enabling zero-downtime migration from BCrypt to PBKDF2-HMAC-SHA512.
- [x] **`LegacyPbkdf2PasswordHasher`** — Dedicated legacy hasher using `$legacy-pbkdf2$` modular crypt prefix, handling legacy format migration per ADR-030 and resolving SEC-005.

### ASP.NET Core Integration
- [x] **`IdentityPasswordHasherBridge<TUser>`** — Drop-in bridge implementing `Microsoft.AspNetCore.Identity.IPasswordHasher<TUser>` backed by `ISimplePasswordHasher`. Registered via `services.AddEricksonLopezIdentityPasswordHasher<TUser>()`.

### Key Lifecycle & Revocation
- [x] **`IKeyRevocationNotifier`, `InProcessKeyRevocationNotifier` & `DelegateKeyRevocationNotifier`** — Real-time key revocation notification contracts, thread-safe in-process broadcaster, and distributed message broker adapter dispatching revocation signals to key rings.
- [x] **`KeyRing` Cache Eviction** — Automated subscription to revocation notifications, immediately zeroing and evicting revoked cryptographic keys from internal active and historical key caches.

### Cryptography & Protocol Hardening
- [x] **`HkdfAesGcmEncryptionEngine`** — Canonical ephemeral key isolation encryption engine per ADR-025.
- [x] **`IRecoveryCodeGenerator`** — Dependency injection abstraction for recovery backup code generation per ADR-029.
- [x] **`DelegateTotpReplayStore` & `AddDistributedTotpReplayStore`** — Delegate-driven distributed TOTP replay store for seamless Redis/database integration.
- [x] **`Pkcs11DigitalSignatureEngine` Cancellation Support** — Cooperative task cancellation overloads (`SignAsync`, `VerifyAsync`) accepting `CancellationToken`.
- [x] **`XmlVerificationOptions` & `XmlVerificationResult`** — W3C XMLDSig certificate validation options and signed element binding to neutralize XML Signature Wrapping (XSW) attacks per ADR-028.
- [x] **Error Model Expansion** — Strongly-typed `SecurityError.InvalidNonce` and `SecurityError.BufferTooSmall` validation errors.

### Cloud Adapters & Extensions
- [x] **`EricksonLopez.Security.GoogleCloud`** — Google Cloud KMS (`GoogleCloudKmsKeyStore`) and Secret Manager (`GoogleCloudSecretManagerStore`) adapters with in-memory test doubles and DI registration via `services.AddEricksonLopezGoogleCloudSecurity()`.

### Showcase & Interactive Verification
- [x] **Showcase Level 11** — `Comprehensive Public API Coverage Verification`: exhaustive runtime test gate verifying all 89 public APIs across all 21 packages.

---

## Version 1.1.0 — Planned (H1 2027)

- [ ] **Satellite Repository Strategy Evaluation (ADR-017)**:
  - Monitor package download thresholds (criteria: $\ge$ 1M downloads/month, independent release cadence).
  - Evaluate potential extraction of `EricksonLopez.Security.ZeroTrust` $\rightarrow$ `EricksonLopez.Authorization`.
  - Evaluate potential extraction of `EricksonLopez.Security.Privacy.Hibp` $\rightarrow$ `EricksonLopez.Privacy`.
  - Evaluate grouping enterprise packages (`Pkcs11` + `XmlDSig`) $\rightarrow$ `EricksonLopez.Security.Enterprise`.

---

## Explicit Non-Goals & Architectural Exclusions

The following features have been formally evaluated and rejected to preserve security, maintainability, and domain boundaries:

| Feature Area | Decision | Governing ADR | Rationale |
|---|---|---|---|
| **OAuth2 / OIDC Server** | Rejected | ADR-015 | Specialized domain; use dedicated identity providers (Duende IdentityServer, OpenIddict). |
| **JWT Issuance** | Rejected | ADR-015 | Outside cryptographic and data protection scope; token generation handles opaque high-entropy tokens. |
| **Rate Limiting / CAPTCHA** | Rejected | ADR-020 | Belongs in network/gateway layers (ASP.NET Core RateLimiter, Cloudflare, YARP). |
| **Full Certificate Authority (CA)** | Rejected | ADR-020 | CA operations belong in dedicated PKI infrastructure (Vault, cert-manager, Active Directory CS). |
| **Proprietary Cryptography** | Rejected | ADR-002, ADR-020 | Non-standard algorithms introduce critical vulnerability risks. |
| **Unauthenticated Ciphers (CBC, ECB)**| Rejected | ADR-002 | Subject to padding oracle and block permutation attacks. |
