# Changelog

All notable changes to `EricksonLopez.Security` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

> **Security releases** are marked with a 🔐 icon. If you are using a version
> lower than the latest security release, you should upgrade immediately.

## [Unreleased]

## [1.0.0] — 2026-09-22

> Initial production release of the EricksonLopez.Security ecosystem across all 21 packages.
> Includes core primitives, AEAD engines, multi-version key lifecycle, multi-cloud KMS and secret store adapters (AWS, Azure, GCP, HashiCorp Vault), SAML 2.0 Enterprise Profiles,
> WebAuthn Advanced Attestation, OpenTelemetry instrumentation, FIDO MDS3, and Roslyn Analyzers.
> All core packages maintain 100% Native AOT trimming compatibility and zero-reflection invariants.

### Added — `EricksonLopez.Security` (application password integration & key lifecycle)

- **`ISimplePasswordHasher`** — New application-layer password hasher interface for ASP.NET Identity integration scenarios. Exposes `HashPassword(string)`, `VerifyPassword(string, string)`, and `NeedsRehash(string)` with support for PHP/BSD BCrypt prefix detection (`$2y$`, `$2b$`, `$2a$`).
- **`NeedsRehash` BCrypt/PHP delegation** — `CompositePasswordHasher.NeedsRehash()` now delegates to the primary hasher when the stored hash algorithm is BCrypt (PHP prefix), enabling zero-downtime migration from BCrypt to PBKDF2-HMAC-SHA512.
- **`HkdfAesGcmEncryptionEngine`** — Canonical ephemeral key isolation encryption engine deriving single-use keys via HKDF-SHA512 per ADR-025.
- **`LegacyPbkdf2PasswordHasher`** — Dedicated legacy hasher emitting `$legacy-pbkdf2$` modular crypt format and verifying legacy `$argon2id$` hashes transparently, resolving finding SEC-005 per ADR-030.
- **`InProcessKeyRevocationNotifier`** — Thread-safe, high-performance in-process implementation of `IKeyRevocationNotifier` for dispatching real-time key revocation events with subscriber exception isolation.
- **`DelegateKeyRevocationNotifier`** — Distributed-ready adapter for `IKeyRevocationNotifier` bridging local `KeyRing` caches to external message brokers (Redis Pub/Sub, RabbitMQ, Kafka, Azure Service Bus). Registered via `services.AddDistributedKeyRevocationNotifier(...)`.
- **`KeyRing` real-time cache eviction** — Subscribes to `IKeyRevocationNotifier` upon initialization, automatically wiping and evicting revoked keys from cache. Added `EvictRevokedKey(KeyIdentifier, KeyVersion, KeyPurpose)` and `TryGetKey(KeyIdentifier, KeyVersion, out CryptographicKey?)`.
- **`KeyLifecycleManager` notification dispatch** — Automatically dispatches revocation broadcast signals via `IKeyRevocationNotifier.NotifyRevokedAsync` during `RevokeKeyAsync`.

### Added — `EricksonLopez.Security.Abstractions`
- **`IKeyRevocationNotifier`** — Real-time key revocation broadcasting contract enabling multi-node cluster and in-process key rings to receive revocation signals and immediately invalidate compromised keys.
- **`SecurityError.InvalidNonce` & `SecurityError.BufferTooSmall`** — Strongly-typed validation error factories for cryptographic nonce validation and span destination buffer sizing.

### Added — `EricksonLopez.Security.AspNetCore`
- **`IdentityPasswordHasherBridge<TUser>`** — Drop-in bridge implementing `Microsoft.AspNetCore.Identity.IPasswordHasher<TUser>` backed by `ISimplePasswordHasher`. Registered via `services.AddEricksonLopezIdentityPasswordHasher<TUser>()`.

### Added — `EricksonLopez.Security.Mfa`
- **`IRecoveryCodeGenerator`** — Dependency injection abstraction interface for recovery code generation per ADR-029.
- **`DelegateTotpReplayStore`** — Delegate-driven implementation of `ITotpReplayStore` to integrate distributed stores (e.g. Redis, distributed cache, SQL) without subclassing.
- **`AddDistributedTotpReplayStore`** — Extension methods on `IServiceCollection` registering delegate-driven distributed TOTP replay verification.

### Added — `EricksonLopez.Security.Cryptography.Pkcs11`
- **`Pkcs11DigitalSignatureEngine` async cancellation** — Added `SignAsync` and `VerifyAsync` overloads accepting `CancellationToken` for cooperative cancellation during HSM operations.

### Added — `EricksonLopez.Security.Cryptography.XmlDSig`
- **`XmlVerificationOptions` & `XmlVerificationResult`** — Configuration options for XML signature trust evaluation and structured verification results binding the signed element to prevent XML Signature Wrapping (XSW) attacks per ADR-028.

### Added — `EricksonLopez.Security.GoogleCloud`
- **`GoogleCloudKmsKeyStore` & `GoogleCloudSecretManagerStore`** — Cloud KMS and Secret Manager key/secret store adapters with in-memory double execution modes and DI registration via `services.AddGoogleCloudSecurity()`.

### Added — CI/CD & Build Infrastructure
- **Continuous Integration Pipeline (`.github/workflows/ci.yml`)**: Automated pipeline running compliance audit, then `dotnet-build-test.yml` (multi-SDK build + Coverlet coverage + SonarCloud) and `aot-smoke-test.yml` in parallel on `main` and `develop` branches.
- **Automated Publishing Pipeline (`.github/workflows/publish.yml`)**: Release-triggered workflow with Stryker mutation gate verification, Strong Name signing, symbol packaging (`.snupkg`), Sigstore build provenance attestation, and NuGet Trusted Publishing via OIDC across all 21 packages.
- **Automated Dependency Updates (`.github/dependabot.yml`)**: Weekly Dependabot scans for NuGet packages and GitHub Actions.
- **Root Configuration Artifacts**:
  - `global.json`: Pins .NET SDK version to `10.0.400` with `latestFeature` roll-forward.
  - `NuGet.config`: Standardized, deterministic package source configuration.
  - `.codecov.yml`: Code coverage thresholds (95% project target, 1% threshold).

### Added — Benchmarks
- Expanded `benchmarks/EricksonLopez.Security.Benchmarks` with comparative benchmarks for:
  - Argon2id vs PBKDF2 password hashing.
  - `CompositePasswordHasher` verification and auto-rehash checks.
  - `BinarySecurityEnvelopeSerializer` span-based serialization and deserialization.
  - Multi-threaded concurrent AEAD throughput testing using `Parallel.For`.

### Added — Documentation & Governance
- **ADR-022 (`docs/adr/adr-022-automated-devsecops-supply-chain-attestation.md`)**: Formalized architecture decision record for Automated DevSecOps, Sigstore Build Provenance Attestation, NuGet OIDC Trusted Publishing, Strong Naming, and Stryker.NET 95% mutation threshold gate.
- **ADR-023 (`docs/adr/adr-023-dual-pbkdf2-hasher-architecture.md`)**: Formalized architectural tier segregation between standalone crypto PBKDF2 (600k iterations, `PBKDF2.V1` format) and composite modular crypt PBKDF2 (210k iterations, `$pbkdf2-sha512$` format).
- **ADR-028 (`docs/adr/adr-028-xml-signature-wrapping-defense-and-certificate-validation.md`)**: Formalized XML Signature Wrapping (XSW) defenses and strict certificate validation via `XmlVerificationOptions` and `XmlVerificationResult`.
- **ADR-029 (`docs/adr/adr-029-recovery-code-generator-dependency-injection-abstraction.md`)**: Formalized `IRecoveryCodeGenerator` interface for dependency injection decoupling while preserving high-performance static utilities.
- **ADR-030 (`docs/adr/adr-030-explicit-legacy-pbkdf2-password-hasher-format-segregation.md`)**: Formalized explicit `$legacy-pbkdf2$` modular crypt format segregation via `LegacyPbkdf2PasswordHasher`, resolving SEC-005.
- **Showcase Level 11**: Added executable Level 11 documentation and sample runner demonstrating comprehensive cross-package API coverage across all 21 ecosystem packages.
- **Audit Remediation**: Optimized `AesGcmSecretProtector.Protect/Unprotect` synchronous overloads to eliminate intermediate array allocations; corrected XML doc in `Cryptography/Pbkdf2PasswordHasher`; updated README NuGet badges to v1.0.0; removed unused ecosystem dependencies from `Directory.Packages.props`.
- **Repository Documentation Audit**: Standardized community health files, expanded Native AOT guide (`docs/aot.md`), enhanced Public API Reference (`docs/api-reference.md`) across all 21 packages, and eliminated duplicate roadmap specifications.

### Fixed — Coherence Audit Remediation (2026-09-02)

All findings from the exhaustive code ↔ documentation coherence audit have been corrected:

**P1 — HIGH (3 corrections)**

- **EX-004** (`README.md`): Corrected the Quick Start comment for `IPasswordHasher.HashPassword()`.
  The comment previously claimed the default hash format is `$argon2id$`, but `AddEricksonLopezSecurity()` registers `CompositePasswordHasher` with `Pbkdf2PasswordHasher` as the primary hasher, which produces `$pbkdf2-sha512$i=210000$...` format. Updated comment now accurately reflects the registered behavior and documents how to promote `Argon2idPasswordHasher` as primary.

- **XML-006 / PHANTOM-001** (`src/EricksonLopez.Security/Passwords/Pbkdf2PasswordHasher.cs`): Instrumented `HashPassword()` with `Stopwatch` + `SecurityMeter.Pbkdf2HashingDurationMs.Record(...)`.
  The `security.pbkdf2.hashing_duration_ms` histogram was documented in `SecurityMeter` and `docs/api-reference.md` but never actually emitted. Operators who subscribed to this metric would receive no data. Now emits on every `HashPassword()` call, consistent with `Argon2idPasswordHasher`.

- **MD-004** (`docs/architecture.md`): Replaced "Hybrid ML-KEM-768 PQC" with accurate HKDF-SHA512 description in the Layer Responsibilities table.
  The previous text could lead architects to document the system as "quantum-resistant" in compliance records. Now states "HKDF-Enhanced AES-256-GCM (substrate: HKDF-SHA512; ML-KEM-768 format slot reserved for v2.x, see ADR-025)".

**P2 — MEDIUM (5 corrections)**

- **XML-001** (`src/EricksonLopez.Security.Abstractions/Passwords/PasswordHashAlgorithm.cs`): Rewrote the `Argon2id = 2` enum member XML to clarify it is a modular crypt format identifier, not an RFC 9106 memory-hard algorithm guarantee. Added `<remarks>` documenting the v1.x PBKDF2 substrate and v2.x upgrade path.

- **XML-002** (`src/EricksonLopez.Security.Cryptography/Passwords/Pbkdf2PasswordHasher.cs`): Added comprehensive `<remarks>` documenting Tier 1 vs Tier 2 format incompatibility per ADR-023. Prevents developers from accidentally mixing `PBKDF2.V1$` and `$pbkdf2-sha512$` hashes in the same verification path.

- **MD-008** (`docs/api-reference.md §5`): Added "Cryptographic Substrate (v1.x)" bullet to `Argon2idPasswordHasher` entry documenting the PBKDF2-HMAC-SHA512 substrate, that `m=` and `p=` are format metadata only, and cross-referencing ADR-024.

- **XML-004** (`src/EricksonLopez.Security/Diagnostics/SecurityMeter.cs`): Added `<remarks>` to `Argon2HashingDurationMs` histogram clarifying that latency values reflect PBKDF2-HMAC-SHA512 execution time in v1.x, not RFC 9106 memory-hard hashing. Updated the OTel instrument `description` string accordingly.

- **EX-005** (`docs/api-reference.md §12`): Corrected the `SecurityOpenTelemetryExtensions` description. `security.argon2id.hashing_duration_ms` and `security.pbkdf2.hashing_duration_ms` are `Histogram<double>` instruments, not counters. Moved them from the "counters" list to a "histograms" list. Also expanded the list of emitted spans and counters to be complete.

**P3 — LOW (5 corrections)**

- **MD-002** (`README.md`): Updated ADR count from "23" to "25" architectural decisions in the documentation index.

- **MD-005** (`docs/nuget-packages.md`): Rewrote the dependency boundary note for `EricksonLopez.Security.Abstractions` to be accurate and non-contradictory. Previous phrasing "zero third-party dependencies... beyond `EricksonLopez.Result`" was self-contradictory. Now states it depends only on `EricksonLopez.Result` (ecosystem sibling) with no web frameworks, ORMs, or cloud SDKs.

- **MISS-002** (`docs/api-reference.md §28`): Added `WrapKeyOperation` (`"security.key.wrap"`) and `UnwrapKeyOperation` (`"security.key.unwrap"`) to the `SecurityActivitySource` constants table. These public constants existed in the source code but were absent from the API reference.

- **MD-003** (`README.md`): Added inline HTML comment to the static test-count badge indicating it is updated manually on each release, so contributors know it is not dynamically generated from CI.

- **MISS-003** (`src/EricksonLopez.Security/Passwords/CompositePasswordHasher.cs`): Added `<remarks>` to `NeedsRehash()` documenting the migration promotion behavior: when the primary hasher is `Pbkdf2PasswordHasher` and the stored hash has a `$argon2id$` prefix, `NeedsRehash()` always returns `true` (intentional by design — promotes rehash to the current primary algorithm on next login).

### Fixed — Coherence Audit Remediation (2026-09-04)

All findings from the second exhaustive code ↔ documentation coherence audit have been corrected:

**P2 — MEDIUM (1 correction)**

- **RISK-003** (`src/EricksonLopez.Security.Azure/`, `src/EricksonLopez.Security.Aws/`, `src/EricksonLopez.Security.HashiCorpVault/`):
  Added `ILogger<T>` constructor injection and a `LogWarning` diagnostic to all 6 cloud adapter store classes
  (`AzureKeyVaultKeyStore`, `AzureKeyVaultSecretStore`, `AwsKmsKeyStore`, `AwsSecretsManagerSecretStore`,
  `HashiCorpVaultKeyStore`, `HashiCorpVaultSecretStore`).
  In v1.x, these adapters use in-memory `ConcurrentDictionary` stubs. Without a runtime warning,
  a team deploying to production without reading documentation would silently lose all cryptographic keys
  and secrets on process restart. The warning is emitted once at application startup (DI container
  instantiation) and includes the configured endpoint URI and the v2.x roadmap reference (ADR-011/012/013).
  Updated class-level `<remarks>` XML documentation to explicitly state "will be lost on process restart".

**P3 — LOW (2 corrections)**

- **XML-007** (`src/EricksonLopez.Security/Passwords/Pbkdf2PasswordHasher.cs`): Added class-level
  `<remarks>` documenting the Tier 2 format (`$pbkdf2-sha512$`, 210,000 iterations) per ADR-023,
  the explicit format incompatibility with `EricksonLopez.Security.Cryptography.Pbkdf2PasswordHasher`
  (`PBKDF2.V1$` format, 600,000 iterations), and the DI registration role as primary hasher
  inside `CompositePasswordHasher`. Developers will now see the incompatibility warning directly
  in IntelliSense without having to consult ADR-023.

- **CONT-001** (`docs/aot.md` §2): Corrected the introductory sentence from
  "All 19 runtime packages are assessed for Native AOT and trimming safety" (ambiguous against the
  20-row table) to "All 20 packages are assessed for Native AOT and trimming safety
  (19 runtime packages + 1 build-time analyzer)". Also changed "Three packages" to
  "Three runtime packages" for precision.

---

### Added — Enterprise Observability & Diagnostics

**Observability Infrastructure** (LATER-1 from roadmap — BCL-only, zero OTel dependency in core):

- **`SecurityActivitySource`** — `System.Diagnostics.ActivitySource` named `"EricksonLopez.Security"` with semantic span names and tag key constants.
- **`SecurityMeter`** — `System.Diagnostics.Metrics.Meter` with counters (`security.encrypt.total`, `security.decrypt.total`, `security.key.rotations_total`, `security.key.revocations_total`, `security.apikey.validations_total`, `security.password.verifications_total`) and histograms (`security.argon2id.hashing_duration_ms`, `security.pbkdf2.hashing_duration_ms`).
- **`AesGcmEncryptionEngine`** instrumented — emits `security.encrypt` / `security.decrypt` spans with `security.algorithm`, `security.result`, and `security.error.code` tags.
- **`Argon2idPasswordHasher`** instrumented — emits `security.password.hash` / `security.password.verify` spans; records hashing latency histogram and verification outcome counter.

### Added — `EricksonLopez.Security.OpenTelemetry` (new satellite)

**Optional OTel SDK integration** (LATER-1 from roadmap):

- **New package** `EricksonLopez.Security.OpenTelemetry` — depends on `OpenTelemetry.Api 1.12.0`. Does NOT add OTel to the core package.
- **`SecurityOpenTelemetryExtensions.AddEricksonLopezSecurityInstrumentation()`** — overloaded for both `TracerProviderBuilder` (traces) and `MeterProviderBuilder` (metrics). Single-call opt-in.



### Added — `EricksonLopez.Security.Saml2`

**SAML 2.0 Enterprise Profile Coverage** (NEXT-1 from roadmap):

- **IdP-initiated SSO** — `ISaml2Service.ProcessIdpInitiatedResponseAsync(string samlResponse, SamlValidationOptions options)`.
  Validates the SAML Response from an Identity Provider without a preceding SP-initiated `AuthnRequest`.
  Includes full replay protection via `IDistributedCache` (falls back to in-process `ConcurrentDictionary` for single-instance deployments).
- **SP-initiated Single Logout (SLO)** — Three new methods on `ISaml2Service`:
  - `CreateLogoutRequest(string nameId, string? sessionIndex, SamlOptions options)` — Generates a signed `<samlp:LogoutRequest>`.
  - `ProcessLogoutResponseAsync(string samlResponse, SamlValidationOptions options)` — Validates the IdP's `<samlp:LogoutResponse>`.
  - `CreateLogoutResponse(string inResponseTo, SamlStatusCode status, SamlOptions options)` — Creates a `<samlp:LogoutResponse>` for SP-initiated logout flows where the SP also acts as SLO responder.

### Added — `EricksonLopez.Security.WebAuthn.Fido2`

**Advanced Attestation Verifiers** (NEXT-2 from roadmap):

- **`AndroidSafetyNetAttestationVerifier`** — Verifies Android SafetyNet/Play Integrity attestation statements.
  - JWS signature validation against Google root CA.
  - `ctsProfileMatch` enforcement (device integrity).
  - Nonce binding with `CryptographicOperations.FixedTimeEquals` (no timing oracle).
  - `timestampMs` freshness check (±60 s window).
- **`TpmAttestationVerifier`** — Verifies TPM 2.0 attestation statements for corporate hardware trust.
  - `TPMS_ATTEST` binary parsing with `BinaryPrimitives` (no unsafe code).
  - `extraData` SHA-256 binding to `clientDataHash`.
  - AIK (Attestation Identity Key) certificate chain validation with `CA:FALSE` constraint enforcement.
  - Multi-target compatibility: uses `X509CertificateLoader` on .NET 9+ and `new X509Certificate2(byte[])` with `SYSLIB0057` suppressed on .NET 8.

### Added — Documentation

**Documentation Sprint deliverables** (NOW-1, NOW-2, NOW-3 from roadmap):

- **`docs/migration-from-dataprotection.md`** — Step-by-step migration guide from `Microsoft.AspNetCore.DataProtection` to `EricksonLopez.Security`. Covers encryption, key management, parallel-run strategy, and gotchas. Includes a `DataProtectionBridge` pattern for zero-downtime migration.
- **`docs/migration-from-identity-passwordhasher.md`** — Migration guide from `ASP.NET Identity PasswordHasher<TUser>` to `EricksonLopez.Security` multi-algorithm composite hasher. Covers `IPasswordHasher` adapter, Argon2id promotion, and recovery-from-PBKDF2-V2 scenarios.
- **`docs/quickstart.md`** — 5-minute getting-started guide. Zero-to-first-AEAD-encrypt in 5 steps with DI, key management, and sample `curl` commands.
- **`docs/roadmap.md`** — Public-facing product roadmap aligned with `product-strategy.md` (Strategy B — Balanced). Documents NOW/NEXT/LATER phases, feature decisions, and explicit rejections.

### Added — Samples

**Functional end-to-end samples** (NOW-2 from roadmap):

- **`samples/EricksonLopez.Security.ApiKeys.Sample`** — ASP.NET Core Minimal API demonstrating full API key lifecycle: generate → hash → store (in-memory `IApiKeyStore`) → constant-time validate → revoke. Shows `UseSecurityHeaders`, `AddSecurityAspNetCore`, and the `IApiKeyGenerator`/`IApiKeyValidator` pipeline.
- **`samples/EricksonLopez.Security.Totp.Sample`** — Console app with full MFA enrollment → TOTP verification → recovery code generation → single-use redemption lifecycle. Uses `ITotpService` and `RecoveryCodeGenerator`.
- **`samples/EricksonLopez.Security.Secrets.Sample`** — Console app demonstrating AES-256-GCM AEAD envelope encryption, key rotation with historical data decryption using v1 after rotation to v2, multi-tenant AAD isolation, and `SecretBuffer` ZeroMemory demonstration.

### Added — Architecture Decision Records

**ADRs 015–021** covering all roadmap decisions:

- **`docs/adr/adr-015-reject-jwt-issuance-and-oauth-server.md`** — Formal rejection of JWT issuance and OAuth2/OIDC server scope. References ADR-001. Prevents feature creep.
- **`docs/adr/adr-016-saml2-profile-coverage-audit.md`** — SAML 2.0 coverage audit results. Documents which profiles exist (SP-initiated SSO, signed/encrypted assertions) and which were missing and implemented in this release (IdP-initiated SSO, SLO).
- **`docs/adr/adr-017-satellite-repository-strategy.md`** — Decision to keep all current satellites in the monorepo until 1M+ downloads/month, with explicit criteria for future extraction of `ZeroTrust`, `HIBP`, and enterprise packages.
- **`docs/adr/adr-018-ssrf-prevention-architecture.md`** — Existing SSRF socket-level prevention architecture documented. `SafeSocketsHttpHandler` blocks RFC 1918, loopback, link-local, and cloud metadata endpoints.
- **`docs/adr/adr-019-opentelemetry-satellite-strategy.md`** — OTel satellite design: zero SDK dependency in core, `System.Diagnostics` BCL instrumentation, optional `EricksonLopez.Security.OpenTelemetry` satellite.
- **`docs/adr/adr-020-reject-rate-limiting-captcha-full-ca-proprietary-crypto.md`** — Formal rejection of rate limiting, CAPTCHA, full Certificate Authority, and proprietary crypto algorithms.
- **`docs/adr/adr-021-defer-fido-mds3-u2f-roslyn-analyzer.md`** — Implementation record for FIDO-U2F verifier, MDS3 satellite, SAML SP Metadata, and Roslyn Analyzers (ELS0001–ELS0005). All previously-deferred items fully implemented.

### Added — `EricksonLopez.Security.WebAuthn.Fido2`

**FIDO-U2F Attestation** (`format=fido-u2f`):

- **`FidoU2FAttestationVerifier`** — verifies legacy CTAP1/U2F attestation per W3C WebAuthn Level 2 §8.6. Constructs `verificationData = 0x00 || rpIdHash || clientDataHash || credentialId || publicKeyU2F` and verifies ECDSA-P256-SHA256 signature using the attestation certificate.
- **`AddWebAuthnFido2()`** updated — now registers all 5 verifiers: `none`, `packed`, `android-safetynet`, `tpm`, `fido-u2f`.

### Added — `EricksonLopez.Security.WebAuthn.Fido2.Mds3` (new satellite)

**FIDO Alliance MDS3 Metadata Service**:

- **`IMds3MetadataService`** — interface with `GetMetadataAsync(Guid aaguid)`, `ValidateAuthenticatorStatusAsync(Guid aaguid)`, and `RefreshAsync()`.
- **`HttpMds3MetadataService`** — downloads and parses the FIDO Alliance MDS3 JWT BLOB from `https://mds3.fidoalliance.org/`. Caches parsed entries (AAGUID → `AuthenticatorMetadata`) in memory for 24h (configurable). Thread-safe refresh via `SemaphoreSlim` double-checked locking.
- **`AuthenticatorMetadata`** — cached entry with description, status reports, attestation root certificates, and AAGUID.
- **`AuthenticatorStatus`** enum — all 14 FIDO Alliance status values (FIDO_CERTIFIED, REVOKED, ATTESTATION_KEY_COMPROMISE, etc.).
- **`Mds3Options`** — configures MDS3 URL, cache duration, disallowed statuses, `AllowUnknownAuthenticators` flag.
- **`Mds3ServiceCollectionExtensions.AddFidoMds3()`** — registers `IMds3MetadataService` as Singleton with typed `HttpClient`.

### Added — `EricksonLopez.Security.Saml2`

**SAML 2.0 SP Metadata Generation**:

- **`ISaml2Service.GenerateSpMetadata()`** — generates standards-compliant `<md:EntityDescriptor>` XML per SAML 2.0 Metadata Specification. Includes `<md:SPSSODescriptor>`, `<md:KeyDescriptor>` (signing + encryption), `<md:SingleLogoutService>` (HTTP-POST + HTTP-Redirect, if SLO configured), `<md:NameIDFormat>`, and `<md:AssertionConsumerService>` (HTTP-POST, index=1, isDefault=true).

### Added — `EricksonLopez.Security.Analyzers` (new satellite, netstandard2.0)

**Roslyn Diagnostic Analyzers** — static analysis at compile time:

| ID | Category | Severity | Description |
|---|---|---|---|
| ELS0001 | Security | Warning | Non-constant-time `==`/`!=` comparison of security-sensitive byte[] or string values. Use `CryptographicOperations.FixedTimeEquals()`. |
| ELS0002 | Security | Warning | `SecretBuffer` local variable not declared with `using`. ZeroMemory scrubbing in `Dispose()` never called. |
| ELS0003 | Security | Warning | Hardcoded string literal assigned to variable with security-sensitive name (password, secret, apikey, signingkey, etc.). |
| ELS0004 | Security | Error | MD5/SHA1/SHA-256 used in password hashing context (`MD5.Create()`, `SHA1.Create()`, or `Rfc2898DeriveBytes.Pbkdf2()` with weak `HashAlgorithmName`). |
| ELS0005 | Security | Warning | Security-sensitive value passed to `ILogger` method without `Redacted<T>` wrapper. |

**Installation**: `dotnet add package EricksonLopez.Security.Analyzers`. No runtime dependency.

### Fixed

- `EricksonLopez.Security.Saml2`: Two `CA1873` logging interpolation warnings in `Saml2Service.cs` resolved with `IsEnabled(LogLevel.Information)` guard (lines 492, 589).
- `EricksonLopez.Security` (core): Missing `using System.Collections.Generic` in `Argon2idPasswordHasher.cs` when `KeyValuePair<,>` was used for `AddTag` overloads.
- `EricksonLopez.Security.OpenTelemetry`: Missing `using System;` in `SecurityOpenTelemetryExtensions.cs`.

---

### Added — Foundation Core & Cryptographic Primitives

### Added — `EricksonLopez.Security.Abstractions`

Foundational zero-dependency package. All other packages depend on this.

- **Domain Primitives** — Immutable, strongly-typed value objects:
  - `Secret<T>`, `ProtectedSecret`, `SecretBuffer` — lifecycle-safe secret containers with `ZeroMemory` on `Dispose`.
  - `CryptographicKey`, `KeyIdentifier`, `KeyVersion`, `KeyPurpose`, `KeyStatus` — key lifecycle domain model.
  - `ApiKey`, `ApiKeyId`, `OpaqueToken`, `SecurityStamp`, `Nonce`, `Salt`, `Fingerprint` — token and identity primitives.
  - `Redacted<T>` — log-safe sensitive value wrapper preventing credential leakage in `ToString()`, `{:G}` format strings, and debugger displays.
- **Port Interfaces** — Clean Architecture ports:
  - `IEncryptionEngine`, `IKeyLifecycleManager`, `IKeyRing`, `IKeyStore` — cryptographic key management ports.
  - `IPasswordHasher`, `ISecretProtector`, `ISecretStore` — password and secret management ports.
  - `IApiKeyGenerator`, `IApiKeyValidator`, `ITokenGenerator`, `ITokenHasher` — token security ports.
- **Error Catalog** — `SecurityError` — zero-allocation, Result-pattern error discriminated union with typed sub-errors:
  - `EncryptionFailed`, `DecryptionFailed`, `KeyExpired`, `KeyRevoked`, `KeyNotFound`,
  - `InvalidKey`, `InvalidToken`, `TokenExpired`, `HashingFailed`, `PasswordPolicyViolation`,
  - `SecurityPolicyViolation`, `SecretNotFound`, `Unauthorized`, `Forbidden`.
- **Security Events** — Strongly-typed domain events for auditability:
  - `KeyRotatedEvent`, `KeyRevokedEvent`, `SecretRotatedEvent`,
  - `ApiKeyCreatedEvent`, `ApiKeyRevokedEvent`, `SecurityPolicyViolatedEvent`.
- **Policy Value Objects** — `PasswordPolicy`, `KeyRotationPolicy`, `ApiKeyPolicy`, `TokenPolicy`.

### Added — `EricksonLopez.Security` (Core)

High-performance, Native AOT-first implementations. Zero reflection. Zero unnecessary allocations.

- **Authenticated Encryption (AEAD)**:
  - 🔐 `AesGcmEncryptionEngine` — AES-256-GCM (NIST SP 800-38D). Unique nonce per encryption. Reject-by-design: no CBC/ECB modes exposed.
  - 🔐 `ChaCha20Poly1305EncryptionEngine` — ChaCha20-Poly1305 (RFC 8439). Software-side alternative for environments without AES hardware acceleration.
  - 🔐 `HybridPostQuantumEncryptionEngine` — HKDF-SHA512 per-operation key derivation + AES-256-GCM providing ephemeral key isolation on every encryption. Registered as `AeadAlgorithm.HybridAes256GcmMlKem`. **Note**: The `HybridAes256GcmMlKem` format identifier reserves the slot for a future NIST FIPS 203 ML-KEM-768 upgrade on .NET 10+ (see ADR-025). The v1.x implementation does **not** provide quantum resistance.
- **Binary Security Envelope**:
  - `BinarySecurityEnvelopeSerializer` — Compact versioned binary envelope with automatic nonce generation, key identifier tagging, version headers, and Associated Data (AAD) tenant context binding. Format is forward-compatible across key versions.
  - `SecurityEnvelope`, `EncryptedData` — strongly typed envelope models.
- **Key Lifecycle Management**:
  - `KeyLifecycleManager` — Multi-version key state machine (`Active → Retired → Revoked → Destroyed`) with transparent key rotation. New encryptions use the active key; historical ciphertexts decrypt seamlessly via retired keys.
  - `InMemoryKeyStore` — Development/testing in-memory `IKeyStore` implementation.
  - `KeyRing` — Purpose-isolated key ring resolver.
- **Password Security**:
  - 🔐 `Pbkdf2PasswordHasher` — PBKDF2 with HMAC-SHA512 at 210,000 iterations (OWASP 2024 minimum). MCF-compatible output format.
  - 🔐 `Argon2idPasswordHasher` — Argon2id with configurable memory, iteration, and parallelism parameters. Modular Crypt Format (MCF) serialization.
  - 🔐 `CompositePasswordHasher` — Algorithm-agnostic dispatcher with automatic rehash detection (`PasswordVerificationResult.SuccessRehashNeeded`). Enables zero-downtime algorithm migrations.
  - `PasswordPolicy` — NIST SP 800-63B compliant, zero-allocation span-based validator. Configurable minimum length, complexity, and breach corpus integration.
- **Constant-Time Comparisons**:
  - 🔐 `ConstantTimeComparer` — Fixed-time byte array and string comparison via `CryptographicOperations.FixedTimeEquals`. Eliminates timing side-channel vulnerabilities.
  - 🔐 `TimingSafeString` — Drop-in constant-time string equality helper.
- **Cryptographic Randomness**:
  - `CryptographicRandom` — OS CSPRNG delegate (`RandomNumberGenerator.Fill`). All token and nonce generation routes through this provider.
- **Token & API Key Security**:
  - `OpaqueTokenGenerator` — 256-bit entropy base64url tokens.
  - `HmacSha256TokenHasher` — Deterministic HMAC-SHA256 token fingerprinting.
  - `ApiKeyGenerator` — Structured format `{prefix}_{idHex16}_{secretUrlSafe}` with single-use plaintext issuance and SHA-256 hashed persistence.
  - 🔐 `ApiKeyValidator` — Constant-time validation against stored hash.
- **Secrets Management**:
  - `AesGcmSecretProtector` — AEAD envelope-based secret protection.
  - `EnvironmentSecretStore` — Environment variable backed `ISecretStore`.
  - `CompositeSecretResolver` — URI-scheme based resolution (`env:`, `store:`, `raw:`).
- **DI Registration**:
  - `services.AddEricksonLopezSecurity()` — zero-configuration bootstrap with sensible, secure defaults.

### Added — `EricksonLopez.Security.AspNetCore`

ASP.NET Core integration satellite. Adds web-layer security without coupling core to HTTP.

- 🔐 **Security Headers Middleware** — Single `UseSecurityHeaders()` call injects:
  - `Content-Security-Policy` (CSP) with configurable directives.
  - `Strict-Transport-Security` (HSTS) with `includeSubDomains` and `preload`.
  - `X-Content-Type-Options: nosniff`.
  - `X-Frame-Options: DENY` (configurable).
  - `Referrer-Policy: strict-origin-when-cross-origin`.
  - `Permissions-Policy` (configurable feature flags).
- **API Key Authentication Middleware** — `UseApiKeyAuthentication()` with constant-time validation. Plugs into ASP.NET Core authentication pipeline.
- **Token Extractors** — `BearerTokenExtractor`, `HeaderTokenExtractor` — safe token extraction with no allocation on miss.
- **`IRequestSecurityContext`** — Scoped per-request security context DI service.

### Added — `EricksonLopez.Security.Testing`

Test doubles and assertion kit. Enables fast, deterministic unit testing without production cryptographic overhead.

- `FakeKeyStore` — In-memory `IKeyStore` test double. Pre-seeded with deterministic keys.
- `FakePasswordHasher` — Deterministic `IPasswordHasher` test double. Verification always succeeds for matching pairs.
- `FakeSecretProtector` — Identity-transform `ISecretProtector` test double.
- `DeterministicCryptographicRandom` — Seeded pseudo-random `ICryptographicRandom` for reproducible tests.
- `SecurityAssert` — xUnit/NUnit-compatible assertion helpers for `SecurityError` and `PasswordVerificationResult`.

### Added — `EricksonLopez.Security.Azure`

Azure Key Vault satellite adapter.

- `AzureKeyVaultKeyStore` — `IKeyStore` backed by Azure Key Vault Keys (AES-256-GCM wrapping).
- `AzureKeyVaultSecretStore` — `ISecretStore` backed by Azure Key Vault Secrets.
- `services.AddEricksonLopezAzureKeyVault()` — DI registration accepting `Uri` and `TokenCredential`.
- Full `CancellationToken` propagation on all async operations.

### Added — `EricksonLopez.Security.Aws`

AWS KMS and Secrets Manager satellite adapter.

- `AwsKmsKeyStore` — `IKeyStore` backed by AWS KMS Customer Managed Keys (CMK).
- `AwsSecretsManagerSecretStore` — `ISecretStore` backed by AWS Secrets Manager.
- `services.AddEricksonLopezAws()` — DI registration accepting `AmazonKeyManagementServiceClient` and `AmazonSecretsManagerClient`.

### Added — `EricksonLopez.Security.HashiCorpVault`

HashiCorp Vault Transit + KV v2 satellite adapter.

- `HashiCorpVaultKeyStore` — `IKeyStore` backed by Vault Transit engine (AES-256-GCM).
- `HashiCorpVaultSecretStore` — `ISecretStore` backed by Vault KV v2 engine.
- `services.AddEricksonLopezHashiCorpVault()` — DI registration accepting `VaultClient`.

### Added — `EricksonLopez.Security.Mfa`

Multi-Factor Authentication satellite.

- 🔐 `TotpService` — RFC 6238 TOTP with constant-time code comparison. Configurable time step (default 30s) and TOTP digits (default 6).
- 🔐 `HotpService` — RFC 4226 HOTP with look-ahead window.
- `RecoveryCodeService` — Cryptographically random recovery codes with bcrypt-equivalent single-use hashing.
- `QrCodeUriGenerator` — `otpauth://totp/...` URI generation (compatible with Google Authenticator, Authy, 1Password).
- `services.AddEricksonLopezMfa()` — DI registration.

### Added — `EricksonLopez.Security.WebAuthn.Fido2`

WebAuthn (FIDO2) passkey ceremonies satellite.

- **Registration flow** — `Fido2Service.StartRegistrationAsync()` + `CompleteRegistrationAsync()`.
- **Authentication flow** — `Fido2Service.StartAuthenticationAsync()` + `CompleteAuthenticationAsync()`.
- 🔐 **XSW Mitigation** (XML Signature Wrapping) — `Saml2XswValidator` integration for assertion canonicalization.
- **Attestation Verifiers**:
  - `NoneAttestationVerifier` — `fmt=none` (no attestation) verification.
  - `PackedAttestationVerifier` — `fmt=packed` (self-attestation + ECDSA/RSA certificate-chain verification).
- **ClientDataJSON parsing** — Constant-time `challenge` extraction and `type` validation.
- **`AuthenticatorData` parser** — RP ID hash, flags (UP/UV/AT/ED), sign count extraction.
- `services.AddEricksonLopezFido2()` — DI registration with `Fido2Options`.

### Added — `EricksonLopez.Security.Network`

SSRF prevention satellite (Tier 0 security package, not optional for webhook-issuing services).

- 🔐 `SafeSocketsHttpHandler` — Custom `SocketsHttpHandler` that intercepts DNS resolution, validates resolved IP addresses against RFC 1918 / loopback / cloud metadata (`169.254.169.254`) blocklists via `SafeDnsResolver`, and binds the socket directly to the validated IP to prevent DNS rebinding attacks.
- `SafeDnsResolver` — Async DNS resolver with IP range blocklist enforcement (`IpAddressRange`).
- `SsrfProtectionOptions` — Configurable allowlist for legitimate internal IP ranges.
- `services.AddSafeHttpClient()` — Extension to register `HttpClient` with `SafeSocketsHttpHandler` via `IHttpClientFactory`.

### Added — `EricksonLopez.Security.ZeroTrust`

Zero Trust / ABAC (Attribute-Based Access Control) engine satellite.

- `AbacPolicyEngine` — Evaluates attribute-based policies against principal claims.
- `ZeroTrustPolicyBuilder` — Fluent builder for resource-action-condition policies.
- `IZeroTrustContext` — Request context for tenant, device trust level, and risk score.
- `services.AddEricksonLopezZeroTrust()` — DI registration.

### Added — `EricksonLopez.Security.Pki`

Public Key Infrastructure (certificate validation) satellite.

- `CertificateChainValidator` — Validates X.509 certificate chains with configurable trust anchors, revocation (OCSP/CRL), and policy OIDs. Validation only — no certificate issuance.
- `CertificatePinningHandler` — `DelegatingHandler` for HTTP client certificate pinning (HPKP-style but without the insecurity of HPKP preload).

### Added — `EricksonLopez.Security.Privacy.Hibp`

Have I Been Pwned (HIBP) k-anonymity integration satellite.

- 🔐 `HibpPasswordChecker` — Checks passwords against HIBP Pwned Passwords API via k-anonymity (SHA-1 prefix only sent to the remote API; full hash never transmitted).
- `IHibpPasswordChecker` — Port interface for testability.
- `services.AddHibpPasswordChecker()` — DI registration with `HttpClient` configuration.

### Added — `EricksonLopez.Security.Cryptography`

Extended cryptographic operations satellite.

- `HkdfKeyDeriver` — HKDF-SHA256/SHA512 key derivation (RFC 5869). Used internally by PQC hybrid engine.
- `EcdhKeyAgreement` — Ephemeral ECDH key agreement for key transport scenarios.
- `RsaOaepWrapper` — RSA-OAEP-SHA256 key wrapping for legacy key transport scenarios (AOT-compatible via `RSA.Create()`).

### Added — `EricksonLopez.Security.Cryptography.Pkcs11`

PKCS#11 Hardware Security Module (HSM) satellite adapter.

- `Pkcs11KeyStore` — `IKeyStore` backed by a PKCS#11 HSM. Uses managed PKCS#11 interop (no unsafe P/Invoke blocks in managed code).
- `Pkcs11Options` — PKCS#11 library path, slot, and PIN configuration.

### Added — `EricksonLopez.Security.Cryptography.XmlDSig`

XML Digital Signatures satellite.

- `XmlDigitalSignatureService` — Signs and verifies XML documents per W3C XML-DSig (RFC 3275).
- `XmlDSigOptions` — Signing certificate and canonicalization algorithm configuration.

### Added — `EricksonLopez.Security.Saml2`

SAML 2.0 Web Browser SSO satellite.

- **SP-initiated SSO**:
  - `Saml2Service.CreateAuthnRequest()` — Generates signed/unsigned `<samlp:AuthnRequest>` XML with configurable NameID policy and binding.
  - `Saml2Service.ProcessResponseAsync()` — Processes IdP `<samlp:Response>`. Validates: status code, `InResponseTo` correlation, XSW attack mitigation, `EncryptedAssertion` decryption, XML signature, `NotBefore`/`NotOnOrAfter` conditions, audience restriction, `NameID` extraction, attribute statement mapping.
- **Security Hardening**:
  - 🔐 `Saml2XswValidator` — XML Signature Wrapping (XSW) attack mitigation. Canonicalizes assertion extraction before signature verification.
  - 🔐 `Saml2SignatureValidator` — XMLDSig envelope signature verification with configurable trusted IdP certificate.
  - 🔐 `Saml2AssertionDecryptor` — `EncryptedAssertion` decryption via RSA-OAEP + AES-256 CBC/GCM.
- `Saml2ClaimsMapper` — Maps SAML attributes to .NET `ClaimsPrincipal`.
- `services.AddEricksonLopezSaml2()` — DI registration with `Saml2Options`.

### Security — v1.0.0

- 🔐 All symmetric encryption uses AEAD modes exclusively. AES-CBC and AES-ECB are not exposed in any API surface (enforced by design per ADR-002).
- 🔐 All token and secret comparisons use `CryptographicOperations.FixedTimeEquals` (constant-time) per ADR-006.
- 🔐 All objects holding cryptographic material (`SecretBuffer`, `CryptographicKey`, `Secret<T>`) call `CryptographicOperations.ZeroMemory` in `Dispose()` per ADR-007.
- 🔐 All API key secrets are hashed (SHA-256) at rest. Plaintext is returned once at issuance only per ADR-009.
- 🔐 XML external entity (XXE) resolution is disabled (`XmlResolver = null`) in all XML parsing paths per SAML2 hardening.

### Architecture — v1.0.0

- 15 Architecture Decision Records (ADRs) documented in `docs/adr/`.
- 10 architectural guides in `docs/`.
- 100% Native AOT trimming compatibility (`IsAotCompatible = true` in `Directory.Build.props`).
- Zero reflection in core packages.
- AOT Smoke Test gate in CI/CD pipeline.
- 243 automated test executions (0 failures) across .NET 8.0, 9.0, and 10.0.

---

*Older entries will be added here as the project history is backfilled.*

> **Note on comparison links**: The links below reference the `v1.0.0` git tag created automatically by the release pipeline (`publish.yml`) when packages are published to NuGet.org.

[Unreleased]: https://github.com/ericksonlopezf/dotnet-security/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/ericksonlopezf/dotnet-security/releases/tag/v1.0.0
