# API Design & Architectural Rationale — EricksonLopez.Security

> **Version**: v1.0.0  
> **Target Frameworks**: .NET 8.0 | .NET 9.0 | .NET 10.0  
> **Core Paradigms**: Clean Architecture, Result Pattern, Native AOT, Span Ergonomics, Misuse Resistance.

---

## 1. Design Philosophy & Core Tenets

The public API of `EricksonLopez.Security` adheres to the guiding principle:
> *"Make secure software easy to write and insecure software hard or impossible to write."*

### Architectural Invariants
1. **Explicit Strongly-Typed Contracts**: Primitive types (`string`, `byte[]`) are wrapped in domain primitives (`KeyIdentifier`, `KeyVersion`, `ApiKeyId`, `Nonce`, `Salt`, `Fingerprint`) to eliminate parameter transposition errors.
2. **Zero Ambient State / No Global Singletons**: All components are registered via `Microsoft.Extensions.DependencyInjection` and configured via standard options patterns (`IOptions<TOptions>`).
3. **Functional Error Handling via Result Pattern**: Anticipated failures (invalid password, expired key, wrong token, tampered envelope) return `Result` or `Result<T>` from `EricksonLopez.Result` with typed `SecurityError` codes. Exceptions are reserved exclusively for developer-induced precondition bugs (`ArgumentNullException`).
4. **Immutability by Default**: Security value objects and envelope structures are immutable records (`record`, `readonly struct`).
5. **Memory Hygiene**: Ephemeral keys, nonces, and plaintext buffers implement `IDisposable` and immediately wipe their memory contents via `CryptographicOperations.ZeroMemory`.
6. **Side-Channel Timing Resistance**: All credential, token, and hash verifications strictly enforce `CryptographicOperations.FixedTimeEquals`.

---

## 2. API Surface Catalog Across All 21 Packages

### Tier 0: Abstractions & Domain Contracts
- **`EricksonLopez.Security.Abstractions`**:
  - `Primitives/`: `KeyIdentifier`, `KeyVersion`, `KeyPurpose`, `KeyStatus`, `KeyMetadata`, `CryptographicKey`, `Redacted<T>`, `ISecret`, `ISecret<T>`, `ISecretBuffer`, `SecurityStamp`, `ApiKeyId`, `ApiKey`, `OpaqueToken`, `Nonce`, `Salt`, `Fingerprint`.
  - `Cryptography/`: `AeadAlgorithm`, `EncryptedData`, `SecurityEnvelope`, `IAuthenticatedEncryptionEngine`, `IEncryptionKeyProvider`, `ISecurityEnvelopeSerializer`.
  - `KeyManagement/`: `IKeyRing`, `IKeyStore`, `IKeyLifecycleManager`.
  - `Passwords/`: `PasswordHashAlgorithm`, `PasswordVerificationResult`, `IPasswordHasher`, `PasswordHash`.
  - `Tokens/`: `ITokenGenerator`, `ITokenHasher`, `IApiKeyGenerator`, `IApiKeyValidator`, `IApiKeyStore`, `ApiKeyIssuanceResult`.
  - `Secrets/`: `ISecretProtector`, `ISecretStore`, `ISecretResolver`.
  - `Randomness/`: `ICryptographicRandomNumberGenerator`, `IConstantTimeComparer`.
  - `Policies/`: `ISecurityPolicy<T>`, `PasswordPolicy`, `KeyRotationPolicy`, `ApiKeyPolicy`, `TokenPolicy`.
  - `Events/`: `ISecurityEvent`, `SecurityEventSeverity`, `KeyRotatedEvent`, `KeyRevokedEvent`, `SecretRotatedEvent`, `ApiKeyCreatedEvent`, `ApiKeyRevokedEvent`.
  - `Errors/`: `SecurityError` (Standardized factory for all failure codes).

### Tier 1: Core Cryptographic & Security Engines
- **`EricksonLopez.Security`**:
  - `AesGcmEncryptionEngine`, `ChaCha20Poly1305EncryptionEngine`, `HybridPostQuantumEncryptionEngine` (HKDF-SHA512 ephemeral key isolation; ML-KEM-768 format slot reserved for v2.x per ADR-025).
  - `BinarySecurityEnvelopeSerializer` (Compact binary stream encoding).
  - `KeyLifecycleManager`, `KeyRing` (Multi-version key state transitions).
  - `Pbkdf2PasswordHasher`, `Argon2idPasswordHasher`, `CompositePasswordHasher`.
  - `OpaqueTokenGenerator`, `ApiKeyGenerator`, `ApiKeyValidator`.
  - `AesGcmSecretProtector`, `CompositeSecretResolver`.
- **`EricksonLopez.Security.Cryptography`**:
  - `ConstantTimeComparer`, `TimingSafeString`.
  - `CryptographicRandom` (CSPRNG wrapper with span overloads).
  - Direct PBKDF2 and Argon2id primitive implementations.
- **`EricksonLopez.Security.Mfa`**:
  - `TotpService` (RFC 6238 TOTP with configurable time-step and drift window).
  - `HotpService` (RFC 4226 counter-based OTP).
  - `RecoveryCodeGenerator` (Single-use high-entropy emergency codes).
  - `Base32Encoding`, `OtpUriBuilder` (Authenticator app QR URI generator).
- **`EricksonLopez.Security.ZeroTrust`**:
  - `AbacPolicyEngine`, `AbacContext`, `AbacPolicy`, `AbacRule`.
  - NIST SP 800-162 & XACML Deny-Overrides evaluation logic.
- **`EricksonLopez.Security.WebAuthn.Fido2`**:
  - `WebAuthnCeremonyService` (Registration & assertion ceremonies).
  - `AuthenticatorDataParser`, `CoseKeyParser`.
  - Attestation verifiers: `PackedAttestationVerifier`, `TpmAttestationVerifier`, `AndroidSafetyNetAttestationVerifier`, `FidoU2FAttestationVerifier`, `NoneAttestationVerifier`.
- **`EricksonLopez.Security.WebAuthn.Fido2.Mds3`**:
  - `HttpMds3MetadataService`, `IMds3MetadataService`, `Mds3Options`.
  - FIDO Alliance MDS3 JWT BLOB parser and authenticator status cache.
- **`EricksonLopez.Security.Saml2`**:
  - `Saml2Service` (SP-initiated & IdP-initiated SSO, SLO, SP Metadata generation).
  - `Saml2XswValidator` (Anti-XML Signature Wrapping validation).
  - `Saml2SignatureValidator`, `Saml2AssertionDecryptor`, `Saml2ClaimsMapper`.

### Tier 2: Web & Network Perimeter Integration
- **`EricksonLopez.Security.AspNetCore`**:
  - `SecurityHeadersMiddleware`, `SecurityHeadersOptions` (CSP, HSTS, X-Frame-Options, XCTO).
  - `ApiKeyAuthenticationMiddleware`, `ApiKeyAuthenticationOptions`.
  - `IRequestSecurityContext`, `RequestSecurityContext`.
- **`EricksonLopez.Security.Network`**:
  - `SafeSocketsHttpHandler` (Socket-level SSRF defense with DNS rebinding mitigation).
  - `SafeDnsResolver`, `IpAddressRange` (CIDR filtering for RFC 1918, loopback, link-local, cloud metadata).

### Tier 3: Enterprise Infrastructure, Cloud KMS & HSM Adapters
- **`EricksonLopez.Security.Pki`**:
  - `CertificateChainValidator`, `PkiValidationOptions` (Custom trust anchors, CRL/OCSP validation).
- **`EricksonLopez.Security.Privacy.Hibp`**:
  - `HaveIBeenPwnedClient`, `PasswordPwnedValidator` (k-Anonymity SHA-1 breach verification).
- **`EricksonLopez.Security.Cryptography.XmlDSig`**:
  - `XmlDigitalSignatureService`, `XmlDSigOptions` (W3C XML-DSig RFC 3275 enveloped, enveloping, detached).
- **`EricksonLopez.Security.Cryptography.Pkcs11`**:
  - `Pkcs11KeyStore`, `Pkcs11HsmSession`, `Pkcs11SignatureEngine` (Hardware Security Module Cryptoki interop).
- **`EricksonLopez.Security.Azure`**:
  - `AzureKeyVaultKeyStore`, `AzureKeyVaultSecretStore` (`Azure.Security.KeyVault.*` integration).
- **`EricksonLopez.Security.Aws`**:
  - `AwsKmsKeyStore`, `AwsSecretsManagerStore` (`AWSSDK.*` integration).
- **`EricksonLopez.Security.GoogleCloud`**:
  - `GoogleCloudKeyStore`, `GoogleCloudSecretStore` (`Google.Cloud.Kms.V1` and `Google.Cloud.SecretManager.V1` integration).
- **`EricksonLopez.Security.HashiCorpVault`**:
  - `HashiCorpVaultTransitEngine`, `HashiCorpVaultKvStore` (Vault HTTP API integration).
- **`EricksonLopez.Security.OpenTelemetry`**:
  - `SecurityOpenTelemetryExtensions.AddEricksonLopezSecurityInstrumentation()` (OTel Tracer & Meter integration).

### Tier 4: Tooling, Testing & Static Analysis
- **`EricksonLopez.Security.Testing`**:
  - `FakeKeyStore`, `FakeSecretStore`, `FakePasswordHasher`, `DeterministicRandomGenerator`, `SecurityAssert`.
- **`EricksonLopez.Security.Analyzers`**:
  - Roslyn Diagnostic Analyzers: `ELS0001` (constant-time comparison), `ELS0002` (`SecretBuffer` disposal), `ELS0003` (hardcoded credentials), `ELS0004` (insecure password hashers), `ELS0005` (unredacted logging).

---

## 3. Backwards Compatibility & SemVer Governance

1. **Semantic Versioning 2.0.0**:
   - `MAJOR`: Breaking API contract alterations or algorithm deprecation removals.
   - `MINOR`: Backward-compatible feature additions, new cryptographic engines, or satellite adapters.
   - `PATCH`: Backward-compatible bug fixes and internal performance optimizations.
2. **Deprecation Strategy**:
   - Deprecated methods or types are annotated with `[Obsolete("...", error: false)]` for at least one minor release prior to removal.
   - Migration pathways must be fully documented in `docs/` before deprecation release.
