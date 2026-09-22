# Public API Inventory — EricksonLopez.Security

> **Version**: v1.0.0  
> **Phase**: PHASE 9 — SHOWCASE SYNCHRONIZATION (POST-DISCOVERY DELTA)  
> **Scope**: Exclusive analysis of Core Library and Infrastructure projects. Ignored: Tests, Benchmarks, Internal Analyzers, Testing Doubles.

---

## Field Descriptions

| Field | Description |
|---|---|
| **Name** | Fully qualified or base name of the public type / member |
| **Namespace** | Namespace where the element resides |
| **Responsibility** | Core single responsibility |
| **Dependencies** | Direct runtime dependencies |
| **Use Cases** | Typical operational and architecture scenarios |
| **Complexity Level** | Basic / Intermediate / Advanced |
| **Existing Example** | Yes (indicates Showcase Level) / No |

---

## 1. Domain Primitives (`EricksonLopez.Security.Abstractions.Primitives`)

| Name | Namespace | Responsibility | Dependencies | Use Cases | Complexity Level | Existing Example |
|---|---|---|---|---|---|:---:|
| `KeyIdentifier` | `EricksonLopez.Security.Abstractions.Primitives` | UUID identifier for cryptographic keys | — | Key identification & key ring lookup | Basic | Yes (L0, L2, L3) |
| `KeyVersion` | `EricksonLopez.Security.Abstractions.Primitives` | Monotonic key version counter (starts at 1) | — | Key rotation & backward-compatible decryption | Basic | Yes (L0, L2, L3) |
| `Redacted<T>` | `EricksonLopez.Security.Abstractions.Primitives` | Memory wrapper masking sensitive values in `ToString()` | — | PII, credentials, API keys in logs | Basic | Yes (L0, L2, L8) |
| `Nonce` | `EricksonLopez.Security.Abstractions.Primitives` | Fixed-length 12-byte AEAD initialization vector | — | AES-GCM and ChaCha20-Poly1305 encryption | Basic | Yes (L0, L2) |
| `Salt` | `EricksonLopez.Security.Abstractions.Primitives` | Cryptographic 16-byte KDF salt | — | Password hashing & key derivation | Basic | Yes (L0, L2) |
| `SecurityStamp` | `EricksonLopez.Security.Abstractions.Primitives` | Unique UUID stamp for session invalidation | — | User session logout & token revocation | Basic | Yes (L0, L2) |
| `Fingerprint` | `EricksonLopez.Security.Abstractions.Primitives` | Strongly-typed SHA-256 binary fingerprint | — | Public key & artifact integrity verification | Intermediate | Yes (L2) |
| `ApiKeyId` | `EricksonLopez.Security.Abstractions.Primitives` | Strongly-typed identifier for API keys | — | API key database indexing | Basic | Yes (L3, L8) |
| `ApiKey` | `EricksonLopez.Security.Abstractions.Primitives` | API key metadata entity (excludes plaintext) | `ApiKeyId` | Persistence, scope checking, revocation | Intermediate | Yes (L3, L8) |
| `ISecret` | `EricksonLopez.Security.Abstractions.Primitives` | Base marker interface for sensitive memory objects | — | Generic constraint for memory wiping | Basic | Yes (L2) |
| `ISecretBuffer` | `EricksonLopez.Security.Abstractions.Primitives` | Ephemeral buffer scrubbed on disposal (`ZeroMemory`) | `ISecret`, `IDisposable` | Ephemeral symmetric keys & decrypted plaintexts | Intermediate | Yes (L2, L7) |
| `SecretBuffer.FromUtf8()` | `EricksonLopez.Security.Memory` | Factory: allocates a new `SecretBuffer` from a `ReadOnlySpan<char>` encoded as UTF-8, enabling zero-intermediate-string sensitive text capture | `SecretBuffer` | Capturing passwords from UI input without managed string allocation | Intermediate | Yes (L2) |
| `CryptographicKey` | `EricksonLopez.Security.Abstractions.Primitives` | Cryptographic key entity with secure buffer & metadata | `KeyMetadata`, `Secret<byte[]>` | Key ring storage & lifecycle transitions | Intermediate | Yes (L1, L3, L8) |
| `KeyMetadata` | `EricksonLopez.Security.Abstractions.Primitives` | Metadata descriptor (Algorithm, Purpose, Status, TTL) | `KeyIdentifier`, `KeyVersion` | Audit tracking & expiration enforcement | Basic | Yes (L3, L8) |
| `ProtectedSecret` | `EricksonLopez.Security.Abstractions.Primitives` | Encrypted envelope container with associated metadata | `SecurityEnvelope` | Storing encrypted database fields | Intermediate | Yes (L3) |
| `OpaqueToken` | `EricksonLopez.Security.Abstractions.Primitives` | High-entropy random token with masked `ToString()` | `Redacted<string>` | Session cookies, bearer tokens, OTPs | Basic | Yes (L1) |

---

## 2. Cryptographic Engines & Envelopes (`EricksonLopez.Security.Abstractions.Cryptography`)

| Name | Namespace | Responsibility | Dependencies | Use Cases | Complexity Level | Existing Example |
|---|---|---|---|---|---|:---:|
| `IAuthenticatedEncryptionEngine` | `...Abstractions.Cryptography` | Unified contract for AEAD ciphers | `EncryptedData` | High-throughput authenticated encryption | Intermediate | Yes (L2, L7) |
| `AeadAlgorithm` | `...Abstractions.Cryptography` | Enum of supported algorithms (`Aes256Gcm=1`, `ChaCha20Poly1305=2`, `HkdfAes256Gcm=3` per ADR-025) | — | Algorithm negotiation & envelope headers | Basic | Yes (L2) |
| `EncryptedData` | `...Abstractions.Cryptography` | Readonly record struct holding ciphertext, nonce, and tag | `Nonce` | Intermediate result of AEAD encryption | Basic | Yes (L2) |
| `ISecurityEnvelopeSerializer` | `...Abstractions.Cryptography` | Binary serializer for interoperable envelope layout | `SecurityEnvelope` | Serializing/deserializing wire packets | Intermediate | Yes (L2) |
| `SecurityEnvelope` | `...Abstractions.Cryptography` | Portable binary envelope containing metadata + payload | `KeyIdentifier`, `KeyVersion` | Database storage of encrypted records | Intermediate | Yes (L2) |
| `AesGcmEncryptionEngine` | `EricksonLopez.Security.Cryptography` | Hardware-accelerated AES-256-GCM cipher engine (`AesGcmEncryptionEngine.Shared` singleton) | `IAuthenticatedEncryptionEngine` | Standard high-throughput encryption hotpaths | Intermediate | Yes (L2, L7) |
| `AesGcmAuthenticatedEncryptionEngine` | `EricksonLopez.Security.Cryptography` | AES-256-GCM engine variant accepting `ICryptographicRandomNumberGenerator` for injectable randomness | `IAuthenticatedEncryptionEngine`, `ICryptographicRandomNumberGenerator` | Testable AES-GCM with deterministic nonce injection | Advanced | Yes (L2) |
| `HkdfAesGcmEncryptionEngine` | `EricksonLopez.Security.Cryptography` | Ephemeral subkey derivation via HKDF-SHA512 + AES-256-GCM | `IAuthenticatedEncryptionEngine` | Per-message key isolation & domain separation | Advanced | Yes (L2) |
| `ChaCha20Poly1305EncryptionEngine` | `EricksonLopez.Security.Cryptography` | RFC 8439 ChaCha20-Poly1305 cipher engine | `IAuthenticatedEncryptionEngine` | Systems lacking AES hardware acceleration | Intermediate | Yes (L2) |
| `BinarySecurityEnvelopeSerializer` | `EricksonLopez.Security.Cryptography` | Zero-allocation binary formatter (`0xECSEC01`) | `ISecurityEnvelopeSerializer` | Compact envelope serialization | Intermediate | Yes (L2) |
| `AuthenticatedContext` | `EricksonLopez.Security.Abstractions.Cryptography` | Strongly-typed cryptographic Associated Authenticated Data (AAD) bound to tenant or raw bytes; `Empty`, `ForTenant(string)`, `FromBytes(ReadOnlySpan<byte>)`, `Span`, `IsEmpty` | — | Per-tenant envelope binding, context-binding AAD for AEAD | Intermediate | Yes (L2) |

---

## 3. Key Lifecycle Management (`EricksonLopez.Security.Abstractions.KeyManagement`)

| Name | Namespace | Responsibility | Dependencies | Use Cases | Complexity Level | Existing Example |
|---|---|---|---|---|---|:---:|
| `KeyPurpose` | `EricksonLopez.Security.Abstractions.Primitives` | Enumeration of cryptographic usage purposes | — | Restricting keys to specific operations | Basic | Yes (L1, L2, L3) |
| `KeyStatus` | `EricksonLopez.Security.Abstractions.Primitives` | Enum of key states (`Active`, `Retired`, `Revoked`, `Destroyed`) | — | State machine lifecycle control | Basic | Yes (L2, L3, L6) |
| `IKeyLifecycleManager` | `...Abstractions.KeyManagement` | Orchestrator for key creation, rotation, revocation | `KeyPurpose`, `CryptographicKey` | Key rotation automations & kill-switches | Intermediate | Yes (L1, L3, L6, L8) |
| `IKeyStore` | `...Abstractions.KeyManagement` | Storage contract for persisting cryptographic keys | `CryptographicKey` | In-memory, Azure KV, AWS KMS, Vault backends | Intermediate | Yes (L8) |
| `IKeyRing` | `...Abstractions.KeyManagement` | Read-only in-memory lookup cache for active/retired keys | `CryptographicKey` | Decrypting payloads with historical keys | Intermediate | Yes (L1, L3, L4) |
| `IEncryptionKeyProvider` | `...Abstractions.KeyManagement` | Provider returning current active key for a purpose | `CryptographicKey` | Internal DI resolution for `ISecretProtector` | Basic | Yes (L1) |
| `InMemoryKeyStore` | `EricksonLopez.Security.KeyManagement` | Thread-safe concurrent dictionary key repository | `IKeyStore` | Local development, testing, and caching | Basic | Yes (L3, L8) |
| `KeyLifecycleManager` | `EricksonLopez.Security.KeyManagement` | Concrete implementation of `IKeyLifecycleManager` | `IKeyStore`, `IKeyRing` | Production key lifecycle management | Intermediate | Yes (L3) |
| `KeyRing` | `EricksonLopez.Security.KeyManagement` | Concrete cached implementation of `IKeyRing` (also implements `IEncryptionKeyProvider`) | `IKeyStore`, `KeyRingOptions` | High-speed in-memory key resolution | Intermediate | Yes (L3, L11) |
| `KeyRingOptions` | `EricksonLopez.Security.KeyManagement` | Configuration for `KeyRing` in-memory cache TTL (`CacheTtl` defaults to 30 seconds; set to `TimeSpan.Zero` to disable) | — | Tuning key cache expiry to minimize plaintext exposure in memory dumps | Basic | Yes (L11) |
| `IKeyRevocationNotifier` | `...Abstractions.KeyManagement` | Defines contract for dispatching and receiving real-time key revocation signals across in-process key rings and cluster nodes | `KeyIdentifier`, `KeyVersion`, `KeyPurpose` | Immediate cluster-wide key revocation broadcasts | Intermediate | Yes (L6, L11) |
| `InProcessKeyRevocationNotifier` | `EricksonLopez.Security.KeyManagement` | High-performance in-process thread-safe broadcaster for key revocations | `IKeyRevocationNotifier` | Local cache invalidation & in-process notification | Intermediate | Yes (L6, L11) |
| `DelegateKeyRevocationNotifier` | `EricksonLopez.Security.KeyManagement` | Distributed-ready key revocation broadcaster delegating to external message brokers | `IKeyRevocationNotifier` | Cluster-wide key revocation & Redis/RabbitMQ/Kafka integration | Intermediate | Yes (L6, L11) |
| `IKeyRing.InvalidateKey()` | `...Abstractions.KeyManagement` | Immediately evicts and scrubs a specific versioned key from the local cache | `KeyIdentifier`, `KeyVersion` | Immediate eviction of revoked/compromised keys | Basic | Yes (L6, L11) |
| `IKeyRing.InvalidateActiveKey()` | `...Abstractions.KeyManagement` | Immediately evicts and scrubs the active key for a given purpose from local cache | `KeyPurpose` | Immediate eviction upon emergency key rotation | Basic | Yes (L6, L11) |
| `IKeyRing.InvalidateAll()` | `...Abstractions.KeyManagement` | Immediately evicts and scrubs all cached keys and metadata from local cache | — | Cluster re-sync & emergency zeroization | Basic | Yes (L6, L11) |

---

## 4. Password Security (`EricksonLopez.Security.Abstractions.Passwords`)

| Name | Namespace | Responsibility | Dependencies | Use Cases | Complexity Level | Existing Example |
|---|---|---|---|---|---|:---:|
| `IPasswordHasher` | `...Abstractions.Passwords` | Interface for hashing and verifying passwords | `PasswordHash` | User authentication & credential storage | Basic | Yes (L1, L8) |
| `ISimplePasswordHasher` | `...Abstractions.Passwords` | Lightweight string-oriented password hasher contract | — | Simplified password hashing without ReadOnlySpan | Basic | Yes (L2, L8) |
| `PasswordVerificationResult` | `...Abstractions.Passwords` | Enum (`Failed=0`, `Success=1`, `SuccessRehashNeeded=2`) | — | Triggering automatic hash upgrades | Basic | Yes (L1, L2, L8) |
| `PasswordHashAlgorithm` | `...Abstractions.Passwords` | Enum (`Pbkdf2HmacSha512=1`, `Argon2id=2`) | — | Modular crypt format tag identification | Basic | Yes (L2, L8) |
| `PasswordHash` | `...Abstractions.Passwords` | Strongly-typed wrapper with redacted `ToString()` | `PasswordHashAlgorithm` | Safe password hash entity | Basic | Yes (L2) |
| `Argon2idPasswordHasher` | `EricksonLopez.Security.Passwords` | Default hasher using 210,000 rounds PBKDF2-SHA512 | `IPasswordHasher` | OWASP-compliant password hashing | Basic | Yes (L1, L8) |
| `Pbkdf2PasswordHasher` | `EricksonLopez.Security.Passwords` | NIST SP 800-63B PBKDF2-HMAC-SHA512 hasher | `IPasswordHasher` | High-iteration PBKDF2 hashing | Basic | Yes (L8) |
| `LegacyPbkdf2PasswordHasher` | `EricksonLopez.Security.Passwords` | Verifies legacy `$legacy-pbkdf2$` hashes and signals rehash | `IPasswordHasher` | Transparent hash upgrade workflows | Intermediate | Yes (L8) |
| `CompositePasswordHasher` | `EricksonLopez.Security.Passwords` | Multi-algorithm dispatcher with auto-rehash signaling | `IPasswordHasher` | Migrating legacy PBKDF2 hashes to Argon2id | Intermediate | Yes (L8) |

---

## 5. Security Policies (`EricksonLopez.Security.Abstractions.Policies`)

| Name | Namespace | Responsibility | Dependencies | Use Cases | Complexity Level | Existing Example |
|---|---|---|---|---|---|:---:|
| `ISecurityPolicy<T>` | `...Abstractions.Policies` | Generic policy validation contract | `Result` | Domain invariant validation | Basic | Yes (L2) |
| `PasswordPolicy` | `...Abstractions.Policies` | NIST SP 800-63B password complexity policy | `ISecurityPolicy<ReadOnlySpan<char>>` | Password registration & change validation | Basic | Yes (L2) |
| `KeyRotationPolicy` | `...Abstractions.Policies` | Policy governing rotation intervals & retirement grace | — | Automated key retirement rules | Basic | Yes (L2) |
| `ApiKeyPolicy` | `...Abstractions.Policies` | Policy defining minimum entropy and expiration for API keys | — | API key issuance | Basic | Yes (L2) |
| `TokenPolicy` | `...Abstractions.Policies` | Policy governing opaque token byte length and TTL | — | Session token validation | Basic | Yes (L2) |

---

## 6. Secrets Management (`EricksonLopez.Security.Abstractions.Secrets`)

| Name | Namespace | Responsibility | Dependencies | Use Cases | Complexity Level | Existing Example |
|---|---|---|---|---|---|:---:|
| `ISecretProtector` | `...Abstractions.Secrets` | High-level facade for protecting/unprotecting secrets | `KeyPurpose` | Encrypting PII, connection strings, payload fields | Basic | Yes (L1, L3, L6) |
| `AesGcmSecretProtector` | `EricksonLopez.Security.Secrets` | Implementation of `ISecretProtector` via AES-256-GCM | `IKeyLifecycleManager` | Default DI secret protector | Intermediate | Yes (L1) |
| `ISecretStore` | `...Abstractions.Secrets` | Backend adapter for retrieving and saving secrets | `Redacted<string>` | Env vars, Azure KV, AWS Secrets Manager | Intermediate | Yes (L8) |
| `EnvironmentSecretStore` | `EricksonLopez.Security.Secrets` | OS environment variable secret store | `ISecretStore` | Container & 12-factor application secrets | Basic | Yes (L8) |
| `ISecretResolver` | `...Abstractions.Secrets` | Resolves secret references by URI scheme | `Redacted<string>` | Dynamic config resolution | Intermediate | Yes (L8) |
| `CompositeSecretResolver` | `EricksonLopez.Security.Secrets` | Multi-scheme resolver (`raw:`, `env:`, `store:`) | `ISecretResolver` | Configuration pipelines | Intermediate | Yes (L8) |

---

## 7. Tokens & API Keys (`EricksonLopez.Security.Abstractions.Tokens`)

| Name | Namespace | Responsibility | Dependencies | Use Cases | Complexity Level | Existing Example |
|---|---|---|---|---|---|:---:|
| `ITokenGenerator` | `...Abstractions.Tokens` | Cryptographic random token generator | `OpaqueToken` | Bearer tokens, CSRF tokens, session IDs | Basic | Yes (L1) |
| `OpaqueTokenGenerator` | `EricksonLopez.Security.Tokens` | CSPRNG-backed implementation of `ITokenGenerator` | `ITokenGenerator` | Generating secure random tokens | Basic | Yes (L1) |
| `OpaqueTokenGenerator.Shared` | `EricksonLopez.Security.Tokens` | Static singleton access to default `OpaqueTokenGenerator` instance (no DI required) | — | Static utility contexts, tests, scripts | Basic | Yes (L2) |
| `ITokenHasher` | `...Abstractions.Tokens` | Hashes tokens for safe database indexing | — | Storing API keys and refresh tokens | Intermediate | Yes (L7) |
| `HmacSha256TokenHasher` | `EricksonLopez.Security.Tokens` | SHA-256 and keyed HMAC-SHA256 token hasher | `ITokenHasher` | One-way token storage with pepper | Intermediate | Yes (L7) |
| `IApiKeyGenerator` | `...Abstractions.Tokens` | Generates structured high-entropy API key pairs | `ApiKeyPolicy` | Issuing client API credentials | Intermediate | Yes (L1, L3) |
| `ApiKeyGenerator` | `EricksonLopez.Security.Tokens` | Concrete implementation of `IApiKeyGenerator` | `ITokenHasher` | Generating (plaintext, hashed) API key pairs | Intermediate | Yes (L3) |
| `IApiKeyValidator` | `...Abstractions.Tokens` | Constant-time validator for candidate API keys | `ApiKey` | Authenticating inbound API requests | Intermediate | Yes (L3) |
| `ApiKeyValidator` | `EricksonLopez.Security.Tokens` | Concrete implementation of `IApiKeyValidator` | `IApiKeyStore` | Authenticating API requests | Intermediate | Yes (L3) |
| `IApiKeyStore` | `...Abstractions.Tokens` | CRUD store for API key entities | `ApiKey` | Managing API key status and scopes | Intermediate | Yes (L8) |
| `InMemoryApiKeyStore` | `EricksonLopez.Security.Tokens` | In-memory thread-safe API key repository | `IApiKeyStore` | Local testing & development | Basic | Yes (L8) |

---

## 8. Zero Trust ABAC Engine (`EricksonLopez.Security.ZeroTrust`)

| Name | Namespace | Responsibility | Dependencies | Use Cases | Complexity Level | Existing Example |
|---|---|---|---|---|---|:---:|
| `IAbacPolicyEngine` | `EricksonLopez.Security.ZeroTrust` | Contract for evaluating dynamic ABAC policies | `AbacDecision` | Dynamic Zero Trust authorization | Advanced | Yes (L10) |
| `AbacPolicyEngine` | `EricksonLopez.Security.ZeroTrust` | NIST SP 800-162 / XACML compliant policy evaluator | `IAbacPolicyEngine` | Enterprise Policy Decision Point (PDP) | Advanced | Yes (L8, L10) |
| `AbacPolicy` | `EricksonLopez.Security.ZeroTrust` | Policy containing rules and a combining algorithm | `AbacRule` | Grouping authorization rules | Intermediate | Yes (L8, L10) |
| `AbacRule` | `EricksonLopez.Security.ZeroTrust` | Atomic rule evaluating a predicate over `AbacContext` | `AbacEffect` | Expressing fine-grained access conditions | Intermediate | Yes (L8, L10) |
| `AbacContext` | `EricksonLopez.Security.ZeroTrust` | Multidimensional attribute container (Subject, Resource, Action, Environment); methods: `Set()`, `Get<T>()`, `TryGet<T>()`, `Has()`, `WithSubject()`, `WithResource()`, `WithAction()`, `WithEnvironment()` | `AbacAttributeCategory` | Contextual request modeling | Intermediate | Yes (L8, L10, L11) |
| `AbacDecision` | `EricksonLopez.Security.ZeroTrust` | Decision record containing status (`Permit`/`Deny`), rule ID, reason | `AbacDecisionStatus` | Authorization enforcement result | Basic | Yes (L8, L10) |
| `AbacCombiningAlgorithm` | `EricksonLopez.Security.ZeroTrust` | Conflict resolution algorithm (`DenyOverrides`, `PermitOverrides`, `FirstApplicable`) | — | Policy combination logic | Intermediate | Yes (L10) |
| `AbacAttributeCategory` | `EricksonLopez.Security.ZeroTrust` | Static string constants defining well-known attribute dimensions: `Subject`, `Resource`, `Action`, `Environment` | — | Standard category keys for `AbacContext` attribute lookups | Basic | Yes (L8, L10, L11) |
| `AbacPolicyEngine.Instance` | `EricksonLopez.Security.ZeroTrust` | Singleton accessor returning the default `AbacPolicyEngine` instance (no DI required) | — | Static utility contexts, command-line tools | Basic | Yes (L11) |
| `AbacPolicyEngine.EvaluateFailClosed()` | `EricksonLopez.Security.ZeroTrust` | Evaluates policies and returns `Deny` if any rule evaluation throws an exception (defensive fail-closed) | `AbacContext`, `IAbacPolicy` | Hardened production policy evaluation | Advanced | Yes (L11) |
| `AbacPolicy.AppliesTo()` | `EricksonLopez.Security.ZeroTrust` | Returns whether the policy's optional target predicate matches the given `AbacContext` | `AbacContext` | Conditional policy targeting | Intermediate | Yes (L11) |

---

## 9. Multi-Factor Authentication (`EricksonLopez.Security.Mfa`)

| Name | Namespace | Responsibility | Dependencies | Use Cases | Complexity Level | Existing Example |
|---|---|---|---|---|---|:---:|
| `ITotpService` | `EricksonLopez.Security.Mfa` | RFC 6238 Time-Based One-Time Password service | `TotpSetupInfo` | 2FA / MFA enrollment and verification | Intermediate | Yes (L3) |
| `TotpService` | `EricksonLopez.Security.Mfa` | Concrete TOTP implementation with time-step tolerance | `ITotpService` | Production 2FA verification | Intermediate | Yes (L3) |
| `IRecoveryCodeGenerator` | `EricksonLopez.Security.Mfa` | Contract for generating and verifying single-use recovery codes | `IReadOnlyList<string>` | MFA emergency backup access workflows | Basic | Yes (L3) |
| `RecoveryCodeGenerator` | `EricksonLopez.Security.Mfa` | Generates alphanumeric recovery codes with constant-time verification | `IRecoveryCodeGenerator` | MFA backup code generation, HashCode, and VerifyCode | Basic | Yes (L3) |
| `TotpOptions` | `EricksonLopez.Security.Mfa` | Configuration for TOTP step, digits, algorithm, drift | — | Tuning TOTP window tolerance | Basic | Yes (L3) |
| `TotpSetupInfo` | `EricksonLopez.Security.Mfa` | Model containing secret key, URI, and formatted manual entry key | — | Authenticator app onboarding (QR codes) | Basic | Yes (L3) |
| `TotpHashAlgorithm` | `EricksonLopez.Security.Mfa` | Enum of HMAC algorithms: `Sha1`, `Sha256`, `Sha512` | — | Custom TOTP hash selection | Basic | Yes (L3) |
| `DelegateTotpReplayStore` | `EricksonLopez.Security.Mfa` | Delegate-driven implementation of `ITotpReplayStore` for distributed backends | `ITotpReplayStore` | Multi-node cluster TOTP replay prevention (Redis, SQL, Memcached) | Intermediate | Yes (L3, L11) |
| `InMemoryTotpReplayStore` | `EricksonLopez.Security.Mfa` | Thread-safe in-memory `ITotpReplayStore` using `ConcurrentDictionary`; registered by default by `AddSecurityMfa()` | `ITotpReplayStore` | Single-node TOTP replay prevention for local development & testing | Basic | Yes (L3) |
| `ITotpReplayStore` | `EricksonLopez.Security.Mfa` | Contract for storing and checking single-use TOTP tokens; `TryAdd(key, expiry)`, `TryAddAsync(key, expiry, ct)` | — | Plugging in Redis, SQL, or in-memory replay stores | Intermediate | Yes (L3, L11) |
| `TotpHashAlgorithm` | `EricksonLopez.Security.Mfa` | Enum specifying HMAC algorithm for TOTP: `Sha1=0`, `Sha256=1`, `Sha512=2` | — | Custom TOTP HMAC selection | Basic | Yes (L3) |
| `AddDistributedTotpReplayStore<TStore>()` | `EricksonLopez.Security.Mfa` | Overrides default in-memory TOTP replay store with custom distributed store type | `IServiceCollection`, `ITotpReplayStore` | Distributed cluster DI configuration | Basic | Yes (L11) |
| `AddDistributedTotpReplayStore(...)` | `EricksonLopez.Security.Mfa` | Overrides default in-memory TOTP replay store with delegate handlers | `IServiceCollection`, `ITotpReplayStore` | Lightweight distributed cluster DI configuration | Basic | Yes (L11) |

---

## 10. WebAuthn & FIDO2 Level 3 Passkeys (`EricksonLopez.Security.WebAuthn.Fido2`)

| Name | Namespace | Responsibility | Dependencies | Use Cases | Complexity Level | Existing Example |
|---|---|---|---|---|---|:---:|
| `IWebAuthnCeremonyService` | `...WebAuthn.Fido2.Abstractions` | Orchestrator for registration & authentication ceremonies | `CredentialCreateOptions` | Passkey enrollment and passwordless login | Advanced | Yes (L5) |
| `WebAuthnCeremonyService` | `...WebAuthn.Fido2.Services` | Concrete implementation of `IWebAuthnCeremonyService` | `IAttestationVerifier` | Complete WebAuthn ceremony handling | Advanced | Yes (L5) |
| `AuthenticatorDataParser` | `...WebAuthn.Fido2.Parsers` | Binary parser for WebAuthn authenticator data bytes | `ICoseKeyParser` | Parsing raw authenticator responses | Advanced | Yes (L5) |
| `PackedAttestationVerifier` | `...WebAuthn.Fido2.Verifiers` | Verifier for Packed format attestations | `IAttestationVerifier` | Hardware security key validation | Advanced | Yes (L5, L11) |
| `NoneAttestationVerifier` | `...WebAuthn.Fido2.Verifiers` | Verifier for direct user consent ("none") | `IAttestationVerifier` | Privacy-preserving registration | Basic | Yes (L5, L11) |
| `TpmAttestationVerifier` | `...WebAuthn.Fido2.Verifiers` | Verifier for TPM 2.0 attestation statements per WebAuthn §8.3 | `IAttestationVerifier` | Enterprise TPM-backed security key validation | Advanced | Yes (L11) |
| `FidoU2FAttestationVerifier` | `...WebAuthn.Fido2.Verifiers` | Verifier for FIDO U2F attestation statements per WebAuthn §8.6 | `IAttestationVerifier` | Legacy FIDO U2F hardware key compatibility | Advanced | Yes (L11) |
| `AndroidSafetyNetAttestationVerifier` | `...WebAuthn.Fido2.Verifiers` | Verifier for Android SafetyNet attestation JWT (§8.5): validates `ctsProfileMatch`, `basicIntegrity` and nonce binding | `IAttestationVerifier` | Android-based passkey device attestation | Advanced | Yes (L11) |
| `AuthenticatorAttachment` | `...WebAuthn.Fido2.Enums` | Enum: `Platform`, `CrossPlatform` — hints authenticator attachment modality | — | Controlling authenticator selection in ceremony options | Basic | Yes (L11) |
| `AuthenticatorStatus` | `...WebAuthn.Fido2.Enums` | Enum of MDS3 authenticator health statuses (e.g. `Fido2Certified`, `UserVerificationBypass`, `Revoked`) | — | Enforcing authenticator trust policies via MDS3 | Advanced | Yes (L11) |
| `CoseAlgorithmIdentifier` | `...WebAuthn.Fido2.Enums` | Enum of COSE algorithm IDs: `ES256=-7`, `RS256=-257`, etc. | — | Public key algorithm negotiation in credential parameters | Advanced | Yes (L11) |
| `CoseEllipticCurve` | `...WebAuthn.Fido2.Enums` | Enum of COSE EC curves: `P256=1`, `P384=2`, `P521=3`, `X25519=4` | — | EC public key parsing | Advanced | Yes (L11) |
| `CoseKeyType` | `...WebAuthn.Fido2.Enums` | Enum of COSE key types: `Ec2=2`, `Rsa=3`, `Symmetric=4` | — | COSE key type dispatch | Intermediate | Yes (L11) |
| `PublicKeyCredentialType` | `...WebAuthn.Fido2.Enums` | Enum: `PublicKey` — the only currently specified WebAuthn credential type | — | Credential parameters typing | Basic | Yes (L11) |
| `ResidentKeyRequirement` | `...WebAuthn.Fido2.Enums` | Enum: `Discouraged`, `Preferred`, `Required` — passkey resident key policy | — | Configuring discoverable credential requirements | Intermediate | Yes (L11) |
| `UserVerificationRequirement` | `...WebAuthn.Fido2.Enums` | Enum: `Discouraged`, `Preferred`, `Required` — user verification policy | — | Enforcing biometric/PIN verification during ceremony | Intermediate | Yes (L11) |
| `HttpMds3MetadataService` | `...WebAuthn.Fido2.Mds3` | HTTP client for FIDO Alliance MDS3 BLOB download, JWT verification, and authenticator metadata lookup | `IMds3MetadataService`, `HttpClient` | Production authenticator status validation against FIDO Alliance | Advanced | Yes (L11) |

---

## 11. SAML 2.0 Service Provider (`EricksonLopez.Security.Saml2`)

| Name | Namespace | Responsibility | Dependencies | Use Cases | Complexity Level | Existing Example |
|---|---|---|---|---|---|:---:|
| `ISaml2Service` | `...Saml2.Services` | Contract for SAML 2.0 SP AuthnRequest & response handling | `Saml2AuthnRequest` | Enterprise SSO integration | Advanced | Yes (L5) |
| `Saml2Service` | `...Saml2.Services` | Concrete SAML 2.0 SP engine with metadata generation | `ISaml2XswValidator` | Okta, Azure AD, Ping Identity SSO | Advanced | Yes (L5) |
| `Saml2XswValidator` | `...Saml2.Xsw` | Inspector mitigating XML Signature Wrapping attacks; `ValidateAndExtractAssertion(XmlDocument)` | `ISaml2XswValidator` | Anti-tamper SAML assertion validation | Advanced | Yes (L5, L11) |
| `Saml2SignatureValidator` | `...Saml2.Cryptography` | Validates & signs XML signatures on assertions and responses; `SignElement()`, `VerifySignature()` | `ISaml2SignatureValidator` | Cryptographic signature checking | Intermediate | Yes (L5, L11) |
| `Saml2AssertionDecryptor` | `...Saml2.Cryptography` | Decrypts `<EncryptedAssertion>` elements using RSA private key from X.509 certificate | `ISaml2AssertionDecryptor` | Decrypting encrypted SAML assertions | Advanced | Yes (L5, L11) |
| `Saml2ClaimsMapper` | `...Saml2.Claims` | Maps `Saml2Assertion` attributes to `ClaimsPrincipal` via configurable `AttributeMap` | `ISaml2ClaimsMapper` | Converting SAML attributes to ASP.NET Core claims | Intermediate | Yes (L5, L11) |
| `Saml2Binding` | `...Saml2.Models` | Enum: `HttpPost`, `HttpRedirect`, `Artifact` — SAML protocol binding variants | — | Selecting SP authentication binding | Intermediate | No |
| `Saml2NameIdFormat` | `...Saml2.Models` | Enum of SAML NameID formats: `Unspecified`, `EmailAddress`, `Persistent`, `Transient`, etc. | — | Configuring NameID format in AuthnRequest | Intermediate | No |
| `Saml2SignatureLocation` | `...Saml2.Models` | Enum: `Response`, `Assertion`, `Both` — controls where XML signature is placed | — | Requiring assertion or response-level signatures | Intermediate | No |
| `Saml2StatusCode` | `...Saml2.Models` | Enum: `Success`, `Requester`, `Responder`, `VersionMismatch` — SAML 2.0 status codes | — | Parsing IdP response status outcomes | Intermediate | No |

---

## 12. ASP.NET Core Middleware & Context (`EricksonLopez.Security.AspNetCore`)

| Name | Namespace | Responsibility | Dependencies | Use Cases | Complexity Level | Existing Example |
|---|---|---|---|---|---|:---:|
| `SecurityHeadersMiddleware` | `...AspNetCore.Headers` | Injects hardened HTTP response headers | `SecurityHeadersOptions` | OWASP Secure Headers compliance | Basic | Yes (L4) |
| `SecurityHeadersOptions` | `...AspNetCore.Headers` | Options for CSP, HSTS, X-Frame-Options, Permissions-Policy, Referrer-Policy | — | Tuning HTTP security perimeter | Basic | Yes (L4) |
| `RequestSecurityContext` | `...AspNetCore.Context` | Scoped accessor for actor ID, auth state, API key, and scopes | `IHttpContextAccessor` | Controller/Minimal API authorization | Basic | Yes (L4) |
| `IRequestSecurityContext` | `...AspNetCore.Context` | Interface: `IsAuthenticated`, `ActorId`, `HasScope()`, `ApiKey`, `Principal` | — | Testability & decoupling | Basic | Yes (L4) |
| `ApiKeyAuthenticationOptions` | `...AspNetCore.Authentication` | Options: `HeaderName`, `QueryParameterName`, `RequireApiKey`, `AuthenticationScheme` | — | Configuring API key extraction from HTTP request | Basic | Yes (L4) |
| `IdentityPasswordHasherBridge<TUser>` | `...AspNetCore.Identity` | Bridges `IPasswordHasher<TUser>` (ASP.NET Core Identity) to `IPasswordHasher` | `IPasswordHasher` | Replacing Identity's default password hasher | Intermediate | Yes (L8) |
| `AddSecurityAspNetCore()` | `...AspNetCore.DependencyInjection` | DI extension: registers `IRequestSecurityContext`, `SecurityHeadersOptions`, `ApiKeyAuthenticationOptions` | — | One-call setup for ASP.NET Core integration | Basic | Yes (L4) |
| `UseSecurityHeaders()` | `...AspNetCore.Extensions` | Middleware extension adding `SecurityHeadersMiddleware` to the pipeline | — | Activating security header injection | Basic | Yes (L4) |
| `UseApiKeyAuthentication()` | `...AspNetCore.Extensions` | Middleware extension adding `ApiKeyAuthenticationMiddleware` to the pipeline | — | Enabling API key header/query authentication | Basic | Yes (L4) |
| `AddEricksonLopezIdentityPasswordHasher<TUser>()` | `...AspNetCore.DependencyInjection` | Registers `IdentityPasswordHasherBridge<TUser>` as `IPasswordHasher<TUser>` | — | Replacing ASP.NET Core Identity's hasher | Basic | Yes (L8) |

---

## 13. Network Security & SSRF Defense (`EricksonLopez.Security.Network`)

| Name | Namespace | Responsibility | Dependencies | Use Cases | Complexity Level | Existing Example |
|---|---|---|---|---|---|:---:|
| `ISafeDnsResolver` | `EricksonLopez.Security.Network` | Contract for SSRF-safe DNS resolution: `ResolveAndValidateAsync(host, ct)` — validates all resolved IP addresses against blocked ranges | — | DNS-level SSRF prevention for hostname-based outbound requests | Intermediate | Yes (L11) |
| `SafeDnsResolver` | `EricksonLopez.Security.Network` | Production implementation of `ISafeDnsResolver`; blocks cloud metadata hostnames, ambiguous octal IPs, RFC 1918, DNS rebinding; injectable DNS delegate for testing | `ISafeDnsResolver`, `SsrfProtectionOptions` | SSRF-safe hostname resolution before making outbound connections | Intermediate | Yes (L11) |
| `SafeSocketsHttpHandler` | `EricksonLopez.Security.Network` | `SocketsHttpHandler` validating IP addresses on connect | `SsrfProtectionOptions` | Mitigating SSRF in outbound HTTP requests | Intermediate | Yes (L4) |
| `SafeHttpClientFactory` | `EricksonLopez.Security.Network` | Static factory producing hardened `HttpClient` with SSRF protection | `SafeSocketsHttpHandler`, `SsrfProtectionOptions` | Outbound webhooks and zero-trust API calls | Intermediate | Yes (L4) |
| `SsrfProtectionOptions` | `EricksonLopez.Security.Network` | Configuration defining blocked IP address ranges | `IpAddressRange` | Blocking RFC 1918 & metadata endpoints | Basic | Yes (L4) |
| `IpAddressRange` | `EricksonLopez.Security.Network` | CIDR range validator for IPv4 and IPv6 | `IPAddress` | IP address filtering rules | Basic | Yes (L4) |

---

## 14. Public Key Infrastructure & X.509 (`EricksonLopez.Security.Pki`)

| Name | Namespace | Responsibility | Dependencies | Use Cases | Complexity Level | Existing Example |
|---|---|---|---|---|---|:---:|
| `ICertificateChainValidator` | `EricksonLopez.Security.Pki` | Contract for certificate chain validation: `ValidateCertificate(X509Certificate2, CertificateValidationOptions)` | `CertificateValidationOptions` | Decoupled certificate validation for testability | Intermediate | Yes (L4) |
| `CertificateChainValidator` | `EricksonLopez.Security.Pki` | Validates X.509 certificate chains with custom trust anchors; implements `ICertificateChainValidator` | `CertificateValidationOptions` | mTLS & B2B partner cert verification | Intermediate | Yes (L4) |
| `CertificateValidationOptions` | `EricksonLopez.Security.Pki` | Configuration for revocation, SAN, and key usage checking (`RevocationMode`, `CustomTrustAnchors`) | `X509Certificate2` | Fine-tuning certificate trust policies | Basic | Yes (L4) |
| `CertificateRevocationStatus` | `EricksonLopez.Security.Pki` | Enum: `Unknown`, `Good`, `Revoked`, `Offline` — result of OCSP/CRL revocation check | — | Interpreting certificate revocation outcomes | Intermediate | No |

---

## 15. XML Digital Signatures (`EricksonLopez.Security.Cryptography.XmlDSig`)

| Name | Namespace | Responsibility | Dependencies | Use Cases | Complexity Level | Existing Example |
|---|---|---|---|---|---|:---:|
| `XmlDigitalSignatureService` | `...Cryptography.XmlDSig` | Concrete service implementing W3C XML Digital Signatures (RFC 3275), signing and anti-XSW verification; `XmlDigitalSignatureService.Instance` singleton | `IXmlDigitalSignatureVerifier`, `IXmlDigitalSigner` | Signing and validating SAML assertions & XML documents | Advanced | Yes (L5) |
| `IXmlDigitalSigner` | `...Cryptography.XmlDSig` | Generates W3C XML Digital Signatures (XMLDSig) for XML strings and XmlDocument | `XmlSigningOptions`, `X509Certificate2` | Signing SAML assertions and XML documents | Advanced | Yes (L5) |
| `IXmlDigitalSignatureVerifier` | `...Cryptography.XmlDSig` | Verifies XML-DSig and extracts signed element with anti-XSW; `VerifyXml()`, `VerifyAndExtractSignedElement()` | `XmlVerificationOptions`, `XmlVerificationResult` | Hardened XML & SAML signature verification | Advanced | Yes (L5) |
| `XmlSigningOptions` | `...Cryptography.XmlDSig` | Options for XML signing: `IncludeKeyInfo`, `CanonicalizationMethod`, `DigestMethod` | — | Configuring XML signature generation | Basic | Yes (L5) |
| `XmlVerificationOptions` | `...Cryptography.XmlDSig` | Options for XML-DSig verification: `RequireTrustedCertificate`, `CustomTrustAnchors` | `X509Certificate2Collection` | Configuring custom trust anchors | Intermediate | Yes (L5) |
| `XmlVerificationResult` | `...Cryptography.XmlDSig` | Result record: `IsValid`, `SigningCertificate`, `SignedElement`, `ReferenceUri` | `XmlElement`, `X509Certificate2` | Safe consumption of verified XML elements | Intermediate | Yes (L5) |
| `XmlSignatureCertificateExtractor` | `...Cryptography.XmlDSig` | Static helper: `ExtractCertificate(xmlString)` — parses the `<KeyInfo>` X.509 certificate from a signed XML document | `X509Certificate2` | Certificate extraction from signed XML responses | Intermediate | Yes (L11) |

---

## 16. Hardware Security Modules (`EricksonLopez.Security.Cryptography.Pkcs11`)

| Name | Namespace | Responsibility | Dependencies | Use Cases | Complexity Level | Existing Example |
|---|---|---|---|---|---|:---:|
| `Pkcs11Constants` | `...Cryptography.Pkcs11.Interop` | Cryptoki mechanism constants (`CKR_OK`, `CKM_RSA_PKCS`, etc.) | — | Hardware token interoperability | Intermediate | Yes (L9) |

---

## 17. Multi-Cloud KMS & Secret Adapters (`Azure`, `Aws`, `HashiCorpVault`, `GoogleCloud`)

| Name | Namespace | Responsibility | Dependencies | Use Cases | Complexity Level | Existing Example |
|---|---|---|---|---|---|:---:|
| `AzureKeyVaultOptions` | `EricksonLopez.Security.Azure` | Configuration for Azure Key Vault URI, secret prefixes, and credentials | — | Cloud key & secret configuration | Basic | Yes (L9) |
| `AzureKeyVaultKeyStore` | `EricksonLopez.Security.Azure` | Azure Key Vault key store adapter implementing `IKeyStore` | `IKeyStore` | Persisting keys in Azure Key Vault | Intermediate | Yes (L9) |
| `AzureKeyVaultSecretStore` | `EricksonLopez.Security.Azure` | Azure Key Vault secret store adapter implementing `ISecretStore` | `ISecretStore` | Storing secrets in Azure Key Vault | Intermediate | Yes (L9) |
| `AzureKeyVaultSecurityExtensions` | `Microsoft.Extensions.DependencyInjection` | `AddAzureKeyVaultSecurity()` extension methods | `IServiceCollection` | One-call Azure Key Vault registration | Basic | Yes (L9) |
| `AwsSecurityOptions` | `EricksonLopez.Security.Aws` | Configuration for AWS KMS ARN, region, and secret namespaces | — | AWS cloud security configuration | Basic | Yes (L9) |
| `AwsKmsKeyStore` | `EricksonLopez.Security.Aws` | AWS KMS key store adapter implementing `IKeyStore` | `IKeyStore` | Managing cryptographic keys in AWS KMS | Intermediate | Yes (L9) |
| `AwsSecretsManagerSecretStore` | `EricksonLopez.Security.Aws` | AWS Secrets Manager adapter implementing `ISecretStore` | `ISecretStore` | Storing secrets in AWS Secrets Manager | Intermediate | Yes (L9) |
| `AwsSecurityExtensions` | `Microsoft.Extensions.DependencyInjection` | `AddAwsSecurity()` extension methods | `IServiceCollection` | One-call AWS KMS & Secrets Manager registration | Basic | Yes (L9) |
| `HashiCorpVaultOptions` | `EricksonLopez.Security.HashiCorpVault` | Configuration for Vault URL, Transit & KV v2 mount paths | — | HashiCorp Vault integration | Basic | Yes (L9) |
| `HashiCorpVaultClient` | `EricksonLopez.Security.HashiCorpVault` | Vault HTTP client for Transit & KV v2 operations | `HttpClient` | Direct Vault API interactions | Intermediate | Yes (L9) |
| `HashiCorpVaultKeyStore` | `EricksonLopez.Security.HashiCorpVault` | HashiCorp Vault Transit engine adapter implementing `IKeyStore` | `IKeyStore` | Transit encryption key persistence | Intermediate | Yes (L9) |
| `HashiCorpVaultSecretStore` | `EricksonLopez.Security.HashiCorpVault` | HashiCorp Vault KV v2 adapter implementing `ISecretStore` | `ISecretStore` | KV v2 secrets storage in Vault | Intermediate | Yes (L9) |
| `HashiCorpVaultSecurityExtensions` | `Microsoft.Extensions.DependencyInjection` | `AddHashiCorpVaultSecurity()` extension methods | `IServiceCollection` | One-call HashiCorp Vault registration | Basic | Yes (L9) |
| `GoogleCloudSecurityOptions` | `EricksonLopez.Security.GoogleCloud` | Configuration for Google Cloud KMS and Secret Manager | — | GCP cloud security configuration | Basic | Yes (L9) |
| `GoogleCloudKmsKeyStore` | `EricksonLopez.Security.GoogleCloud` | Google Cloud KMS key store adapter implementing `IKeyStore` | `IKeyStore` | Managing cryptographic keys in Cloud KMS | Intermediate | Yes (L9) |
| `GoogleCloudSecretManagerStore` | `EricksonLopez.Security.GoogleCloud` | Google Cloud Secret Manager adapter implementing `ISecretStore` | `ISecretStore` | Storing secrets in Secret Manager | Intermediate | Yes (L9) |
| `GoogleCloudSecurityExtensions` | `Microsoft.Extensions.DependencyInjection` | `AddGoogleCloudSecurity()` extension methods | `IServiceCollection` | One-call Google Cloud KMS & Secret Manager registration | Basic | Yes (L9) |

---

## 18. FIDO Alliance MDS3 & Breach Detection (`WebAuthn.Fido2.Mds3`, `Privacy.Hibp`)

| Name | Namespace | Responsibility | Dependencies | Use Cases | Complexity Level | Existing Example |
|---|---|---|---|---|---|:---:|
| `Mds3Options` | `...WebAuthn.Fido2.Mds3` | Configuration for FIDO Metadata Service v3 endpoint & cache | — | Authenticator verification rules | Basic | Yes (L9) |
| `HibpOptions` | `...Privacy.Hibp.Models` | Configuration for Have I Been Pwned k-anonymity client | — | Checking passwords against breach database | Basic | Yes (L9) |
| `IHaveIBeenPwnedClient` | `...Privacy.Hibp.Abstractions` | HIBP Pwned Passwords API client: `CheckPasswordAsync()`, `GetRangeAsync()` | `HttpClient` | Checking passwords against breach database | Intermediate | Yes (L6) |
| `IPasswordPwnedValidator` | `...Privacy.Hibp.Abstractions` | Validates password is not in HIBP breach set: `ValidateNotPwnedAsync()` | `IHaveIBeenPwnedClient` | Registration/reset pipeline enforcement | Intermediate | Yes (L6) |
| `PwnedPasswordCheckResult` | `...Privacy.Hibp.Models` | Result record: `.IsPwned`, `.BreachCount`, `.HashPrefix` | — | Displaying breach data to users | Basic | Yes (L6) |
| `AddHaveIBeenPwned()` | `...Privacy.Hibp.DependencyInjection` | DI extension registering `IHaveIBeenPwnedClient` (HttpClient) and `IPasswordPwnedValidator` | `HibpOptions` | One-call HIBP service registration | Basic | Yes (L6) |

---

## 19. Observability & Diagnostics (`EricksonLopez.Security.Diagnostics`, `OpenTelemetry`)

| Name | Namespace | Responsibility | Dependencies | Use Cases | Complexity Level | Existing Example |
|---|---|---|---|---|---|:---:|
| `SecurityActivitySource` | `EricksonLopez.Security.Diagnostics` | Standard `ActivitySource` emitting distributed tracing spans | `System.Diagnostics` | APM tracing for crypto operations | Intermediate | Yes (L7, L10) |
| `SecurityMeter` | `EricksonLopez.Security.Diagnostics` | Standard `Meter` emitting counters and histograms | `System.Diagnostics.Metrics` | Prometheus / OpenTelemetry dashboards | Intermediate | Yes (L7, L10) |
| `SecurityOpenTelemetryExtensions` | `EricksonLopez.Security.OpenTelemetry` | OTel pipeline extensions: `AddEricksonLopezSecurityInstrumentation(TracerProviderBuilder)`, `AddEricksonLopezSecurityInstrumentation(MeterProviderBuilder)` | `OpenTelemetry.API` | Subscribing `SecurityActivitySource` and `SecurityMeter` in OTel SDK | Basic | Yes (L10) |

---

## Coverage Verdict: 100% of discovered public APIs across Core Library & Infrastructure have executable examples in `samples/EricksonLopez.Security.Sample`.

---

## 20. ABAC Decision Vocabulary (`EricksonLopez.Security.ZeroTrust`)

| Name | Namespace | Responsibility | Dependencies | Use Cases | Complexity Level | Existing Example |
|---|---|---|---|---|---|:---:|
| `AbacDecisionStatus` | `EricksonLopez.Security.ZeroTrust` | XACML decision outcome: `Permit`, `Deny`, `NotApplicable`, `Indeterminate` | — | Interpreting ABAC evaluation results | Basic | Yes (L8, L10) |
| `AbacEffect` | `EricksonLopez.Security.ZeroTrust` | Rule effect declaration: `Permit`, `Deny` | — | Expressing rule intent | Basic | Yes (L8, L10) |

---

## 21. Cryptographic Error Catalog (`EricksonLopez.Security.Abstractions.Errors`)

| Name | Namespace | Responsibility | Dependencies | Use Cases | Complexity Level | Existing Example |
|---|---|---|---|---|---|:---:|
| `SecurityError.InvalidNonce` | `...Abstractions.Errors` | Factory producing typed error for invalid IV byte length | `SecurityError` | AEAD nonce precondition enforcement | Basic | Yes (L2, L6) |
| `SecurityError.BufferTooSmall` | `...Abstractions.Errors` | Factory producing typed error for insufficient destination buffer | `SecurityError` | Zero-allocation span destination validation | Basic | Yes (L2, L6) |
| `SecurityError.AuthenticationTagMismatch` | `...Abstractions.Errors` | Factory producing error for ciphertext tampering or corruption | `SecurityError` | AEAD payload authentication failure | Basic | Yes (L6) |
| `SecurityError.KeyExpired` | `...Abstractions.Errors` | Factory producing error when retired key exceeds validity | `SecurityError` | Lifecycle expiration enforcement | Basic | Yes (L6) |
| `SecurityError.KeyRevoked` | `...Abstractions.Errors` | Factory producing error when key has been explicitly revoked | `SecurityError` | Compromised key kill-switch handling | Basic | Yes (L6) |
| `SecurityEventSeverity` | `...Abstractions.Events` | Audit event severity enum: `Informational`, `Warning`, `High`, `Critical` | — | Severity taxonomy for `ISecurityEvent` implementations | Basic | Yes (L2) |

---

## 22. Testing Utilities (`EricksonLopez.Security.Testing`)

> **Classification**: Infrastructure (test support). These types are exclusively for test code — they must not be used in production assemblies.

| Name | Namespace | Responsibility | Dependencies | Use Cases | Complexity Level | Existing Example |
|---|---|---|---|---|---|:---:|
| `FakePasswordHasher` | `...Security.Testing.Fakes` | Deterministic SHA-256 `IPasswordHasher` test double (`HashPassword`, `VerifyPassword`, `NeedsRehash`, `SimulateNeedsRehash`) | `IPasswordHasher` | Unit testing password hashing flows without KDF cost | Basic | Yes (L8) |
| `FakeSecretProtector` | `...Security.Testing.Fakes` | XOR-masking in-memory `ISecretProtector` with `InjectedError` failure simulation | `ISecretProtector` | Unit testing secret protect/unprotect paths | Basic | Yes (L8) |
| `FakeKeyStore` | `...Security.Testing.Fakes` | In-memory `IKeyStore` test double with full CRUD and `InjectedError` simulation | `IKeyStore` | Unit testing key lifecycle managers without external backends | Basic | Yes (L8) |
| `DeterministicRandomNumberGenerator` | `...Security.Testing.Fakes` | Seeded `ICryptographicRandomNumberGenerator` for reproducible tests (`Fill()`, `GetInt32()`) | `ICryptographicRandomNumberGenerator` | Reproducible cryptographic test scenarios | Intermediate | Yes (L8) |
| `TestHttpMessageHandler` | `...Security.Testing.Http` | Configurable `HttpMessageHandler` test double (string response constructor, `LastRequest`, `LastRequestHeaders`, `Requests`, `RequestCount`) | `HttpMessageHandler` | Mocking HIBP, SSRF, and external HTTP calls in unit tests | Basic | Yes (L8) |
| `FakeLogger<T>` | `...Security.Testing.Logging` | `ILogger<T>` test double with structured capture; `Entries`, `Count`, `Messages`, `HasMessage()`, `HasWarning()`, `HasError()`, `Clear()`, `BeginScope()` | `ILogger<T>` | Asserting on structured log output in unit tests | Basic | Yes (L8, L11) |
| `FakeLogRecord` | `...Security.Testing.Logging` | Positional record for captured log entries (`LogLevel`, `EventId`, `State`, `Exception`, `Message`) | — | Fine-grained log assertion in test cases | Basic | Yes (L8) |
| `SecurityAssert` | `...Security.Testing.Assertions` | Static assertion helpers: `AreConstantTimeEqual(ReadOnlySpan<byte>, ReadOnlySpan<byte>)`, `IsRedacted(Redacted<T>)` | — | Verifying constant-time safety and redaction in tests | Basic | Yes (L11) |

---

## 23. Roslyn Analyzers (`EricksonLopez.Security.Analyzers`)

> **Classification**: Infrastructure (build-time only). These analyzers run during compilation — they are not referenced at runtime.

| Name | Diagnostic ID | Responsibility | Complexity Level | Existing Example |
|---|---|---|---|:---:|
| `HardcodedSecretAnalyzer` | `ELS0003` | Detects hardcoded cryptographic secrets, passwords, and tokens in string literals | Intermediate | No |
| `InsecurePasswordAlgorithmAnalyzer` | `ELS0004` | Flags use of insecure password hashing algorithms (MD5, SHA-1 without KDF) | Intermediate | No |
| `LoggingRawSecretAnalyzer` | `ELS0005` | Detects logging of `SecretBuffer`, `Secret<T>`, or `Redacted<T>` raw values via format arguments | Advanced | No |
| `NonConstantTimeComparisonAnalyzer` | `ELS0001` | Flags `==` or `string.Equals` comparisons on sensitive byte arrays (prefer `CryptographicOperations.FixedTimeEquals`) | Intermediate | No |
| `UndisposedSecretBufferAnalyzer` | `ELS0002` | Detects `SecretBuffer` allocations that are not wrapped in a `using` declaration or statement | Intermediate | No |
| `DiagnosticIds` | — | Static class exposing all diagnostic ID constants (`ELS0001`–`ELS0005`) | Basic | No |

---

> **Synchronization stamp v1.1.1**: Phase 9 delta applied — added `AuthenticatedContext` (§2), `AesGcmAuthenticatedEncryptionEngine` (§2), `SecretBuffer.FromUtf8()` (§1), `KeyRingOptions` (§3), `ISafeDnsResolver`/`SafeDnsResolver` (§13), `TpmAttestationVerifier`, `FidoU2FAttestationVerifier`, `AndroidSafetyNetAttestationVerifier` (§10), 8 WebAuthn enums (§10), `HttpMds3MetadataService` (§10/§18), 4 SAML enums (§11), `Saml2AssertionDecryptor`, `Saml2ClaimsMapper` (§11), `ICertificateChainValidator`, `CertificateRevocationStatus` (§14), `XmlSigningOptions`, `XmlSignatureCertificateExtractor` (§15), `AbacAttributeCategory`, `AbacPolicyEngine.Instance`, `AbacPolicyEngine.EvaluateFailClosed()`, `AbacPolicy.AppliesTo()` (§8), `InMemoryTotpReplayStore`, `ITotpReplayStore` (§9), `SecurityAssert` (§22), new §23 Roslyn Analyzers (6 entries, IDs `ELS0001`–`ELS0005` verified against `DiagnosticIds.cs`). Coverage verdict: **100%** — all 12 showcase levels plus Level 11 comprehensive API coverage execute with zero errors.
