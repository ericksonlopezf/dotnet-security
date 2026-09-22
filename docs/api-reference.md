# Public API Reference — EricksonLopez.Security

> **Root Namespace**: `EricksonLopez.Security.*`  
> **Target Frameworks**: .NET 8.0, .NET 9.0, .NET 10.0  
> **Documentation Style**: Official Microsoft Learn Format.

---

## Module Index

- [1. Domain Primitives & Value Objects (`EricksonLopez.Security.Abstractions.Primitives`)](#1-domain-primitives--value-objects)
- [2. Secrets & Envelopes (`EricksonLopez.Security.Abstractions.Secrets`)](#2-secrets--envelopes)
- [3. Cryptographic Engines (`EricksonLopez.Security.Abstractions.Cryptography`)](#3-cryptographic-engines)
- [4. Key Lifecycle Management (`EricksonLopez.Security.Abstractions.KeyManagement`)](#4-key-lifecycle-management)
- [5. Passwords & Policies (`EricksonLopez.Security.Abstractions.Passwords`)](#5-passwords--policies)
- [6. Tokens & API Keys (`EricksonLopez.Security.Abstractions.Tokens`)](#6-tokens--api-keys)
- [7. Error Catalog (`EricksonLopez.Security.Abstractions.Errors`)](#7-error-catalog)
- [8. Zero Trust & ABAC (`EricksonLopez.Security.ZeroTrust`)](#8-zero-trust--abac)
- [9. WebAuthn & Passkeys (`EricksonLopez.Security.WebAuthn.Fido2`)](#9-webauthn--passkeys)
- [10. SAML 2.0 Service Provider (`EricksonLopez.Security.Saml2`)](#10-saml-20-service-provider)
- [11. Network SSRF Prevention (`EricksonLopez.Security.Network`)](#11-network-ssrf-prevention)
- [12. Diagnostics & OpenTelemetry (`EricksonLopez.Security.OpenTelemetry`)](#12-diagnostics--opentelemetry)
- [13. Multi-Factor Authentication (`EricksonLopez.Security.Mfa`)](#13-multi-factor-authentication)
- [14. FIDO Alliance MDS3 Client (`EricksonLopez.Security.WebAuthn.Fido2.Mds3`)](#14-fido-alliance-mds3-client)
- [15. Public Key Infrastructure & X.509 (`EricksonLopez.Security.Pki`)](#15-public-key-infrastructure--x509)
- [16. Breach Detection Client (`EricksonLopez.Security.Privacy.Hibp`)](#16-breach-detection-client)
- [17. XML Digital Signatures (`EricksonLopez.Security.Cryptography.XmlDSig`)](#17-xml-digital-signatures)
- [18. Hardware Security Modules (`EricksonLopez.Security.Cryptography.Pkcs11`)](#18-hardware-security-modules)
- [19. ASP.NET Core Middleware & Context (`EricksonLopez.Security.AspNetCore`)](#19-aspnet-core-middleware--context)
- [20. Cloud KMS Adapters (`Azure`, `Aws`, `HashiCorpVault`, `GoogleCloud`)](#20-cloud-kms-adapters)
- [21. Testing Utilities & Static Analyzers (`Testing`, `Analyzers`)](#21-testing-utilities--static-analyzers)
- [22. Core Primitives Supplement](#22-core-primitives-supplement)
- [23. Enumerations](#23-enumerations)
- [24. Concrete Password Implementations](#24-concrete-password-implementations)
- [25. Token Security](#25-token-security)
- [26. API Key Store](#26-api-key-store)
- [27. Secret Resolution](#27-secret-resolution)
- [28. Diagnostics & Observability (Core)](#28-diagnostics--observability-core)
- [29. Memory Primitives — Concrete Implementations](#29-memory-primitives--concrete-implementations)

---

## 1. Domain Primitives & Value Objects

### `KeyIdentifier`
```csharp
namespace EricksonLopez.Security.Abstractions.Primitives;

public readonly record struct KeyIdentifier : IEquatable<KeyIdentifier>, IComparable<KeyIdentifier>
```
An immutable, strongly-typed domain primitive identifying cryptographic keys and secrets.

#### Constructors & Static Factories
- `public KeyIdentifier(string value)`: Initializes a new instance after verifying the input is non-null, non-empty, and within length bounds.
- `public static KeyIdentifier New()`: Generates a new unique 32-character hexadecimal identifier based on Guid ("N" format without hyphens).
- `public static KeyIdentifier Prefixed(string prefix)`: Generates a semantic prefixed identifier (e.g. `"key_sec-4fecdac2ba87e980abc123456789abcd"`).
- `public static bool TryCreate(string? value, out KeyIdentifier identifier)`: Safe factory returning `false` on invalid input without throwing exceptions.

---

### `KeyVersion`
```csharp
namespace EricksonLopez.Security.Abstractions.Primitives;

public readonly record struct KeyVersion : IEquatable<KeyVersion>, IComparable<KeyVersion>
```
Represents a strictly monotonic version number (starting at 1) for cryptographic keys.

#### Members
- `public static readonly KeyVersion Initial = new(1);`
- `public KeyVersion Next()`: Returns the incremented version.
- `public int Value { get; }`: The underlying sequential integer.

---

### `Redacted<T>`
```csharp
namespace EricksonLopez.Security.Abstractions.Primitives;

public readonly struct Redacted<T> : IEquatable<Redacted<T>>
```
A memory-safe wrapper for sensitive credentials preventing accidental exposure in log aggregators, APM traces, and exception messages.

#### Members
- `public T? UnsafeValue { get; }`: Exposes the sensitive inner value for authorized cryptographic operations.
- `public override string ToString()`: Returns constant `"[REDACTED]"`.

---

### `Nonce` & `Salt`
```csharp
namespace EricksonLopez.Security.Abstractions.Primitives;

public readonly struct Nonce : IEquatable<Nonce>
public readonly struct Salt : IEquatable<Salt>
```
Immutable fixed-length structures wrapping initialization vectors (`Nonce`, variable length, standard AES-GCM 12 bytes) and cryptographic salts (`Salt`, 16 bytes).

---

### `ISecretBuffer`
```csharp
namespace EricksonLopez.Security.Abstractions.Primitives;

public interface ISecretBuffer : IDisposable  // also inherits ISecret
{
    ReadOnlySpan<byte> Span { get; }        // stack-friendly span over the pinned buffer
    ReadOnlyMemory<byte> Memory { get; }    // heap-friendly memory handle for async scenarios
    int Length { get; }                     // number of bytes stored (inherited from ISecret)
    bool IsDisposed { get; }               // true after Dispose(); subsequent access throws ObjectDisposedException
}
```
Defines a rented or allocated memory buffer whose contents are deterministically overwritten with zeros (`CryptographicOperations.ZeroMemory`) upon `Dispose()`.

---

### `KeyMetadata`
```csharp
namespace EricksonLopez.Security.Abstractions.Primitives;

public sealed record KeyMetadata(
    KeyIdentifier KeyId,
    KeyVersion Version,
    KeyPurpose Purpose,
    KeyStatus Status,
    string AlgorithmId,
    DateTimeOffset CreatedAtUtc,
    DateTimeOffset? ExpiresAtUtc = null,
    DateTimeOffset? RevokedAtUtc = null);
```
Represents immutable metadata describing a cryptographic key, its lifecycle state, and cryptographic algorithm bindings.

#### Methods
- `public bool IsUsableForNewOperations(DateTimeOffset? nowUtc = null)`: Returns `true` if the key status is `Active` and within its valid time window.
- `public bool IsUsableForDecryption()`: Returns `true` if the key status is `Active` or `Retired`.

---

## 2. Secrets & Envelopes

### `ISecretProtector`
```csharp
namespace EricksonLopez.Security.Abstractions.Secrets;

public interface ISecretProtector
{
    // Async overloads — prefer these in ASP.NET Core and async contexts
    ValueTask<Result<byte[]>> ProtectAsync(
        ReadOnlyMemory<byte> secret,
        KeyPurpose purpose = KeyPurpose.SecretProtection,
        AuthenticatedContext expectedAssociatedData = default,
        CancellationToken cancellationToken = default);

    ValueTask<Result<byte[]>> UnprotectAsync(
        ReadOnlyMemory<byte> protectedData,
        AuthenticatedContext expectedAssociatedData = default,
        CancellationToken cancellationToken = default);

    ValueTask<Result<ISecretBuffer>> UnprotectToSecretBufferAsync(
        ReadOnlyMemory<byte> protectedData,
        AuthenticatedContext expectedAssociatedData = default,
        CancellationToken cancellationToken = default);

    // Synchronous span overloads — zero-allocation; prefer for high-throughput hotpaths
    Result<byte[]> Protect(
        ReadOnlySpan<byte> secret,
        KeyPurpose purpose = KeyPurpose.SecretProtection,
        AuthenticatedContext expectedAssociatedData = default);

    Result<byte[]> Unprotect(
        ReadOnlySpan<byte> protectedData,
        AuthenticatedContext expectedAssociatedData = default);
}
```
High-level facade providing single-pass envelope protection, key resolution, authenticated associated data (AAD) tenant isolation, and synchronous span overloads. The `AuthenticatedContext` struct is constructed via `AuthenticatedContext.ForTenant(tenantId)` or `AuthenticatedContext.FromBytes(ReadOnlySpan<byte>)`.

> **Note on `AuthenticatedContext`**: This is a strongly-typed struct in `EricksonLopez.Security.Abstractions.Cryptography` namespace. Passing raw `byte[]` directly will result in a compile-time error (`CS1503`). Always use the factory methods `ForTenant()` or `FromBytes()` to construct the context.

> **Note on Synchronous Overloads (`Protect` / `Unprotect`)**: The synchronous `Protect(ReadOnlySpan<byte>)` and `Unprotect(ReadOnlySpan<byte>)` overloads resolve the key synchronously from `IKeyRing` when the provider implements it (zero-overhead path). When the provider is a non-`IKeyRing` async-only source, a blocking `.GetAwaiter().GetResult()` fallback is used — avoid this in ASP.NET Core request pipelines to prevent potential thread-pool starvation. Always prefer `ProtectAsync` / `UnprotectAsync` when running under an async context.

---

## 3. Cryptographic Engines

### `IAuthenticatedEncryptionEngine`
```csharp
namespace EricksonLopez.Security.Abstractions.Cryptography;

public interface IAuthenticatedEncryptionEngine
{
    AeadAlgorithm Algorithm { get; }
    int KeySizeBytes { get; }    // e.g. 32 for AES-256
    int NonceSizeBytes { get; }  // e.g. 12 (96-bit)
    int TagSizeBytes { get; }    // e.g. 16 (128-bit)

    // Convenience allocating overload — generates a fresh random nonce internally
    Result<EncryptedData> Encrypt(
        ReadOnlySpan<byte> plaintext,
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> associatedData = default);

    // Zero-allocation overload — caller supplies nonce and output buffers
    Result Encrypt(
        ReadOnlySpan<byte> plaintext,
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> nonce,
        Span<byte> ciphertextDestination,
        Span<byte> tagDestination,
        ReadOnlySpan<byte> associatedData = default);

    Result Decrypt(
        ReadOnlySpan<byte> ciphertext,
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> tag,
        ReadOnlySpan<byte> associatedData,
        Span<byte> plaintextDestination,
        out int bytesWritten);
}
```

### `HkdfAesGcmEncryptionEngine`
```csharp
namespace EricksonLopez.Security.Cryptography;

public sealed class HkdfAesGcmEncryptionEngine : IAuthenticatedEncryptionEngine
{
    public static HkdfAesGcmEncryptionEngine Shared { get; }
    public AeadAlgorithm Algorithm => AeadAlgorithm.HkdfAes256Gcm;
    // Derives per-message subkey via HKDF-SHA256 before executing AES-256-GCM
}
```

---

## 4. Key Lifecycle Management

### `IKeyLifecycleManager`
```csharp
namespace EricksonLopez.Security.Abstractions.KeyManagement;

public interface IKeyLifecycleManager
{
    ValueTask<Result<CryptographicKey>> GenerateAndActivateKeyAsync(
        KeyPurpose purpose,
        string algorithmId = "AES-256-GCM",
        TimeSpan? validityPeriod = null,
        CancellationToken cancellationToken = default);

    ValueTask<Result<CryptographicKey>> RotateKeyAsync(
        KeyPurpose purpose,
        TimeSpan? validityPeriod = null,
        CancellationToken cancellationToken = default);

    ValueTask<Result> RevokeKeyAsync(
        KeyIdentifier keyId,
        KeyVersion version,
        string reason,
        CancellationToken cancellationToken = default);
}
```

### `IKeyRing`
```csharp
namespace EricksonLopez.Security.Abstractions.KeyManagement;

public interface IKeyRing
{
    Result<CryptographicKey> GetActiveKey(KeyPurpose purpose);
    Result<CryptographicKey> GetKey(KeyIdentifier keyId, KeyVersion version);
    ValueTask<Result<CryptographicKey>> GetActiveKeyAsync(KeyPurpose purpose, CancellationToken cancellationToken = default);
    ValueTask<Result<CryptographicKey>> GetKeyAsync(KeyIdentifier keyId, KeyVersion version, CancellationToken cancellationToken = default);
    ValueTask<Result<IReadOnlyList<KeyMetadata>>> ListMetadataAsync(KeyPurpose? purpose = null, CancellationToken cancellationToken = default);
    void InvalidateKey(KeyIdentifier keyId, KeyVersion version);
    void InvalidateActiveKey(KeyPurpose purpose);
    void InvalidateAll();
}
```
Thread-safe in-memory cache and resolver for active and historical keys across purpose boundaries.

### `KeyRingOptions`
```csharp
namespace EricksonLopez.Security.KeyManagement;

public sealed class KeyRingOptions
{
    public KeyRingOptions();
    public TimeSpan CacheTtl { get; set; } // Default: TimeSpan.FromSeconds(30)
}
```
Configuration for `KeyRing` instance-level caching. Controls how long decrypted key material is retained in memory after initial load.

| Property | Default | Description |
|---|---|---|
| `CacheTtl` | `TimeSpan.FromSeconds(30)` | Maximum time a key is cached in memory after retrieval from `IKeyStore`. Set to `TimeSpan.Zero` to disable caching (every operation fetches from store). |

> **Security**: Shorter `CacheTtl` minimizes the window of exposure for plaintext key material in memory dumps. Longer values reduce latency and `IKeyStore` read pressure in high-throughput services. Recommended: 30–300 seconds depending on your threat model.

#### When to Use
- When constructing `KeyRing` directly (outside of DI): `new KeyRing(store, new KeyRingOptions { CacheTtl = TimeSpan.FromMinutes(1) }, notifier)`.
- To disable caching entirely for air-gapped or HSM-backed key stores.

---


```csharp
namespace EricksonLopez.Security.Abstractions.KeyManagement;

public interface IKeyRevocationNotifier
{
    ValueTask NotifyRevokedAsync(KeyIdentifier keyId, KeyVersion version, KeyPurpose purpose, CancellationToken cancellationToken = default);
    IDisposable Subscribe(Action<KeyIdentifier, KeyVersion, KeyPurpose> handler);
}
```
Defines a contract for dispatching and receiving real-time key revocation signals across in-process key rings and distributed cluster nodes.

### `InProcessKeyRevocationNotifier`
```csharp
namespace EricksonLopez.Security.KeyManagement;

public sealed class InProcessKeyRevocationNotifier : IKeyRevocationNotifier
{
    public ValueTask NotifyRevokedAsync(KeyIdentifier keyId, KeyVersion version, KeyPurpose purpose, CancellationToken cancellationToken = default);
    public IDisposable Subscribe(Action<KeyIdentifier, KeyVersion, KeyPurpose> handler);
}
```
High-performance, thread-safe in-process implementation of `IKeyRevocationNotifier` dispatching revocation events with defensive subscriber exception isolation. Registered automatically via `services.AddKeyManagement()`.

### `DelegateKeyRevocationNotifier`
```csharp
namespace EricksonLopez.Security.KeyManagement;

public sealed class DelegateKeyRevocationNotifier : IKeyRevocationNotifier
{
    public DelegateKeyRevocationNotifier(Func<KeyIdentifier, KeyVersion, KeyPurpose, CancellationToken, ValueTask> publishHandler);
    public ValueTask NotifyRevokedAsync(KeyIdentifier keyId, KeyVersion version, KeyPurpose purpose, CancellationToken cancellationToken = default);
    public ValueTask ReceiveRemoteRevocationAsync(KeyIdentifier keyId, KeyVersion version, KeyPurpose purpose, CancellationToken cancellationToken = default);
    public IDisposable Subscribe(Action<KeyIdentifier, KeyVersion, KeyPurpose> handler);
}
```
Distributed adapter bridging local in-process `KeyRing` caches to external message brokers (e.g. Redis Pub/Sub, RabbitMQ, Kafka, Azure Service Bus). Ingests remote revocation notices via `ReceiveRemoteRevocationAsync` without re-broadcasting. Registered via `services.AddDistributedKeyRevocationNotifier(...)`.

---

## 5. Passwords & Policies

### `IPasswordHasher`
```csharp
namespace EricksonLopez.Security.Abstractions.Passwords;

public interface IPasswordHasher
{
    PasswordHashAlgorithm Algorithm { get; }
    string HashPassword(ReadOnlySpan<char> password);
    PasswordVerificationResult VerifyPassword(ReadOnlySpan<char> password, string hashedPassword);
    bool NeedsRehash(string hashedPassword);
}
```

### `ISimplePasswordHasher`
```csharp
namespace EricksonLopez.Security.Abstractions.Passwords;

public interface ISimplePasswordHasher
{
    string Hash(string password);
    bool Verify(string password, string hash);
    bool NeedsRehash(string hash);
}
```
A lightweight, string-oriented abstraction designed for consumer code and service boundaries that do not require span-based low-level ergonomics. Implemented directly by `CompositePasswordHasher`.

| Member | Description |
|---|---|
| `Algorithm` | Identifies the hashing algorithm used (e.g. `Argon2id`, `Pbkdf2HmacSha512`). |
| `HashPassword` | Derives a self-describing modular-crypt-format hash from a plaintext password. |
| `VerifyPassword` | Compares a plaintext password against a stored hash. Returns `Failed`, `Success`, or `SuccessRehashNeeded`. |
| `NeedsRehash` | Returns `true` when cost parameters are outdated and the hash should be upgraded on next login. |

#### Password Hasher Implementations & Dual Archetype Architecture (ADR-023)

The ecosystem provides specialized implementations of `IPasswordHasher` tailored to distinct bounded contexts:

1. **`EricksonLopez.Security.Passwords.Pbkdf2PasswordHasher`** (`EricksonLopez.Security`):
   - **Format**: Modular crypt format `$pbkdf2-sha512$i=210000$s=<salt>$<hash>`.
   - **Default Iterations**: `210,000` (OWASP standard for HMAC-SHA512).
   - **Role**: Primary hasher for full application suites; designed to interoperate seamlessly in `CompositePasswordHasher` with `Argon2idPasswordHasher` for transparent auto-upgrades.
   - **DI Registration**: `services.AddPasswordSecurity()`.

2. **`EricksonLopez.Security.Cryptography.Passwords.Pbkdf2PasswordHasher`** (`EricksonLopez.Security.Cryptography`):
   - **Format**: Lightweight format `PBKDF2.V1$<iterations>$<salt>$<hash>`.
   - **Default Iterations**: `600,000` (high-security single-hasher profile for standalone crypto environments).
   - **Role**: Standalone, zero-dependency password hasher for micro-components that consume only the cryptographic primitives tier.
   - **DI Registration**: `services.AddEricksonLopezCryptographyCore()`.

3. **`Argon2idPasswordHasher`** (`EricksonLopez.Security`):
   - **Format**: Standard modular crypt `$argon2id$v=19$m=65536,t=3,p=4$...` per RFC 9106 MCF.
   - **Default Parameters**: 64 MB memory header, 3 time-cost iterations, 4 parallelism lanes.
   - **Cryptographic Substrate (v1.x)**: PBKDF2-HMAC-SHA512 (effective iterations = `time_cost × 70,000`; default: 210,000). The `m=` and `p=` parameters are format metadata only — not used by the KDF. Not memory-hard in v1.x. See §24 and [ADR-024](./adr/adr-024-argon2id-hasher-implementation-strategy.md) for full substrate details and v2.x upgrade path.

4. **`LegacyPbkdf2PasswordHasher`** (`EricksonLopez.Security`):
   - **Format**: Modular crypt format `$legacy-pbkdf2$i=<iterations>$s=<salt>$<hash>`.
   - **Role**: Validates legacy hashes produced by older system versions, returning `PasswordVerificationResult.SuccessRehashNeeded` to signal automatic rehash on login.

5. **`CompositePasswordHasher`** (`EricksonLopez.Security`):
   - Composes a primary hasher with secondary fallback hashers, validating legacy formats and returning `SuccessRehashNeeded` to trigger transparent hash upgrades.

### `PasswordPolicy`
```csharp
namespace EricksonLopez.Security.Abstractions.Policies;

public sealed record PasswordPolicy(
    int MinimumLength = 12,
    int MaximumLength = 128,
    bool RequireDigit = true,
    bool RequireUppercase = true,
    bool RequireLowercase = true,
    bool RequireNonAlphanumeric = true,
    int MaxConsecutiveRepeatedChars = 3) : ISecurityPolicy<string>
```

---

## 6. Tokens & API Keys

### `IApiKeyGenerator` & `IApiKeyValidator`
```csharp
namespace EricksonLopez.Security.Abstractions.Tokens;

public interface IApiKeyGenerator
{
    ApiKeyIssuanceResult GenerateApiKey(
        string ownerId,
        string name,
        string prefix = "ek_live",
        TimeSpan? lifetime = null,
        IReadOnlySet<string>? scopes = null);
}

public interface IApiKeyValidator
{
    ValueTask<Result<ApiKey>> ValidateApiKeyAsync(
        string plaintextApiKey,
        CancellationToken cancellationToken = default);
}

### `ApiKeyIssuanceResult`
```csharp
namespace EricksonLopez.Security.Abstractions.Tokens;

public sealed record ApiKeyIssuanceResult(
    ApiKey Key,
    string PlaintextApiKey);
```
```

---

## 7. Error Catalog

### `SecurityError`
```csharp
namespace EricksonLopez.Security.Abstractions.Errors;

public static class SecurityError
{
    // Cryptographic Errors
    public static Error InvalidCiphertext(string? details = null);
    public static Error AuthenticationTagMismatch(string? details = null);
    public static Error InvalidKey(string? details = null);
    public static Error InvalidNonce(int actualLength, int expectedLength = 12);
    public static Error BufferTooSmall(int requiredBytes, int availableBytes);
    public static Error UnsupportedAlgorithm(string algorithm, string? details = null);
    public static Error EncryptionFailed(string details);
    public static Error DecryptionFailed(string details);

    // Key Management Errors
    public static Error KeyNotFound(string keyId, string? details = null);
    public static Error KeyExpired(string keyId, string? details = null);
    public static Error KeyRevoked(string keyId, string? details = null);
    public static Error KeyPurposeMismatch(string expectedPurpose, string actualPurpose);

    // Token & Password Errors
    public static Error InvalidToken(string? details = null);
    public static Error TokenExpired(string? details = null);
    public static Error TokenRevoked(string? details = null);
    public static Error InvalidPassword(string? details = null);

    // Policy & Secret Errors
    public static Error SecurityPolicyViolation(string policyName, string details);
    public static Error SecretNotFound(string secretName);
}
```

---

## 8. Zero Trust & ABAC

### `IAbacPolicyEngine`
```csharp
namespace EricksonLopez.Security.ZeroTrust;

public interface IAbacPolicyEngine
{
    AbacDecision Evaluate(AbacContext context, IReadOnlyList<AbacPolicy> policies);
}
```

---

## 9. WebAuthn & Passkeys

### `IWebAuthnCeremonyService`
```csharp
namespace EricksonLopez.Security.WebAuthn.Fido2.Abstractions;

public interface IWebAuthnCeremonyService
{
    /// <summary>Generates a credential creation options payload with a fresh cryptographic challenge.</summary>
    CredentialCreateOptions CreateRegistrationOptions(
        PublicKeyCredentialUserEntity user,
        CredentialCreateOptions? customOptions = null);

    /// <summary>Validates an authenticator attestation response and returns the verified credential registration.</summary>
    Task<Result<VerifiedCredentialRegistration>> VerifyRegistrationAsync(
        AuthenticatorAttestationRawResponse response,
        byte[] expectedChallenge,
        byte[] userHandle,
        CancellationToken cancellationToken = default);

    /// <summary>Generates a credential assertion options payload with a fresh cryptographic challenge.</summary>
    CredentialRequestOptions CreateAuthenticationOptions(
        CredentialRequestOptions? customOptions = null);

    /// <summary>Validates an authenticator assertion response and returns the verified credential assertion.</summary>
    Task<Result<VerifiedCredentialAssertion>> VerifyAuthenticationAsync(
        AuthenticatorAssertionRawResponse response,
        byte[] expectedChallenge,
        CosePublicKey storedPublicKey,
        uint storedSignCount,
        bool userVerificationRequired = false,
        CancellationToken cancellationToken = default);
}
```

**Key types**: `CredentialCreateOptions`, `CredentialRequestOptions`, `VerifiedCredentialRegistration`, `VerifiedCredentialAssertion`, `PublicKeyCredentialUserEntity`, `AuthenticatorAttestationRawResponse`, `AuthenticatorAssertionRawResponse`, `CosePublicKey` — all in namespace `EricksonLopez.Security.WebAuthn.Fido2.Models`.

#### Protocol & Ceremony Models (`EricksonLopez.Security.WebAuthn.Fido2.Models`)

| Model | Kind | Description |
|---|---|---|
| `CredentialCreateOptions` | `class` | Ceremony parameters passed to `navigator.credentials.create()`. |
| `CredentialRequestOptions` | `class` | Ceremony parameters passed to `navigator.credentials.get()`. |
| `AuthenticatorAttestationRawResponse` | `class` | Client JSON payload submitted upon registration ceremony completion. |
| `AuthenticatorAssertionRawResponse` | `class` | Client JSON payload submitted upon authentication ceremony completion. |
| `VerifiedCredentialRegistration` | `record` | Validated registration result containing credential ID, public key, counter, and AAGUID. |
| `VerifiedCredentialAssertion` | `record` | Validated authentication result confirming user presence/verification. |
| `PublicKeyCredentialUserEntity` | `record` | User entity metadata (`Id`, `Name`, `DisplayName`). |
| `RelyingPartyIdentity` | `record` | Relying party configuration (`Id`, `Name`). |
| `CosePublicKey` | `class` | COSE key representation (EC2 / RSA) decoded from authenticator attestation. |
| `AuthenticatorData` | `class` | Parsed authenticator data flags, sign count, and attested credential data. |
| `CollectedClientData` | `class` | Parsed client data JSON containing ceremony type, challenge, and origin. |
| `AttestationObject` | `class` | Decoded CBOR attestation container. |
| `AttestedCredentialData` | `class` | Authenticator AAGUID, credential ID, and COSE public key bytes. |
| `PublicKeyCredentialDescriptor` | `record` | Credential descriptor referencing allowed/excluded credential IDs. |
| `PublicKeyCredentialParameters` | `record` | Supported cryptographic algorithm types (e.g. ES256, RS256). |
| `WebAuthnOptions` | `class` | Service configuration options for origin, RP ID, timeout, and verification strictness. |

---

## 10. SAML 2.0 Service Provider

### `ISaml2Service`
```csharp
namespace EricksonLopez.Security.Saml2.Abstractions;

public interface ISaml2Service
{
    Saml2AuthnRequest CreateAuthnRequest(string? relayState = null);
    Task<Result<Saml2AuthenticationResult>> ProcessResponseAsync(
        string samlResponseXml,
        string? expectedInResponseTo = null,
        CancellationToken cancellationToken = default);
    Task<Result<Saml2AuthenticationResult>> ProcessIdpInitiatedResponseAsync(
        string samlResponseXml,
        CancellationToken cancellationToken = default);
    Saml2LogoutRequest CreateLogoutRequest(
        Saml2NameId nameId,
        string? sessionIndex = null,
        string? relayState = null);
    Task<Result<Saml2LogoutResponse>> ProcessLogoutResponseAsync(
        string samlLogoutResponseXml,
        string expectedInResponseTo,
        CancellationToken cancellationToken = default);
    Saml2LogoutResponse CreateLogoutResponse(
        string inResponseTo,
        string destination,
        bool success = true);
    string GenerateSpMetadata();
}
```

#### Protocol & Assertion Models (`EricksonLopez.Security.Saml2.Models`)

| Model | Kind | Description |
|---|---|---|
| `Saml2AuthnRequest` | `class` | Encapsulates an outbound SAML 2.0 `<AuthnRequest>` XML document and binding parameters. |
| `Saml2Response` | `class` | Encapsulates an inbound SAML 2.0 `<Response>` containing assertions and status codes. |
| `Saml2Assertion` | `class` | Decoded and signature-verified SAML assertion payload. |
| `Saml2AuthenticationResult` | `record` | High-level authentication outcome containing claims principal and session indices. |
| `Saml2LogoutRequest` | `class` | Single Logout (SLO) request targeting IdP or SP session termination. |
| `Saml2LogoutResponse` | `class` | Single Logout (SLO) response payload. |
| `Saml2Attribute` | `class` | Assertion attribute statement entry (name, friendly name, and string values). |
| `Saml2Subject` | `class` | Subject identity and confirmation elements. |
| `Saml2SubjectConfirmation` | `class` | Subject confirmation data, method, and recipient conditions. |
| `Saml2Conditions` | `class` | Temporal validity window (`NotBefore`, `NotOnOrAfter`) and audience restrictions. |
| `Saml2AuthnStatement` | `class` | Authentication statement detailing auth instant, session index, and context class. |
| `Saml2NameId` | `class` | Subject NameID value and format URI. |
| `Saml2Status` | `class` | SAML top-level and second-level status codes and status message. |
| `Saml2Options` | `class` | SP entity ID, assertion consumer service URL, metadata, and signing options. |

---

## 11. Network SSRF Prevention

### `SafeSocketsHttpHandler`
```csharp
namespace EricksonLopez.Security.Network;

public sealed class SafeSocketsHttpHandler : SocketsHttpHandler
{
    public SafeSocketsHttpHandler(SsrfProtectionOptions options, ISafeDnsResolver? dnsResolver = null);
}
```

### `SafeHttpClientFactory`
```csharp
namespace EricksonLopez.Security.Network;

public static class SafeHttpClientFactory
{
    public static HttpClient CreateClient(Action<SsrfProtectionOptions>? configure = null);
    public static HttpClient CreateClient(SsrfProtectionOptions options);
}
```
### `ISafeDnsResolver`
```csharp
namespace EricksonLopez.Security.Network;

public interface ISafeDnsResolver
{
    Task<Result<IPAddress[]>> ResolveAndValidateAsync(string host, CancellationToken cancellationToken = default);
}
```
Contract for SSRF-safe DNS resolution. Resolves a hostname to its IP addresses and validates every resolved address against configured blocked ranges. Accepts raw IP literals as well as DNS hostnames.

#### When to Use
- When making outbound connections to user-supplied or dynamically configured hostnames.
- Before passing a hostname to any HTTP client, gRPC channel, or socket connect.
- Prefer over `Dns.GetHostAddressesAsync` in any multi-tenant or webhook processing service.

#### When NOT to Use
- For loopback or intranet hostname resolution in controlled, closed networks where SSRF is not a threat model.

### `SafeDnsResolver`
```csharp
namespace EricksonLopez.Security.Network;

public sealed class SafeDnsResolver : ISafeDnsResolver
{
    public SafeDnsResolver(
        SsrfProtectionOptions? options = null,
        Func<string, CancellationToken, Task<IPAddress[]>>? dnsLookup = null);

    public Task<Result<IPAddress[]>> ResolveAndValidateAsync(
        string host,
        CancellationToken cancellationToken = default);
}
```
Production implementation of `ISafeDnsResolver`. Blocks SSRF vectors:
- **Cloud metadata hostnames**: `169.254.169.254`, `metadata.google.internal`, `metadata.azure.com`, AWS ECS endpoint, GCP metadata endpoint, etc.
- **Ambiguous octal IPv4 formats**: e.g. `010.0.0.1` (octal leading-zero bypass).
- **RFC 1918 private ranges**: Unless explicitly added to `AllowedRanges`.
- **DNS rebinding**: Validates every IP address returned by DNS, not just the first.
- **Allowlist enforcement**: If `SsrfProtectionOptions.AllowedHostnames` is non-empty, treats it as a deny-by-default allowlist.

The `dnsLookup` constructor parameter allows injecting a custom DNS delegate for unit testing without requiring actual network calls.

#### Basic Example
```csharp
var options = new SsrfProtectionOptions
{
    AllowedHostnames = new HashSet<string> { "api.example.com" },
    RestrictToAllowedHostnames = true
};
var resolver = new SafeDnsResolver(options);
var result = await resolver.ResolveAndValidateAsync("api.example.com");
if (!result.IsSuccess)
    throw new InvalidOperationException($"SSRF blocked: {result.Error.Description}");
```

---

## 12. Diagnostics & OpenTelemetry

### `SecurityOpenTelemetryExtensions`
```csharp
namespace EricksonLopez.Security.OpenTelemetry;

public static class SecurityOpenTelemetryExtensions
{
    public static TracerProviderBuilder AddEricksonLopezSecurityInstrumentation(this TracerProviderBuilder builder);
    public static MeterProviderBuilder AddEricksonLopezSecurityInstrumentation(this MeterProviderBuilder builder);
}
```
Emits semantic spans (`security.encrypt`, `security.decrypt`, `security.password.hash`, `security.password.verify`, `security.secret.protect`, `security.secret.unprotect`) and counters (`security.encrypt.total`, `security.decrypt.total`, `security.key.rotations_total`, `security.key.revocations_total`, `security.apikey.validations_total`, `security.password.verifications_total`) and histograms (`security.argon2id.hashing_duration_ms`, `security.pbkdf2.hashing_duration_ms`).

> **Note**: `security.argon2id.hashing_duration_ms` and `security.pbkdf2.hashing_duration_ms` are `Histogram<double>` instruments (not counters) and are named accordingly in the `SecurityMeter` class. Subscribe via `MeterListener.InstrumentPublished` filtering on `InstrumentType == typeof(Histogram<double>)`.

---

## 13. Multi-Factor Authentication

### `ITotpService`
```csharp
namespace EricksonLopez.Security.Mfa;

public interface ITotpService
{
    string GenerateSecretKey(int byteLength = 20);
    TotpSetupInfo GenerateSetupInfo(string issuer, string accountName, string? secretKey = null, TotpOptions? options = null);
    string ComputeCode(string secretKey, DateTimeOffset timestamp, TotpOptions? options = null);
    bool VerifyCode(string secretKey, string code, DateTimeOffset? timestamp = null, TotpOptions? options = null);
}
```

### `TotpService`
```csharp
namespace EricksonLopez.Security.Mfa;

public sealed class TotpService : ITotpService
{
    public TotpService(TimeProvider? timeProvider = null);
    public string GenerateSecretKey(int byteLength = 20);
    public TotpSetupInfo GenerateSetupInfo(string issuer, string accountName, string? secretKey = null, TotpOptions? options = null);
    public string ComputeCode(string secretKey, DateTimeOffset timestamp, TotpOptions? options = null);
    public bool VerifyCode(string secretKey, string code, DateTimeOffset? timestamp = null, TotpOptions? options = null);
}
```

### `TotpSetupInfo`
```csharp
namespace EricksonLopez.Security.Mfa;

public sealed record TotpSetupInfo(
    string SecretKey,
    string FormattedSecretKey,
    string AuthenticatorUri);
```

### `IRecoveryCodeGenerator` & `RecoveryCodeGenerator`
```csharp
namespace EricksonLopez.Security.Mfa;

public interface IRecoveryCodeGenerator
{
    string[] GenerateCodes(int count = 10, int codeLength = 10);
}

public sealed class RecoveryCodeGenerator : IRecoveryCodeGenerator
{
    public string[] GenerateCodes(int count = 10, int codeLength = 10);
    public static string HashCode(string code);
    public static bool VerifyCode(string candidateCode, string storedHash);
}
```

### `ITotpReplayStore`
```csharp
namespace EricksonLopez.Security.Mfa;

public interface ITotpReplayStore
{
    bool TryAdd(string key, DateTimeOffset expiresAt);
    ValueTask<bool> TryAddAsync(string key, DateTimeOffset expiresAt, CancellationToken cancellationToken = default);
}
```
Contract for tracking consumed TOTP codes within valid time-steps to prevent token replay attacks.

### `InMemoryTotpReplayStore`
```csharp
namespace EricksonLopez.Security.Mfa;

public sealed class InMemoryTotpReplayStore : ITotpReplayStore
{
    public bool TryAdd(string key, DateTimeOffset expiresAt);
    ValueTask<bool> TryAddAsync(string key, DateTimeOffset expiresAt, CancellationToken cancellationToken = default);
}
```
Default in-memory, thread-safe replay store utilizing concurrent collections and time-based eviction.

### `DelegateTotpReplayStore`
```csharp
namespace EricksonLopez.Security.Mfa;

public sealed class DelegateTotpReplayStore : ITotpReplayStore
{
    public DelegateTotpReplayStore(Func<string, DateTimeOffset, CancellationToken, ValueTask<bool>> asyncHandler);
    public DelegateTotpReplayStore(
        Func<string, DateTimeOffset, CancellationToken, ValueTask<bool>> asyncHandler,
        Func<string, DateTimeOffset, bool>? syncHandler);

    public bool TryAdd(string key, DateTimeOffset expiresAt);
    public ValueTask<bool> TryAddAsync(string key, DateTimeOffset expiresAt, CancellationToken cancellationToken = default);
}
```
Delegate-driven implementation enabling distributed replay store integration (e.g. Redis, distributed cache, SQL) without requiring subclassing. Registered via `services.AddDistributedTotpReplayStore(...)`.

---

## 14. FIDO Alliance MDS3 Client

### `IMds3MetadataService`
```csharp
namespace EricksonLopez.Security.WebAuthn.Fido2.Mds3;

public interface IMds3MetadataService
{
    Task<Result<AuthenticatorMetadata?>> GetMetadataAsync(Guid aaguid, CancellationToken cancellationToken = default);
    Task<Result<bool>> ValidateAuthenticatorStatusAsync(Guid aaguid, CancellationToken cancellationToken = default);
}
```

---

## 15. Public Key Infrastructure & X.509

### `ICertificateChainValidator`
```csharp
namespace EricksonLopez.Security.Pki;

public interface ICertificateChainValidator
{
    Result<bool> ValidateCertificate(X509Certificate2 certificate, CertificateValidationOptions? options = null);
}
```

---

## 16. Breach Detection Client

### `IHaveIBeenPwnedClient`
```csharp
namespace EricksonLopez.Security.Privacy.Hibp.Abstractions;

public interface IHaveIBeenPwnedClient
{
    Task<Result<PwnedPasswordCheckResult>> CheckPasswordAsync(string password, CancellationToken cancellationToken = default);
    Task<Result<IReadOnlyList<PwnedPasswordEntry>>> GetRangeAsync(string hashPrefix, CancellationToken cancellationToken = default);
}
```

---

## 17. XML Digital Signatures

### `XmlDigitalSignatureService`
```csharp
namespace EricksonLopez.Security.Cryptography.XmlDSig;

public sealed class XmlDigitalSignatureService
{
    // W3C XML Digital Signatures (RFC 3275) enveloped & enveloping signatures
}
```

### `IXmlDigitalSignatureVerifier` & `XmlDigitalSignatureVerifier`
```csharp
namespace EricksonLopez.Security.Cryptography.XmlDSig;

public interface IXmlDigitalSignatureVerifier
{
    Result<bool> VerifyXml(string xmlContent, X509Certificate2? expectedCertificate = null);
    Result<bool> VerifyXml(string xmlContent, X509Certificate2? expectedCertificate, XmlVerificationOptions? options);
    Result<bool> VerifyXml(XmlDocument document, X509Certificate2? expectedCertificate = null);
    Result<bool> VerifyXml(XmlDocument document, X509Certificate2? expectedCertificate, XmlVerificationOptions? options);
    Result<XmlVerificationResult> VerifyAndExtractSignedElement(
        XmlDocument document,
        X509Certificate2? expectedCertificate = null,
        XmlVerificationOptions? options = null);
}

public sealed class XmlDigitalSignatureService : IXmlDigitalSignatureVerifier, IXmlDigitalSigner
{
    public static XmlDigitalSignatureService Instance { get; }
    public Result<string> SignXml(string xmlContent, X509Certificate2 signingCertificate, XmlSigningOptions? options = null);
    public Result<string> SignXml(XmlDocument document, X509Certificate2 signingCertificate, XmlSigningOptions? options = null);
    public Result<bool> VerifyXml(string xmlContent, X509Certificate2? expectedCertificate = null);
    public Result<bool> VerifyXml(string xmlContent, X509Certificate2? expectedCertificate, XmlVerificationOptions? options);
    public Result<bool> VerifyXml(XmlDocument document, X509Certificate2? expectedCertificate = null);
    public Result<bool> VerifyXml(XmlDocument document, X509Certificate2? expectedCertificate, XmlVerificationOptions? options);
    public Result<XmlVerificationResult> VerifyAndExtractSignedElement(
        XmlDocument document,
        X509Certificate2? expectedCertificate = null,
        XmlVerificationOptions? options = null);
}

public sealed class XmlVerificationOptions
{
    public bool RequireTrustedCertificate { get; set; } = true;
    public IList<X509Certificate2> CustomTrustAnchors { get; set; } = new List<X509Certificate2>();
    public Func<X509Certificate2, bool>? CertificateTrustEvaluator { get; set; }
    public bool AllowUntrustedEmbeddedCertificate { get; set; }
}

public sealed class XmlVerificationResult
{
    public bool IsValid { get; }
    public XmlElement? SignedElement { get; }
    public string? ReferenceUri { get; }
    public X509Certificate2? SigningCertificate { get; }

    public XmlVerificationResult(
        bool isValid,
        XmlElement? signedElement,
        string? referenceUri,
        X509Certificate2? signingCertificate);
}
```

---

## 18. Hardware Security Modules

### `IDigitalSignatureEngine` (PKCS#11)
```csharp
// Interface defined in:
namespace EricksonLopez.Security.Abstractions.Cryptography;

public interface IDigitalSignatureEngine
{
    Result Sign(ReadOnlySpan<byte> payload, KeyIdentifier keyId, Span<byte> signatureDestination, out int bytesWritten);
    Result Verify(ReadOnlySpan<byte> payload, ReadOnlySpan<byte> signature, KeyIdentifier keyId);
}

// Concrete PKCS#11 implementation:
namespace EricksonLopez.Security.Cryptography.Pkcs11.Signing;

public sealed class Pkcs11DigitalSignatureEngine : IDigitalSignatureEngine { /* ... */ }
```

---

## 19. ASP.NET Core Middleware & Context

### `IRequestSecurityContext`
```csharp
namespace EricksonLopez.Security.AspNetCore.Context;

public interface IRequestSecurityContext
{
    bool IsAuthenticated { get; }
    string? ActorId { get; }
    ApiKey? ApiKey { get; }
    ClaimsPrincipal? Principal { get; }
    bool HasScope(string scope);
}
```

### Application Builder & DI Extensions
```csharp
namespace Microsoft.AspNetCore.Builder;

public static class AspNetCoreSecurityExtensions
{
    public static IApplicationBuilder UseSecurityHeaders(this IApplicationBuilder app);
    public static IApplicationBuilder UseApiKeyAuthentication(this IApplicationBuilder app);
    public static IServiceCollection AddEricksonLopezIdentityPasswordHasher<TUser>(this IServiceCollection services)
        where TUser : class;
}
```

### `IdentityPasswordHasherBridge<TUser>`
```csharp
namespace EricksonLopez.Security.AspNetCore.Identity;

public sealed class IdentityPasswordHasherBridge<TUser> : Microsoft.AspNetCore.Identity.IPasswordHasher<TUser>
    where TUser : class
{
    public IdentityPasswordHasherBridge(EricksonLopez.Security.Abstractions.Passwords.IPasswordHasher hasher);
    public string HashPassword(TUser user, string password);
    public PasswordVerificationResult VerifyHashedPassword(TUser user, string hashedPassword, string providedPassword);
}
```
Bridges ASP.NET Core Identity's `IPasswordHasher<TUser>` to `EricksonLopez.Security`'s `CompositePasswordHasher`, enabling transparent verification of legacy hashes and automatic rehash upgrades to PBKDF2/Argon2id.

---

## 20. Cloud KMS Adapters

> [!NOTE]
> **Implementation Status (v1.x)**: In v1.x, the cloud adapters (`AzureKeyVaultKeyStore`, `AwsKmsKeyStore`, `HashiCorpVaultKeyStore`, `GoogleCloudKmsKeyStore` and their corresponding `ISecretStore` implementations) provide high-performance in-memory implementations (`ConcurrentDictionary`) that model the adapter contracts for development, local testing, and application architectural decoupling without cloud account prerequisites. Direct HTTP/gRPC integration with cloud vendor SDKs is scheduled on the v2.x roadmap.

### Azure Key Vault (`EricksonLopez.Security.Azure`)
```csharp
namespace EricksonLopez.Security.Azure;

public sealed class AzureKeyVaultOptions
{
    public Uri? VaultUri { get; set; }
    public string SecretPrefix { get; set; } = string.Empty;
    public bool EnableDevelopmentInMemoryStub { get; set; }
    public global::Azure.Core.TokenCredential? Credential { get; set; }
    public global::Azure.Security.KeyVault.Secrets.SecretClient? SecretClient { get; set; }
    public global::Azure.Security.KeyVault.Keys.KeyClient? KeyClient { get; set; }
}

public sealed class AzureKeyVaultKeyStore : IKeyStore { /* ... */ }
public sealed class AzureKeyVaultSecretStore : ISecretStore { /* ... */ }
```
- **Registration**: `services.AddAzureKeyVaultSecurity(Action<AzureKeyVaultOptions> configure)` registers `IKeyStore` and `ISecretStore` singleton adapters.

---

### AWS KMS & Secrets Manager (`EricksonLopez.Security.Aws`)
```csharp
namespace EricksonLopez.Security.Aws;

public sealed class AwsSecurityOptions
{
    public string Region { get; set; } = "us-east-1";
    public string? KmsKeyId { get; set; }
    public string SecretPrefix { get; set; } = string.Empty;
    public bool EnableDevelopmentInMemoryStub { get; set; }
    public Amazon.Runtime.AWSCredentials? Credentials { get; set; }
    public Amazon.SecretsManager.IAmazonSecretsManager? SecretsManagerClient { get; set; }
    public Amazon.KeyManagementService.IAmazonKeyManagementService? KmsClient { get; set; }
}

public sealed class AwsKmsKeyStore : IKeyStore { /* ... */ }
public sealed class AwsSecretsManagerSecretStore : ISecretStore { /* ... */ }
```
- **Registration**: `services.AddAwsSecurity(Action<AwsSecurityOptions> configure)` registers `IKeyStore` and `ISecretStore` singleton adapters.

---

### HashiCorp Vault (`EricksonLopez.Security.HashiCorpVault`)
```csharp
namespace EricksonLopez.Security.HashiCorpVault;

public sealed class HashiCorpVaultOptions
{
    public Uri? VaultUrl { get; set; }
    public string TransitMountPath { get; set; } = "transit";
    public string KvMountPath { get; set; } = "secret";
    public string SecretPathPrefix { get; set; } = string.Empty;
    public bool EnableDevelopmentInMemoryStub { get; set; }
    public string? Token { get; set; }
    public string? RoleId { get; set; }
    public string? SecretId { get; set; }
    public string AppRoleMountPath { get; set; } = "approle";
    public string? Namespace { get; set; }
    public System.Net.Http.HttpClient? HttpClient { get; set; }
}

public sealed class HashiCorpVaultKeyStore : IKeyStore { /* ... */ }
public sealed class HashiCorpVaultSecretStore : ISecretStore { /* ... */ }
public sealed class HashiCorpVaultClient { /* ... */ }
```
- **Registration**: `services.AddHashiCorpVaultSecurity(Action<HashiCorpVaultOptions> configure)` registers `IKeyStore` and `ISecretStore` singleton adapters.

---

### Google Cloud KMS & Secret Manager (`EricksonLopez.Security.GoogleCloud`)
```csharp
namespace EricksonLopez.Security.GoogleCloud;

public sealed class GoogleCloudSecurityOptions
{
    public string? ProjectId { get; set; }
    public string LocationId { get; set; } = "global";
    public string? KeyRingId { get; set; }
    public string SecretPrefix { get; set; } = string.Empty;
    public bool EnableDevelopmentInMemoryStub { get; set; }
    public Google.Cloud.SecretManager.V1.SecretManagerServiceClient? SecretManagerClient { get; set; }
    public Google.Cloud.Kms.V1.KeyManagementServiceClient? KmsClient { get; set; }
}

public sealed class GoogleCloudKmsKeyStore : IKeyStore { /* ... */ }
public sealed class GoogleCloudSecretManagerStore : ISecretStore { /* ... */ }
```
- **Registration**: `services.AddGoogleCloudSecurity(Action<GoogleCloudSecurityOptions> configure)` registers `IKeyStore` and `ISecretStore` singleton adapters.

---

## 21. Testing Utilities & Static Analyzers

### Testing Doubles (`EricksonLopez.Security.Testing`)
- `FakeKeyStore`: In-memory thread-safe `IKeyStore` with programmatic fault injection.
- `FakeSecretProtector`: In-memory dictionary-backed `ISecretProtector`.
- `FakePasswordHasher`: Deterministic fast hasher for high-speed unit tests.
- `DeterministicRandomNumberGenerator`: Fixed-seed CSPRNG double (`ICryptographicRandomNumberGenerator`).
- `SecurityAssert`: Cryptographic assertion helpers verifying zeroization and constant-time execution.

### Static Roslyn Security Analyzers (`EricksonLopez.Security.Analyzers`)
| Diagnostic ID | Severity | Rule Description |
|---|---|---|
| `ELS0001` | Warning | Constant-time equality: Non-constant time comparison on sensitive bytes/strings. Use `CryptographicOperations.FixedTimeEquals` instead of `==` or `string.Equals`. |
| `ELS0002` | Warning | SecretBuffer lifecycle: `SecretBuffer` instance created without enclosing `using` declaration or statement. Enforced by `UndisposedSecretBufferAnalyzer`. |
| `ELS0003` | Warning | Hardcoded secret: Plaintext cryptographic key or secret literal assigned to a sensitive variable. Enforced by `HardcodedSecretAnalyzer`. |
| `ELS0004` | Warning | Insecure password algorithm: MD5 or SHA-1 used in a password hashing context. Enforced by `InsecurePasswordAlgorithmAnalyzer`. |
| `ELS0005` | Warning | Sensitive data exposure: `SecretBuffer`, `Secret<T>`, or `Redacted<T>` value passed directly to a logging format argument. Enforced by `LoggingRawSecretAnalyzer`. |

#### `DiagnosticIds` constants
```csharp
namespace EricksonLopez.Security.Analyzers;

public static class DiagnosticIds
{
    public const string NonConstantTimeComparison = "ELS0001";
    public const string UndisposedSecretBuffer    = "ELS0002";
    public const string HardcodedSecret           = "ELS0003";
    public const string InsecurePasswordAlgorithm = "ELS0004";
    public const string LoggingRawSecret          = "ELS0005";
}
```

---

## 22. Core Primitives Supplement

### `Fingerprint`
```csharp
namespace EricksonLopez.Security.Abstractions.Primitives;

public readonly record struct Fingerprint : IEquatable<Fingerprint>, IComparable<Fingerprint>
```
Strongly-typed immutable SHA-256 cryptographic fingerprint for tokens, certificates, and artifact integrity.

| Member | Description |
|---|---|
| `public string HexValue { get; }` | Uppercase hex-encoded SHA-256 fingerprint string. |
| `public static Fingerprint FromUtf8String(string input)` | Computes SHA-256 from a UTF-8 string. |
| `public static Fingerprint FromBytes(ReadOnlySpan<byte> data)` | Computes SHA-256 from raw bytes. |
| `public Fingerprint(string hexValue)` | Constructs from existing hex string (normalized to uppercase). |
| `public int CompareTo(Fingerprint other)` | Ordinal comparison for sorting and sets. |

---

### `SecurityStamp`
```csharp
namespace EricksonLopez.Security.Abstractions.Primitives;

public readonly record struct SecurityStamp : IEquatable<SecurityStamp>
```
Strongly-typed immutable security stamp for invalidating user sessions, refresh tokens, and authorization caches.

| Member | Description |
|---|---|
| `public string Value { get; }` | The raw stamp string. |
| `public static SecurityStamp New()` | Generates a new random UUIDv4 security stamp. |
| `public static bool TryCreate(string? value, out SecurityStamp stamp)` | Safe factory without exceptions. |
| `implicit operator SecurityStamp(string)` | Implicit conversion from string. |
| `implicit operator string(SecurityStamp)` | Implicit conversion to string. |

---

### `PasswordHash`
```csharp
namespace EricksonLopez.Security.Abstractions.Passwords;

public readonly record struct PasswordHash : IEquatable<PasswordHash>
```
Strongly-typed immutable container for a stored, self-describing password hash string. `ToString()` always returns `"[REDACTED PASSWORD HASH]"` to prevent leakage.

| Member | Description |
|---|---|
| `public string Value { get; }` | The raw modular crypt format string (authorized access only). |
| `public override string ToString()` | Always returns `"[REDACTED PASSWORD HASH]"`. |
| `implicit operator PasswordHash(string)` | Wraps a hash string. |
| `implicit operator string(PasswordHash)` | Unwraps the inner hash string. |

---

### `ApiKeyId`
```csharp
namespace EricksonLopez.Security.Abstractions.Primitives;

public readonly record struct ApiKeyId : IEquatable<ApiKeyId>, IComparable<ApiKeyId>
```
Strongly-typed identifier for API keys, string-backed, with implicit string conversion.

| Member | Description |
|---|---|
| `public string Value { get; }` | The raw string ID. |
| `public static ApiKeyId New()` | Generates a new random compact UUID identifier. |
| `implicit operator ApiKeyId(string)` | Implicit conversion from string. |
| `implicit operator string(ApiKeyId)` | Implicit conversion to string. |

---

### `ApiKey`
```csharp
namespace EricksonLopez.Security.Abstractions.Primitives;

public sealed record ApiKey(
    ApiKeyId Id,
    string OwnerId,
    string Name,
    string DisplayPrefix,
    string HashedSecret,
    DateTimeOffset CreatedAtUtc,
    DateTimeOffset? ExpiresAtUtc = null,
    DateTimeOffset? RevokedAtUtc = null,
    IReadOnlySet<string>? Scopes = null)
```
Immutable entity representing a persisted API key. Never stores the plaintext secret — only the salted cryptographic hash.

| Member | Description |
|---|---|
| `bool IsRevoked` | `true` if `RevokedAtUtc` is set. |
| `bool IsActive(DateTimeOffset? nowUtc = null)` | `true` if key is not revoked and not expired. |
| `bool HasScope(string scope)` | `true` if the key has been granted the specified scope. |

---

## 23. Enumerations

### `KeyPurpose`
```csharp
namespace EricksonLopez.Security.Abstractions.Primitives;

public enum KeyPurpose { Encryption = 1, Signing = 2, Hashing = 3, TokenProtection = 4, SecretProtection = 5, KeyWrapping = 6 }
```
Purpose-binding enum preventing key reuse across incompatible cryptographic operations (ADR-007 Misuse Resistance).

### `KeyStatus`
```csharp
public enum KeyStatus { Active = 1, Retired = 2, Revoked = 3, Destroyed = 4 }
```
Key lifecycle state machine. Active keys may encrypt; Retired keys may only decrypt; Revoked keys are prohibited for all operations.

### `PasswordHashAlgorithm`
```csharp
namespace EricksonLopez.Security.Abstractions.Passwords;

public enum PasswordHashAlgorithm : byte { Pbkdf2HmacSha512 = 1, Argon2id = 2, BCrypt = 3 }
```
Identifies the adaptive KDF algorithm used to generate a stored password hash.

### `AeadAlgorithm`
```csharp
namespace EricksonLopez.Security.Abstractions.Cryptography;

public enum AeadAlgorithm : byte
{
    Aes256Gcm = 1,
    ChaCha20Poly1305 = 2,
    HkdfAes256Gcm = 3
}
```
Identifies the authenticated encryption scheme bound to a `SecurityEnvelope`. The canonical identifier for the HKDF-enhanced scheme is `HkdfAes256Gcm = 3`. Full ML-KEM-768 encapsulation support is planned for a future release (see ADR-025).

### `PasswordVerificationResult`
```csharp
namespace EricksonLopez.Security.Abstractions.Passwords;

public enum PasswordVerificationResult { Success = 1, SuccessRehashNeeded = 2, Failed = 3 }
```
Result of a `IPasswordHasher.VerifyPassword()` call. `SuccessRehashNeeded` signals that the hash must be upgraded transparently on next login. **Note**: `Failed` has value `3`, not `0` — do not compare by numeric value.

---

## 24. Concrete Password Implementations

### `Argon2idPasswordHasher`
```csharp
namespace EricksonLopez.Security.Passwords;

public sealed class Argon2idPasswordHasher : IPasswordHasher
```
Password hasher that produces hashes encoded in the Argon2id modular crypt format
(`$argon2id$v=19$m={memory},t={iterations},p={parallelism}$...`).

> **Cryptographic substrate**: The underlying derivation function is **PBKDF2-HMAC-SHA512**
> (effective iterations = `time_cost × 70,000`; default: 210,000). The `m=` and `p=` parameters
> are stored as format metadata for rehash detection but are **not** used by the derivation function.
> The class is not memory-hard in the Argon2id sense. See `<remarks>` in the source XML for details.

| Member | Description |
|---|
---|
| `public static readonly Argon2idPasswordHasher Default` | Singleton: 64 MB, 3 time-cost iterations (210k PBKDF2 rounds), 4-lane parallelism header. |
| `public Argon2idPasswordHasher(int memorySizeKb = 65536, int iterations = 3, int parallelism = 4, int saltSizeBytes = 16)` | Custom cost parameters. `iterations` is the PBKDF2 multiplier (×70,000). |
| `public string HashPassword(ReadOnlySpan<char> password)` | Returns a modular crypt format string. |
| `public PasswordVerificationResult VerifyPassword(ReadOnlySpan<char> password, string hashedPassword)` | Constant-time PBKDF2 verification. |
| `public bool NeedsRehash(string hashedPassword)` | Returns `true` if format cost parameters don't match current config. |

**Best practice:** Use `Argon2idPasswordHasher.Default` for new deployments. Adjust `memorySizeKb` and `iterations` based on server throughput targets measured against 300–500ms hash time.

---

### `Pbkdf2PasswordHasher`
```csharp
namespace EricksonLopez.Security.Passwords;

public sealed class Pbkdf2PasswordHasher : IPasswordHasher
```
PBKDF2-HMAC-SHA512 password hasher per RFC 8018 and OWASP recommendations (`$pbkdf2-sha512$i=210000$...`).

| Member | Description |
|---|---|
| `public static readonly Pbkdf2PasswordHasher Default` | Singleton (210,000 iterations). |
| `public const int DefaultIterations = 210_000` | OWASP-recommended minimum. |
| `public Pbkdf2PasswordHasher(int iterations = 210_000, int saltSizeBytes = 16, int derivedKeySizeBytes = 32)` | Custom cost parameters. |

---

### `CompositePasswordHasher`
```csharp
namespace EricksonLopez.Security.Passwords;

public sealed class CompositePasswordHasher : IPasswordHasher
```
Transparent multi-algorithm password hasher. Inspects modular crypt prefixes to route verification to the correct algorithm engine. Signals `SuccessRehashNeeded` when the primary algorithm differs from the stored hash (enabling zero-downtime algorithm migration).

| Member | Description |
|---|---|
| `public CompositePasswordHasher(IPasswordHasher? primaryHasher = null, IEnumerable<IPasswordHasher>? additionalHashers = null)` | Default primary is `Pbkdf2PasswordHasher`. |
| `public PasswordHashAlgorithm Algorithm` | Delegates to the primary hasher. |
| `public PasswordVerificationResult VerifyPassword(...)` | Routes to matching prefix hasher; returns `SuccessRehashNeeded` for non-primary matches. |

---

### `LegacyPbkdf2PasswordHasher`
```csharp
namespace EricksonLopez.Security.Passwords;

public sealed class LegacyPbkdf2PasswordHasher : IPasswordHasher
```
Dedicated legacy password hasher emitting the `$legacy-pbkdf2$` modular crypt prefix and transparently verifying legacy `$argon2id$` hashes produced by earlier framework versions per ADR-030. Always returns `SuccessRehashNeeded` upon valid verification to promote migration to the primary hasher.

| Member | Description |
|---|---|
| `public static readonly LegacyPbkdf2PasswordHasher Default` | Singleton: 64 MB memory metadata, 3 iterations (210,000 PBKDF2 rounds), 4 lanes. |
| `public LegacyPbkdf2PasswordHasher(int memorySizeKb = 65536, int iterations = 3, int parallelism = 4, int saltSizeBytes = 16)` | Custom cost parameters. |
| `public PasswordHashAlgorithm Algorithm` | Returns `PasswordHashAlgorithm.Pbkdf2HmacSha512`. |
| `public string HashPassword(ReadOnlySpan<char> password)` | Emits hash with `$legacy-pbkdf2$` modular crypt prefix. |
| `public PasswordVerificationResult VerifyPassword(ReadOnlySpan<char> password, string hashedPassword)` | Constant-time PBKDF2 verification; signals `SuccessRehashNeeded` on match. |
| `public bool NeedsRehash(string hashedPassword)` | Returns `true` if stored format or parameters warrant rehash. |

---

## 25. Token Security

### `ITokenHasher`
```csharp
namespace EricksonLopez.Security.Abstractions.Tokens;

public interface ITokenHasher
{
    string HashToken(ReadOnlySpan<char> token);
    bool VerifyToken(ReadOnlySpan<char> token, string expectedHash);
}
```
Deterministic cryptographic hashing for tokens enabling indexed database lookups without storing reversible token plaintext.

### `HmacSha256TokenHasher`
```csharp
namespace EricksonLopez.Security.Tokens;

public sealed class HmacSha256TokenHasher : ITokenHasher
```
Token hasher producing lowercase hex digests using HMAC-SHA256 (with optional pepper) or plain SHA-256.

| Member | Description |
|---|---|
| `public HmacSha256TokenHasher()` | SHA-256 mode (no pepper key). |
| `public HmacSha256TokenHasher(ReadOnlySpan<byte> pepperKey)` | HMAC-SHA256 mode with server-side pepper. Prevents DB dump attacks. |
| `public string HashToken(ReadOnlySpan<char> token)` | Returns lowercase hex digest. |
| `public bool VerifyToken(ReadOnlySpan<char> token, string expectedHash)` | Constant-time comparison via `ConstantTimeComparer`. |

---

## 26. API Key Store

### `IApiKeyStore`
```csharp
namespace EricksonLopez.Security.Abstractions.Tokens;

public interface IApiKeyStore
{
    ValueTask<Result<ApiKey>> GetByIdAsync(ApiKeyId keyId, CancellationToken cancellationToken = default);
    ValueTask<Result> SaveAsync(ApiKey apiKey, CancellationToken cancellationToken = default);
    ValueTask<Result> RevokeAsync(ApiKeyId keyId, CancellationToken cancellationToken = default);
}
```

### `InMemoryApiKeyStore`
```csharp
namespace EricksonLopez.Security.Tokens;

public sealed class InMemoryApiKeyStore : IApiKeyStore
```
Thread-safe in-memory `IApiKeyStore` using `ConcurrentDictionary` for testing, development, and containerized deployments.

---

## 27. Secret Resolution

### `ISecretResolver`
```csharp
namespace EricksonLopez.Security.Abstractions.Secrets;

public interface ISecretResolver
{
    ValueTask<Result<Redacted<string>>> ResolveAsync(string secretReference, CancellationToken cancellationToken = default);
}
```
Resolves secret URI references across multiple backend stores. Supported schemes:
- `raw:VALUE` — inline plaintext (dev/test only)
- `env:VAR_NAME` — environment variable
- `store:SECRET_NAME` — registered `ISecretStore`

### `CompositeSecretResolver`
```csharp
namespace EricksonLopez.Security.Secrets;

public sealed class CompositeSecretResolver : ISecretResolver
```
Multi-scheme resolver delegating to `EnvironmentSecretStore` and a registered `ISecretStore` based on URI prefix.

| Constructor | Description |
|---|---|
| `CompositeSecretResolver(ISecretStore secretStore, EnvironmentSecretStore? envStore = null)` | If `envStore` is `null`, creates an unprefixed `EnvironmentSecretStore`. |

---

### `EnvironmentSecretStore`
```csharp
namespace EricksonLopez.Security.Secrets;

public sealed class EnvironmentSecretStore : ISecretStore
```
`ISecretStore` implementation reading and writing secrets from environment variables. Normalizes key names to `UPPER_CASE` with `.`, `:`, `-` replaced by `_`.

| Member | Description |
|---|---|
| `public EnvironmentSecretStore(string prefix = "")` | Optional prefix prepended to all key names (e.g. `"APP_"`). |
| `GetSecretAsync(string secretName, ...)` | Returns `SecretNotFound` if env var is absent. |
| `SetSecretAsync(string secretName, string secretValue, ...)` | Writes to `Environment.SetEnvironmentVariable`. |

---

## 28. Diagnostics & Observability (Core)

### `SecurityActivitySource`
```csharp
namespace EricksonLopez.Security.Diagnostics;

public static class SecurityActivitySource
```
Central `System.Diagnostics.ActivitySource` for all EricksonLopez.Security distributed tracing. Zero OTel SDK dependency — uses BCL inbox `System.Diagnostics` only (ADR-019).

| Member | Value | Description |
|---|---|---|
| `SourceName` | `"EricksonLopez.Security"` | Subscribe with `ActivityListener.ShouldListenTo`. |
| `SourceVersion` | `"1.0.0"` | Instrumentation version. |
| `Instance` | `ActivitySource` | Shared singleton. |
| `EncryptOperation` | `"security.encrypt"` | Span name for AEAD encrypt. |
| `DecryptOperation` | `"security.decrypt"` | Span name for AEAD decrypt. |
| `HashPasswordOperation` | `"security.password.hash"` | Span name for password hashing. |
| `VerifyPasswordOperation` | `"security.password.verify"` | Span name for password verification. |
| `ProtectSecretOperation` | `"security.secret.protect"` | Span name for secret wrapping. |
| `UnprotectSecretOperation` | `"security.secret.unprotect"` | Span name for secret unwrapping. |
| `WrapKeyOperation` | `"security.key.wrap"` | Span name for KMS key wrap operations. |
| `UnwrapKeyOperation` | `"security.key.unwrap"` | Span name for KMS key unwrap operations. |
| `TagAlgorithm` | `"security.algorithm"` | Tag key for the AEAD algorithm. |
| `TagKeyVersion` | `"security.key.version"` | Tag key for the key version. |
| `TagHashAlgorithm` | `"security.hash.algorithm"` | Tag key for the hash algorithm. |
| `TagResult` | `"security.result"` | Tag key for the operation result. |
| `TagErrorCode` | `"security.error.code"` | Tag key for the error code. |

---

### `SecurityMeter`
```csharp
namespace EricksonLopez.Security.Diagnostics;

public static class SecurityMeter
```
Central `System.Diagnostics.Metrics.Meter` for all EricksonLopez.Security metrics. Zero OTel SDK dependency. Subscribe via `MeterListener` or the `EricksonLopez.Security.OpenTelemetry` package.

| C# Property | OTel Instrument Name | Type | Description |
|---|---|---|---|
| `MeterName` | `"EricksonLopez.Security"` | — | Subscribe with `MeterListener.InstrumentPublished`. |
| `Instance` | — | `Meter` | Shared singleton. |
| `EncryptTotal` | `security.encrypt.total` | `Counter<long>` | Count of AEAD encrypt operations. Tags: `security.algorithm`. |
| `DecryptTotal` | `security.decrypt.total` | `Counter<long>` | Count of AEAD decrypt operations. Tags: `security.algorithm`, `security.key.version`. |
| `KeyRotationsTotal` | `security.key.rotations_total` | `Counter<long>` | Count of key rotation events. |
| `KeyRevocationsTotal` | `security.key.revocations_total` | `Counter<long>` | Count of key revocation events. |
| `ApiKeyValidationsTotal` | `security.apikey.validations_total` | `Counter<long>` | Count of API key validation attempts. Tags: `security.result`. |
| `PasswordVerificationsTotal` | `security.password.verifications_total` | `Counter<long>` | Count of password verification attempts. Tags: `security.result`, `security.hash.algorithm`. |
| `Argon2HashingDurationMs` | `security.argon2id.hashing_duration_ms` | `Histogram<double>` | Latency of Argon2idPasswordHasher hashing in milliseconds. Use for PBKDF2 iteration cost tuning. |
| `Pbkdf2HashingDurationMs` | `security.pbkdf2.hashing_duration_ms` | `Histogram<double>` | Latency of PBKDF2 hashing in milliseconds. |

> **Note**: The C# property name (e.g. `PasswordVerificationsTotal`) is the instrument accessor. The OTel instrument name (e.g. `security.password.verifications_total`) is the name emitted to your metrics backend and used in dashboards, alerts, and OTEL collector configuration.

---

## 29. Memory Primitives — Concrete Implementations

### `SecretBuffer` (factory methods)
```csharp
namespace EricksonLopez.Security.Memory;

public sealed class SecretBuffer : ISecretBuffer
```

| Member | Description |
|---|---|
| `static SecretBuffer FromSpan(ReadOnlySpan<byte> source)` | Allocates a new `SecretBuffer` and copies `source` into it. Throws `ArgumentException` if source is empty. |
| `static SecretBuffer CreateRandom(int sizeBytes)` | Allocates a new `SecretBuffer` filled with cryptographically random bytes via `RandomNumberGenerator.Fill`. |
| `static SecretBuffer FromUtf8(ReadOnlySpan<char> chars)` | Allocates a new `SecretBuffer` by UTF-8 encoding a `ReadOnlySpan<char>`. Avoids creating an intermediate managed `string` allocation — critical for capturing passwords directly from UI input without string interning. Throws `ArgumentException` if `chars` is empty. |
| `Span<byte> GetWritableSpan()` | Returns a writable span over the buffer for in-place mutation (e.g. filling from a KDF). Throws `ObjectDisposedException` if disposed. |
| `bool FixedTimeEquals(ReadOnlySpan<byte> other)` | Constant-time comparison against another byte span. |

> **Lifecycle**: Always use `SecretBuffer` inside a `using` block. The Roslyn analyzer `ELS0002` enforces this at compile time.

> **`FromUtf8` vs `new SecretBuffer`**: Prefer `SecretBuffer.FromUtf8(passwordSpan)` over `new SecretBuffer(Encoding.UTF8.GetBytes(password))` because the latter creates a temporary `byte[]` and, if `password` is a `string`, that string may be interned and survive GC indefinitely. `FromUtf8` encodes directly into the pooled buffer with no intermediate allocation.

### `ChaCha20Poly1305EncryptionEngine`
```csharp
namespace EricksonLopez.Security.Cryptography;

public sealed class ChaCha20Poly1305EncryptionEngine : IAuthenticatedEncryptionEngine
```

| Member | Description |
|---|---|
| `static readonly ChaCha20Poly1305EncryptionEngine Shared` | Shared singleton instance. |
| `static bool IsSupported` | `true` if the current platform and OS kernel support ChaCha20-Poly1305 (delegates to `System.Security.Cryptography.ChaCha20Poly1305.IsSupported`). Always check before use — returns `SecurityError.UnsupportedAlgorithm` when `false`. |
| `AeadAlgorithm Algorithm` | Returns `AeadAlgorithm.ChaCha20Poly1305`. |
| `int KeySizeBytes` | `32` (256-bit key). |
| `int NonceSizeBytes` | `12` (96-bit nonce per RFC 8439). |
| `int TagSizeBytes` | `16` (128-bit Poly1305 tag). |

> **Platform support**: ChaCha20-Poly1305 requires kernel-level support. It is universally available on Linux 4.8+ and Windows 10 1803+ (KB4493437). Always check `ChaCha20Poly1305EncryptionEngine.IsSupported` before first use in your application startup.

---

## 30. Real-Time Key Revocation & Cache Eviction

### `IKeyRevocationNotifier`
```csharp
namespace EricksonLopez.Security.Abstractions.KeyManagement;

public interface IKeyRevocationNotifier
{
    ValueTask NotifyRevokedAsync(KeyIdentifier keyId, KeyVersion version, KeyPurpose purpose, CancellationToken cancellationToken = default);
    IDisposable Subscribe(Action<KeyIdentifier, KeyVersion, KeyPurpose> handler);
}
```

#### Purpose & Architecture
Defines the authoritative contract for dispatching and receiving real-time key revocation signals across in-process `KeyRing` caches and distributed cluster nodes. When a key is compromised, this interface bypasses cache TTL expiration to evict keys immediately.

#### Members
- `NotifyRevokedAsync`: Broadcasts key revocation notifications asynchronously to all registered listeners.
- `Subscribe`: Registers a revocation listener callback invoked immediately when a revocation signal is received. Returns an `IDisposable` unsubscription token.

---

### `InProcessKeyRevocationNotifier`
```csharp
namespace EricksonLopez.Security.KeyManagement;

public sealed class InProcessKeyRevocationNotifier : IKeyRevocationNotifier
```

#### Remarks
Thread-safe, zero-allocation, high-performance in-process implementation of `IKeyRevocationNotifier`. Employs defensive subscriber isolation so that a failing subscriber callback cannot block or interrupt other listeners.

#### Basic Example
```csharp
var notifier = new InProcessKeyRevocationNotifier();
using var sub = notifier.Subscribe((keyId, version, purpose) =>
{
    Console.WriteLine($"Key {keyId}:{version} revoked for purpose {purpose}");
});

await notifier.NotifyRevokedAsync(new KeyIdentifier("key_1"), KeyVersion.Initial, KeyPurpose.SecretProtection);
```

#### Best Practices
- Automatically registered by `services.AddSecurity()` as singleton.
- Inject into custom `KeyLifecycleManager` or cluster message bus adapters (RabbitMQ, Kafka, Redis Pub/Sub).

---

### `IKeyRing` Invalidation Methods
```csharp
namespace EricksonLopez.Security.Abstractions.KeyManagement;

public interface IKeyRing
{
    void InvalidateKey(KeyIdentifier keyId, KeyVersion version);
    void InvalidateActiveKey(KeyPurpose purpose);
    void InvalidateAll();
}
```

#### Members
- `InvalidateKey(KeyIdentifier keyId, KeyVersion version)`: Immediately evicts and scrubs a specific versioned key from the local cache using `CryptographicOperations.ZeroMemory()`.
- `InvalidateActiveKey(KeyPurpose purpose)`: Immediately evicts and scrubs the active cached key for the specified purpose.
- `InvalidateAll()`: Immediately clears and scrubs all cached keys and metadata from the local cache.

#### When to Use
- When reacting to out-of-band security incidents.
- When performing manual key rotation or hot swapping encryption keys without restarting application hosts.

#### When NOT to Use
- During normal high-throughput read operations. KeyRing caches keys automatically; explicit invalidation is intended for lifecycle events and revocation.

---

## 31. Distributed TOTP Replay Prevention

### `DelegateTotpReplayStore`
```csharp
namespace EricksonLopez.Security.Mfa;

public sealed class DelegateTotpReplayStore : ITotpReplayStore
{
    public DelegateTotpReplayStore(Func<string, DateTimeOffset, CancellationToken, ValueTask<bool>> asyncHandler);
    public DelegateTotpReplayStore(
        Func<string, DateTimeOffset, CancellationToken, ValueTask<bool>> asyncHandler,
        Func<string, DateTimeOffset, bool>? syncHandler);
}
```

#### Purpose
Provides a delegate-driven implementation of `ITotpReplayStore` allowing application teams to connect multi-node distributed caches (e.g. Redis, distributed memory, SQL) directly into the MFA TOTP verification pipeline without writing subclass boilerplate.

#### Parameters
- `asyncHandler`: Asynchronous delegate invoked with `(key, expiresAt, cancellationToken)` returning `ValueTask<bool>` (`true` if key was successfully recorded for the first time, `false` if key was already present indicating a replay attack).
- `syncHandler`: Optional synchronous delegate invoked when non-async verification methods are executed.

#### Basic Example
```csharp
var clusterDict = new ConcurrentDictionary<string, DateTimeOffset>();
var store = new DelegateTotpReplayStore(
    asyncHandler: (key, expiry, ct) => ValueTask.FromResult(clusterDict.TryAdd(key, expiry)),
    syncHandler: (key, expiry) => clusterDict.TryAdd(key, expiry));

var totpService = new TotpService(TimeProvider.System, store);
var isValid = await totpService.VerifyCodeAsync(secret, code, DateTimeOffset.UtcNow, new TotpOptions { PreventReplay = true });
```

---

### `SecurityMfaServiceCollectionExtensions.AddDistributedTotpReplayStore`
```csharp
namespace EricksonLopez.Security.Mfa;

public static class SecurityMfaServiceCollectionExtensions
{
    public static IServiceCollection AddDistributedTotpReplayStore<TStore>(this IServiceCollection services)
        where TStore : class, ITotpReplayStore;

    public static IServiceCollection AddDistributedTotpReplayStore(
        this IServiceCollection services,
        Func<string, DateTimeOffset, CancellationToken, ValueTask<bool>> asyncHandler,
        Func<string, DateTimeOffset, bool>? syncHandler = null);
}
```

#### Remarks
Replaces the default `InMemoryTotpReplayStore` registered by `services.AddSecurityMfa()` with the configured distributed replay store singleton.

#### When to Use
- In any load-balanced or Kubernetes deployment where multiple backend replicas handle 2FA logins.

---

## 31. Cryptographic Binding Context

### `AuthenticatedContext`
```csharp
namespace EricksonLopez.Security.Abstractions.Cryptography;

public readonly struct AuthenticatedContext : IEquatable<AuthenticatedContext>
```
Strongly-typed container for Authenticated Associated Data (AAD) used in AEAD encryption. Binds encrypted envelopes cryptographically to specific tenants, request contexts, or application domains — making ciphertext produced for one context invalid when presented in another.

#### Static Factories
| Member | Description |
|---|---|
| `static AuthenticatedContext Empty` | Returns the default empty context (no AAD). |
| `static AuthenticatedContext ForTenant(string tenantId)` | Creates an AAD binding for a specific tenant. Encodes `"tenant:<tenantId>"` as UTF-8 bytes. Throws `ArgumentException` if `tenantId` is null or whitespace. |
| `static AuthenticatedContext FromBytes(ReadOnlySpan<byte> contextBytes)` | Creates an AAD binding from raw bytes. Returns `Empty` if the span is empty. |

#### Properties
| Member | Description |
|---|---|
| `ReadOnlySpan<byte> Span` | Gets the raw AAD bytes (empty span for `Empty` context). |
| `bool IsEmpty` | `true` if no AAD bytes are bound. |

#### Equality
- `Equals(AuthenticatedContext other)` — constant-time comparison via `CryptographicOperations.FixedTimeEquals`.
- Supports `==` and `!=` operators.
- `GetHashCode()` uses `HashCode.AddBytes` over the AAD span.

#### Basic Example
```csharp
// Per-tenant envelope binding
var ctx = AuthenticatedContext.ForTenant("acme-corp");
byte[] ciphertext = (await protector.ProtectAsync(plaintext, KeyPurpose.SecretProtection, ctx)).Value;

// Custom request-scoped binding
var requestCtx = AuthenticatedContext.FromBytes(
    Encoding.UTF8.GetBytes($"request:{requestId};region:{region}"));

// No AAD (backward compatibility or low-risk scenarios)
var noCtx = AuthenticatedContext.Empty;
```

#### When to Use
- Bind encrypted database fields to their owning tenant to prevent cross-tenant decryption.
- Domain-separate ciphertexts across environments (e.g. `env:prod` vs `env:staging`).
- Include request or session identifiers as AAD to bind ephemeral tokens to their issuing context.

#### When NOT to Use
- Do NOT pass user-controlled input as AAD without validation — AAD is authenticated but not secret; it appears in the envelope metadata.
- Do NOT use `AuthenticatedContext.Empty` for multi-tenant systems — missing AAD allows cross-tenant decryption attacks.

> **Consistency requirement**: AAD used at encryption time must be byte-for-byte identical at decryption time. Any change to AAD bytes causes an `AuthenticationTagMismatch` error, which is the security guarantee. Serialize context fields deterministically (UTF-8, fixed byte order) to ensure reproducibility.
