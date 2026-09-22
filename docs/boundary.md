# Architectural Boundary Specification: EricksonLopez.Security

## 1. Purpose

`EricksonLopez.Security` defines the foundational cryptographic abstractions, authenticated encryption envelopes, key lifecycle state machines, zero-allocation memory primitives, and modular security adapters for enterprise .NET ecosystems.

---

## 2. Layer Segregation & Package Ownership

### Core Primitives & Contracts (`EricksonLopez.Security.Abstractions`)
- Pure domain models, value objects (`KeyIdentifier`, `KeyVersion`, `SecretBuffer`), error catalogs (`SecurityError`), and contract interfaces.
- **Allowed Dependencies**: .NET BCL and `EricksonLopez.Result` (ecosystem sibling for monadic functional error handling).
- **Forbidden Dependencies**: Concrete cryptography providers, web frameworks, third-party cloud SDKs.

### Cryptographic Engine (`EricksonLopez.Security.Cryptography`)
- Direct AEAD cipher implementations (AES-256-GCM, ChaCha20-Poly1305), constant-time comparers (`FixedTimeEquals`), and memory-scrubbed buffers (`CryptographicOperations.ZeroMemory`).
- Zero heap allocation pipelines using `ReadOnlySpan<byte>` and pooled array buffers.

### Core Security Manager (`EricksonLopez.Security`)
- Authenticated binary envelopes (`SecurityEnvelope`), multi-version key rings, password hashers, token security, and secret protection pipelines.

### Cloud Key & Secret Satellite Adapters (`EricksonLopez.Security.Aws`, `Azure`, `HashiCorpVault`, `GoogleCloud`)
- SPI provider implementations for remote key management.
- **v1.x Status**: Provider doubles/stubs backed by thread-safe `ConcurrentDictionary` for testing and deterministic validation without external cloud SDK overhead. Full SDK integration scheduled for future milestones.

### Protocol & Identity Engines (`EricksonLopez.Security.Saml2`, `WebAuthn.Fido2`, `ZeroTrust`)
- Protocol-specific ceremony runners: SAML 2.0 Service Provider with Anti-XSW protection, FIDO2/WebAuthn Level 3 Passkeys orchestrator, and NIST SP 800-162 / XACML ABAC evaluator.

---

## 3. Core Architectural Invariants

1. **Native AOT Compatibility**: Enforced globally across core packages (`IsAotCompatible=true`, `EnableTrimAnalyzer=true`). Zero runtime reflection in core crypto paths.
2. **Zero Insecure Ciphers**: ECB and CBC modes prohibited by design. Only AEAD authenticated ciphers permitted.
3. **Memory Scrubbing**: Sensitive key material and plaintexts scrubbed via `CryptographicOperations.ZeroMemory` on object disposal.
4. **Side-Channel Timing Resistance**: All cryptographic tag and signature verifications must execute via constant-time comparers.
5. **Result Pattern**: Functional error handling via `Result<T>` with standardized domain error codes; zero exceptions for normal control flow.
