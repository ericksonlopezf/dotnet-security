# Threat Model & Security Evaluation (STRIDE Analysis)

## 1. Scope & Trust Boundaries

`EricksonLopez.Security` protects sensitive application state, persistent tokens, and cryptographic material against adversaries with various levels of access:
- **Network Adversaries**: Eavesdropping, replay attacks, man-in-the-middle (MitM).
- **Compromised Persistence / Database Adversaries**: SQL injection dumps, raw storage volume snapshots.
- **Side-Channel Adversaries**: Remote and local timing analysis.
- **Log / APM Aggregation**: Unintentional leakage of credentials and tokens into observability pipelines.

---

## 2. STRIDE Threat Matrix

| STRIDE Category | Threat Scenario | Specific Mitigation in `EricksonLopez.Security` |
|---|---|---|
| **Spoofing** | Forged API keys presented to web API endpoints. | Structured high-entropy API keys with SHA-256 hash storage; `ApiKeyValidator` uses constant-time comparison. |
| **Tampering** | Ciphertext alteration or cross-tenant envelope manipulation. | **AES-256-GCM** / **ChaCha20-Poly1305** authenticated encryption with 128-bit authentication tags and Associated Data (AAD) tenant binding. |
| **Repudiation** | Key rotation or revocation actions untracked. | Domain event emission (`KeyRotatedEvent`, `KeyRevokedEvent`, `ApiKeyCreatedEvent`) with immutable timestamps and key identifiers. |
| **Information Disclosure** | Plaintext API keys or credentials leaked into application logs. | `Redacted<T>`, `Secret<T>`, and `OpaqueToken` unconditionally return `[REDACTED]` in `ToString()`. Single-use plaintext API key issuance. |
| **Information Disclosure** | Timing side-channel attacks on tokens or password comparisons. | `CryptographicOperations.FixedTimeEquals` enforced across `ConstantTimeComparer`, `TimingSafeString`, and `ITokenHasher`. |
| **Denial of Service** | Unbounded PBKDF2/Argon2 iteration parameters causing CPU starvation. | `PasswordPolicy` and configurable constructor bounds prevent malicious computational amplification. |
| **Elevation of Privilege** | Replay of expired or revoked API keys. | Explicit status checks (`IsActive()`, `IsRevoked`) and expiration validation prior to token secret comparison. |

---

## 3. Defense-in-Depth Mechanisms

1. **Memory Scrubbing**: `SecretBuffer` uses `CryptographicOperations.ZeroMemory` upon disposal to minimize RAM residency of sensitive key material.
2. **Native AOT Trimming Safety**: Zero runtime reflection ensures no code stripping vulnerabilities during ahead-of-time compilation.
3. **No Unauthenticated Encryption**: Legacy unauthenticated cipher modes (AES-CBC, ECB) are completely absent from the library.
