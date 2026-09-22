# Security Model & Invariants

## 1. Security Architecture Tenets

`EricksonLopez.Security` is founded upon six core architectural invariants:

1. **Misuse Resistance**: APIs are designed so that insecure configurations (unauthenticated ciphers, non-random nonces, hardcoded keys, premature memory leaks) fail at compile time or fail fast via strongly-typed `Result` error codes.
2. **Authenticated Encryption by Default**: Only AEAD modes (AES-256-GCM and ChaCha20-Poly1305) are permitted. Unauthenticated ciphers (AES-CBC, ECB) are completely excluded.
3. **Cryptographic Agility & Multi-Version Envelopes**: Payloads are serialized with versioned envelopes (`SecurityEnvelope`), allowing algorithms and keys to evolve without breaking historical record decryption.
4. **Side-Channel Timing Resistance**: All credential, token, HMAC, and hash comparisons execute in constant time (`CryptographicOperations.FixedTimeEquals`, `TimingSafeString`).
5. **Memory Scrubbing**: Sensitive key material, intermediate tokens, and rented buffers are wiped from RAM using `CryptographicOperations.ZeroMemory` upon disposal.
6. **Type-Safe Redaction**: Sensitive value wrappers (`Redacted<T>`, `Secret<T>`, `OpaqueToken`) prevent accidental exposure in application logs, traces, and exception messages.

---

## 2. Invariants & Guardrails Matrix

| Component | Invariant Protected | Enforcement Mechanism |
|---|---|---|
| **`SecretBuffer`** | Ephemeral key material must not linger in GC heap. | Uses `ArrayPool<byte>` with deterministic `CryptographicOperations.ZeroMemory` on `Dispose()`. |
| **`EncryptedData`** | Plaintext must not be confused with ciphertext. | Distinct strongly-typed records; ciphertext is decoupled from raw plaintext byte buffers. |
| **`SecurityEnvelope`** | Payloads must carry key lineage and algorithm metadata. | Deterministic binary layout with magic byte, version, algorithm ID, key ID, version, nonce, tag, and ciphertext. |
| **`KeyRing`** | Historical data remains decryptable after key rotation. | Retains `Retired` keys for decrypt while routing new encryptions exclusively to the highest `Active` key. |
| **`CompositePasswordHasher`**| Legacy password hashes must be upgraded transparently. | Returns `PasswordVerificationResult.SuccessRehashNeeded` upon valid legacy hash verification. |
| **`ApiKeyGenerator`** | Plaintext secrets must never be recoverable from the DB. | Returns single-use plaintext on issuance; persists only SHA-256 / HMAC digests. |
| **`ConstantTimeComparer`** | Mismatched token lengths or values must not leak timing information. | Constant-time bitwise operations without early return branches. |

---

## 3. Residual Risk & Defense-in-Depth

- **Physical Machine Compromise**: Root/kernel-level memory access or hardware cold boot attacks cannot be 100% prevented by managed runtimes; however, explicit memory zeroing drastically minimizes the exposure window.
- **KMS / HSM Outages**: Applications utilizing custom `IKeyStore` adapters should configure resilient caching and retry policies (e.g., via `Microsoft.Extensions.Http.Resilience` / Polly, or application-level retry policies).
