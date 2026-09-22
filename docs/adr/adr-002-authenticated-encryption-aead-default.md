# ADR-002: Authenticated Encryption (AEAD) as the Sole Symmetric Primitive

## Status
Accepted

## Date
2026-09-04

## Context
Traditional cryptographic designs frequently paired unauthenticated encryption modes (such as AES-CBC or AES-CTR) with manual HMAC hashing (Encrypt-then-MAC). In practice, manual composition often introduced critical implementation vulnerabilities, including padding oracle attacks (e.g. Lucky Thirteen, POODLE), MAC comparison timing side-channels, and unauthenticated metadata tampering.

## Decision
1. **AEAD Exclusivity**: Mandatory and exclusive use of Authenticated Encryption with Associated Data (AEAD) primitives:
   - Primary standard: **AES-256-GCM** (NIST SP 800-38D) with 256-bit keys, 96-bit unique nonces, and 128-bit authentication tags.
   - Secondary standard: **ChaCha20-Poly1305** (RFC 8439) on supported platforms.
2. **Rejection of Unauthenticated Modes**: AES-CBC, ECB, OFB, and raw unauthenticated streams are strictly prohibited and will not be provided in the public API.
3. **Associated Data Binding**: Contextual metadata (e.g., Tenant ID, Resource Type, Record ID) MUST be bound via AEAD Associated Data (AAD) to prevent ciphertext transplant attacks across tenants or record boundaries.

## Consequences
- **Positive**: Complete mitigation of padding oracle and ciphertext malleability attacks. Native hardware acceleration via AES-NI and CLMUL.
- **Negative**: Nonce reuse is catastrophic in GCM mode; therefore, nonces MUST be generated using cryptographically secure random number generators (`RandomNumberGenerator.Fill`) for every encryption operation.
