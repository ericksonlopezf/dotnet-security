# ADR-009: Non-Reversible Hashed Storage for Tokens and API Keys

## Status
Accepted

## Date
2026-09-04

## Context
Storing API keys, session tokens, and refresh tokens in plaintext inside databases creates a severe single point of failure: database dumps or unauthorized SQL read access compromise all service tokens across the entire platform.

## Decision
1. **Single-Use Plaintext Issuance**: Plaintext API keys (`{prefix}_{id16}_{secret24}`) and opaque tokens are returned to the caller exactly ONCE upon issuance.
2. **Hashed Persistence**: Only cryptographic SHA-256 / HMAC-SHA256 digests of the secret part are persisted in the database.
3. **Lookup Prefix (`DisplayPrefix`)**: Stored entities include a non-sensitive identifier prefix (e.g., `ek_live_4fecdac2ba87e980_****`) for database indexing, UI display, and administrative revocation.
4. **Constant-Time Verification**: Incoming API keys are parsed into key identifier and secret, retrieved by key identifier, and verified using constant-time hash comparison.

## Consequences
- **Positive**: Database breach or SQL injection cannot expose usable API keys.
- **Negative**: Users who lose their API key must generate a new key; plaintext cannot be recovered.
