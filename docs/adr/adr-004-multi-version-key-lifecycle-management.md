# ADR-004: Multi-Version Key Lifecycle Management and State Transitions

## Status
Accepted

## Date
2026-09-04

## Context
Cryptographic keys must undergo regular rotation to adhere to cryptographic best practices (NIST SP 800-57 Part 1). Traditional systems frequently break legacy ciphertexts upon key rotation or require dangerous in-place database batch re-encryption jobs that cause system downtime.

## Decision
1. **Key Versioning (`KeyVersion`)**: Keys are assigned strongly typed, positive sequential versions starting at `v1`.
2. **Key Status State Machine**:
   - `Active`: Permitted for both new encryption operations and decryption.
   - `Retired`: Prohibited for new encryptions; permitted strictly for historical decrypt operations.
   - `Revoked`: Hard emergency kill-switch; immediately rejected for all cryptographic operations.
   - `Destroyed`: Zeroed out in memory and securely deleted.
3. **Automated Rotation Workflow (`IKeyLifecycleManager`)**:
   - Rotating a key transitions the current `Active` key to `Retired`.
   - Generates a new `Active` key with `version = previous.Next()`.
   - Emits `KeyRotatedEvent` domain event for audit logging.
4. **Transparent Envelope Resolution**: Decryption operations read the envelope header's `(KeyId, Version)`, look up the exact historical key in `IKeyRing`, and decrypt without manual version branching.

## Consequences
- **Positive**: Zero-downtime key rotation. Historical data remains decryptable on read without blocking background re-encryption migrations.
- **Negative**: Key repositories must retain retired keys as long as historical records encrypted under those keys exist.
