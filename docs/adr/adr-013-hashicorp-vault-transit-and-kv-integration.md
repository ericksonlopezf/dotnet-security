# ADR-013: HashiCorp Vault Transit and KV v2 Satellite Integration

## Status
Accepted

## Date
2026-09-04

## Context
Multi-cloud, hybrid, and on-premises enterprise environments frequently utilize HashiCorp Vault for centralized key management and dynamic secret distribution across container clusters (Kubernetes).

## Decision
1. **Satellite Package**: `EricksonLopez.Security.HashiCorpVault` encapsulates Vault-specific API mechanics.
2. **Adapter Implementations**:
   - `HashiCorpVaultKeyStore`: Implements `IKeyStore` leveraging the Vault Transit secrets engine.
   - `HashiCorpVaultSecretStore`: Implements `ISecretStore` leveraging the Vault KV v2 engine.
3. **DI Registration**: Exposes `services.AddHashiCorpVaultSecurity(...)`.

## Implementation Status (Production API & Development Mode)
The v1.0 implementation of `HashiCorpVaultKeyStore` and `HashiCorpVaultSecretStore` provides production-grade integration directly with HashiCorp Vault's Transit secrets engine and KV v2 secrets engine via authenticated HTTP/REST API endpoints. For local development and CI testing environments without an active Vault cluster, setting `HashiCorpVaultOptions.EnableDevelopmentInMemoryStub = true` enables a thread-safe in-memory test double backed by `ConcurrentDictionary`.

## Consequences
- **Positive**: Cloud-neutral secrets and key management contracts with genuine Vault Transit / KV-v2 integration are fully operational in v1.0, with zero external dependencies required for local testing when development stub mode is active.
- **Negative**: Applications targeting live Vault require configured Vault address and authentication tokens (`VAULT_TOKEN`).
