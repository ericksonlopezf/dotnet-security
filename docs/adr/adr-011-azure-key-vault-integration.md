# ADR-011: Azure Key Vault Key and Secret Store Satellite Integration

## Status
Accepted

## Date
2026-09-04

## Context
Enterprise cloud architectures hosted on Microsoft Azure require persisting and resolving cryptographic keys and application secrets from Azure Key Vault (AKV) with hardware-security module (HSM) backing and Managed Identity / Azure RBAC access controls.

## Decision
1. **Satellite Package Segregation**: `EricksonLopez.Security.Azure` is implemented as an optional satellite adapter package, keeping `EricksonLopez.Security.Abstractions` and core libraries 100% free of cloud SDK dependencies.
2. **Adapter Implementation**:
   - `AzureKeyVaultKeyStore`: Implements `IKeyStore` to persist, retrieve, and transition cryptographic key metadata in Key Vault.
   - `AzureKeyVaultSecretStore`: Implements `ISecretStore` with secret prefix namespace isolation.
3. **DI Registration**: Exposes `services.AddAzureKeyVaultSecurity(...)` for easy DI configuration.

## Implementation Status (Production SDK & Development Mode)
The v1.0 implementation of `AzureKeyVaultKeyStore` and `AzureKeyVaultSecretStore` provides production-grade integration directly with `Azure.Security.KeyVault.Keys` (with `CryptographyClient` RSA-OAEP key wrapping) and `Azure.Security.KeyVault.Secrets` (via `SecretClient`). For local development and CI testing environments without active Azure credentials, setting `AzureKeyVaultOptions.EnableDevelopmentInMemoryStub = true` enables a thread-safe in-memory test double backed by `ConcurrentDictionary`.

## Consequences
- **Positive**: Native Azure Key Vault integration with enterprise hardware-backed key protection is fully operational in v1.0, with zero cloud dependencies required for local testing when development stub mode is active.
- **Negative**: Applications targeting live Key Vault require configuring appropriate Azure credentials (`TokenCredential` / `DefaultAzureCredential`).
