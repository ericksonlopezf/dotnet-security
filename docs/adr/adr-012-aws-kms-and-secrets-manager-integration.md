# ADR-012: AWS KMS and Secrets Manager Satellite Integration

## Status
Accepted

## Date
2026-09-04

## Context
Deployments hosted on Amazon Web Services (AWS) require managing cryptographic keys in AWS Key Management Service (KMS) and application secrets in AWS Secrets Manager using IAM roles and AWS encryption envelopes.

## Decision
1. **Satellite Package Segregation**: `EricksonLopez.Security.Aws` provides isolated AWS integration without cloud vendor lock-in inside the core libraries.
2. **Adapter Implementations**:
   - `AwsKmsKeyStore`: Implements `IKeyStore` for persisting and resolving cryptographic keys via KMS data key envelopes.
   - `AwsSecretsManagerSecretStore`: Implements `ISecretStore` for managing application secrets.
3. **DI Registration**: Exposes `services.AddAwsSecurity(...)`.

## Implementation Status (Production SDK & Development Mode)
The v1.0 implementation of `AwsKmsKeyStore` and `AwsSecretsManagerSecretStore` provides production-grade integration directly with `AWSSDK.KeyManagementService` (via `IAmazonKeyManagementService`) and `AWSSDK.SecretsManager` (via `IAmazonSecretsManager`). For local development and CI testing environments without active AWS credentials, setting `AwsKmsOptions.EnableDevelopmentInMemoryStub = true` enables a thread-safe in-memory test double backed by `ConcurrentDictionary`.

## Consequences
- **Positive**: Native AWS KMS and Secrets Manager integration with hardware-backed KMS customer managed keys (CMK) is fully operational in v1.0, with zero cloud dependencies required for local testing when development stub mode is active.
- **Negative**: Applications targeting live AWS KMS require configured AWS IAM credentials or IAM Roles for Service Accounts (IRSA).
