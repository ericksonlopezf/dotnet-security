# ADR-008: Type-Safe Redaction for Sensitive Primitives

## Status
Accepted

## Date
2026-09-04

## Context
Accidental leakage of API keys, credentials, connection strings, and cryptographic tokens into application logs, APM traces, exception messages, and monitoring dashboards is a major OWASP Top 10 vulnerability (A09: Security Logging and Monitoring Failures).

## Decision
1. **`Redacted<T>` Value Type**: All sensitive configuration values, connection strings, and secrets are encapsulated in `Redacted<T>`.
2. **Mandatory Masking in `ToString()`**: `ToString()` on sensitive primitives (`Redacted<T>`, `Secret<T>`, `SecretBuffer`, `ProtectedSecret`, `OpaqueToken`, `ApiKeyId`, `TimingSafeString`) unconditionally returns `"[REDACTED]"`.
3. **Explicit Opt-in for Raw Value Access**: Plaintext data can only be accessed through explicit property/method names such as `UnsafeValue` or `GetKeyBytes()`.

## Consequences
- **Positive**: Complete prevention of accidental credential leakage in standard structured logging, Serilog, OpenTelemetry, and console outputs.
- **Negative**: Developers must intentionally call `.UnsafeValue` when passing secrets to underlying drivers.
