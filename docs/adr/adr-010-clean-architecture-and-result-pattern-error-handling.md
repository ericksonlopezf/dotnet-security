# ADR-010: Result Pattern and Functional Error Handling in Security Primitives

## Status
Accepted

## Date
2026-09-04

## Context
In security-critical workflows, throwing runtime exceptions for expected failure modes (invalid passwords, expired tokens, revoked keys, ciphertext tampering) causes performance degradation due to stack trace generation, encourages catch-all exception swallowing, and leaks implementation details in unhandled exception handlers.

## Decision
1. **Result Pattern Everywhere**: All recoverable domain and security operations return `Result` or `Result<T>` from `EricksonLopez.Result`.
2. **Standardized Error Catalog (`SecurityError`)**: Predefined structured error codes and descriptive domain errors:
   - `Security.InvalidCiphertext`
   - `Security.AuthenticationTagMismatch`
   - `Security.InvalidKey`
   - `Security.KeyNotFound`
   - `Security.KeyExpired`
   - `Security.KeyRevoked`
   - `Security.InvalidToken`
   - `Security.TokenExpired`
   - `Security.TokenRevoked`
   - `Security.PolicyViolation`
   - `Security.SecretNotFound`
3. **Exceptions Reserved for Invariant Violations**: Exceptions (`ArgumentNullException`, `ArgumentOutOfRangeException`, `ObjectDisposedException`) are strictly reserved for developer contract and invariant violations.

## Consequences
- **Positive**: Zero allocation for expected security failures, explicit compiler-enforced error handling, safe Native AOT stack execution.
- **Negative**: Callers must explicitly check `.IsSuccess` / `.IsFailure` instead of relying on `try / catch`.
