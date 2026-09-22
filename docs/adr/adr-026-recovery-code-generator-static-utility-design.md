# ADR-026: RecoveryCodeGenerator Static Utility Architecture and API Design

## Status
Superseded by [ADR-029](adr-029-recovery-code-generator-dependency-injection-abstraction.md)

## Date
2026-09-02

**Date**: 2026-09-02  
**Status**: Superseded by [ADR-029](adr-029-recovery-code-generator-dependency-injection-abstraction.md)  
**Deciders**: EricksonLopez.Security Core Team

> [!NOTE]
> This ADR was superseded by [ADR-029](adr-029-recovery-code-generator-dependency-injection-abstraction.md) which reintroduced `IRecoveryCodeGenerator` as a mockable DI abstraction while retaining static helpers on `RecoveryCodeGenerator`.

---

## Context

During the comprehensive technical coherence audit, a discrepancy was identified in the MFA documentation:
- `docs/api-reference.md` documented an `IRecoveryCodeGenerator` interface with `GenerateCodes` and `VerifyCode(string, IEnumerable<string>)` methods.
- The actual implementation in `EricksonLopez.Security.Mfa` has always been `public static class RecoveryCodeGenerator` exposing only `GenerateCodes(int count = 10, int codeLength = 10)`.
- `docs/cookbook.md` attempted to resolve `RecoveryCodeGenerator` from `IServiceProvider`, causing runtime/compilation failures.

An architectural evaluation was conducted to determine whether to:
1. Introduce an `IRecoveryCodeGenerator` interface and register it in `services.AddSecurityMfa()`.
2. Formalize `RecoveryCodeGenerator` as a static utility class and correct all documentation and examples.

---

## Decision

### 1. Retain `RecoveryCodeGenerator` as a Static Utility
`RecoveryCodeGenerator` remains a **pure static utility class**:
- Cryptographic generation is stateless, thread-safe, and depends solely on `System.Security.Cryptography.RandomNumberGenerator`.
- Eliminates unnecessary object allocation, DI container registrations, and service resolution overhead.

### 2. Separation of Concerns: Generation vs. Verification
- **Generation**: `RecoveryCodeGenerator.GenerateCodes(...)` generates cryptographically random alphanumeric backup codes formatted in unambiguous Base32 chunks (`XXXX-XXXX-XX`).
- **Storage & Verification**: Recovery codes are single-use credentials. Storing and verifying them requires cryptographic hashing (`ITokenHasher` / `HmacSha256TokenHasher`) and atomic database invalidation upon consumption.
- Adding a `VerifyCode` method to a generator class violates the Single Responsibility Principle and encourages storing recovery codes in reversible or plaintext form. Verification belongs in the credential verification pipeline of the consumer application.

### 3. Documentation & Example Parity
- `docs/api-reference.md` is corrected to document `public static class RecoveryCodeGenerator`.
- `docs/cookbook.md` Recipe 5 is updated to call `RecoveryCodeGenerator.GenerateCodes(...)` directly without DI resolution.

---

## Consequences

- **Positive**:
  - Clean separation of concerns between code generation and stateful credential invalidation.
  - Zero GC allocations for service resolution; zero DI overhead.
  - 100% coherence across codebase, XML documentation, API reference, and cookbook examples.
- **Negative**:
  - Direct static invocation cannot be replaced with a mock interface in consumer tests (mitigated: code generation uses OS CSPRNG and requires no mocking in standard unit tests).

---

## References

- [ADR-001: Bounded Context, Responsibilities, and Package Strategy](./adr-001-bounded-context-and-package-strategy.md)
- [ADR-009: Non-Reversible Hashed Token and Structured API Key Storage](./adr-009-hashed-token-and-api-key-storage-pattern.md)
- RFC 6238: TOTP: Time-Based One-Time Password Algorithm
- NIST SP 800-63B: Section 5.1.4.1 (Backup Authentication Codes)
