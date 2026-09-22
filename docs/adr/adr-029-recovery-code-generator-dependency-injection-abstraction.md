# ADR-029: Recovery Code Generator Dependency Injection Abstraction

## Status
Accepted

## Date
2026-09-07

**Date**: 2026-09-07  
**Status**: Accepted  
**Deciders**: EricksonLopez.Security Core Team

---

## Context

In [ADR-026](./adr-026-recovery-code-generator-static-utility-design.md), `RecoveryCodeGenerator` was formalized as a high-performance, stateless static utility class. This eliminated service resolution allocations in cryptographic hotpaths.

However, subsequent consumer feedback and security audit reviews (finding AUTH-010) identified practical friction points:
1. **Inversion of Control (IoC) & Unit Testing**: Application services relying on dependency injection patterns required a mockable abstraction (`IRecoveryCodeGenerator`) to test MFA onboarding and recovery flows without generating pseudo-random values during test setup.
2. **Contract Consistency**: Other MFA capabilities in `EricksonLopez.Security.Mfa` (such as `ITotpService`) provide injectable interfaces.

---

## Decision

### 1. Introduce `IRecoveryCodeGenerator` Interface
Introduce the `IRecoveryCodeGenerator` contract in `EricksonLopez.Security.Mfa`:
```csharp
namespace EricksonLopez.Security.Mfa;

public interface IRecoveryCodeGenerator
{
    string[] GenerateCodes(int count = 10, int codeLength = 10);
}
```

### 2. Dual Support: Injectable Service & Static Verification Utilities
- **Injectable Instance & Class**: `public sealed class RecoveryCodeGenerator : IRecoveryCodeGenerator` implements `GenerateCodes(count, codeLength)` as an instance method, registered as a Singleton in `services.AddSecurityMfa()`. Consumers may also instantiate it directly (`new RecoveryCodeGenerator()`).
- **Static Verification Utilities**: Retain static helper methods `RecoveryCodeGenerator.HashCode(plaintextCode)` and `RecoveryCodeGenerator.VerifyCode(plaintextCode, storedHash)` for high-performance, constant-time verification without service resolution overhead.

### 3. Cryptographic Storage & Single-Use Enforcement
- Generation produces formatted, high-entropy alphanumeric strings (e.g., `XXXX-XXXX-XXXX`).
- Storage in consumer persistence must always store salted/keyed cryptographic hashes (`HmacSha256TokenHasher` or SHA-256).
- Verification enforces atomic invalidation upon successful redemption to prevent code reuse.

---

## Consequences

- **Positive**:
  - Full DI compatibility for Clean Architecture and domain service layers.
  - Zero breaking changes for existing consumers utilizing static utility methods.
  - Seamless mocking and deterministic test fixtures in application test suites.
- **Negative**:
  - Small addition to the public API surface in `EricksonLopez.Security.Mfa`.

---

## References

- [ADR-026: RecoveryCodeGenerator Static Utility Architecture and API Design](./adr-026-recovery-code-generator-static-utility-design.md)
- Security Audit Remediation — Finding AUTH-010 (Recovery Code DI Abstraction)
- NIST SP 800-63B §5.1.4.1 (Backup Authentication Codes)
