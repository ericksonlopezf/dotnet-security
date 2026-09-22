# ADR-019: OpenTelemetry Observability Satellite Strategy

## Status
Accepted

## Date
2026-09-01

**Date**: 2026-09-01  
**Status**: Accepted  
**Deciders**: EricksonLopez.Security Core Team

---

## Context

Enterprise teams that adopt `EricksonLopez.Security` need observability into security operations:

- **Latency** — How long do KMS calls take? Is Argon2id adding latency spikes?
- **Key lifecycle events** — How often are keys being rotated? Are there unexpected revocations?
- **Authentication signals** — How many failed API key validations occur per minute?
- **Encryption volume** — How many encrypt/decrypt operations per service instance?

Currently, none of this is instrumented. The library is a black box from an observability standpoint.
Competitors do not offer this either — making it a genuine differentiator if implemented.

However, introducing OpenTelemetry (OTel) into the core packages would violate two critical invariants:
1. **`EricksonLopez.Security.Abstractions` must be zero-dependency** (ADR-001).
2. **`EricksonLopez.Security` core must minimize transitive dependencies** to maintain AOT compatibility and portability.

---

## Decision

### Architecture: Optional Satellite Package

Introduce a new optional NuGet package: **`EricksonLopez.Security.OpenTelemetry`**.

#### Invariants (Non-Negotiable)

1. **OTel SDK NEVER enters `Abstractions` or `Core`** — The `OpenTelemetry`, `OpenTelemetry.Api`, and `System.Diagnostics.DiagnosticSource` packages are dependencies of `EricksonLopez.Security.OpenTelemetry` ONLY.
2. **Core uses `System.Diagnostics.Activity` source pattern** — The core package publishes `ActivitySource` named `"EricksonLopez.Security"` for opt-in tracing. This uses the zero-dependency BCL `System.Diagnostics.DiagnosticSource` which is inbox in .NET 5+. No OTel reference needed in core.
3. **The satellite is strictly additive** — Adding or removing the OTel package does not change any behavior in the core. It only subscribes to the `ActivitySource` and `Meter` events emitted by core.

#### Instrumentation Plan

| Signal | Instrument | Operation |
|---|---|---|
| Trace span | `Activity` | `Encrypt`, `Decrypt`, `ProtectSecret`, `UnprotectSecret` |
| Trace span | `Activity` | `HashPassword`, `VerifyPassword` |
| Trace span | `Activity` | `WrapKey`, `UnwrapKey`, `KmsEncrypt`, `KmsDecrypt` (cloud adapters) |
| Counter | `ObservableCounter<long>` | `security.key.rotations_total` |
| Counter | `ObservableCounter<long>` | `security.key.revocations_total` |
| Counter | `Counter<long>` | `security.apikey.validations_total{result=success\|failure}` |
| Counter | `Counter<long>` | `security.password.verifications_total{result=success\|rehash_needed\|failure}` |
| Histogram | `Histogram<double>` | `security.argon2id.hashing_duration_ms` |
| Histogram | `Histogram<double>` | `security.kms.operation_duration_ms{provider=azure\|aws\|hashicorp}` |

#### Attribute Conventions (OTEL Semantic Conventions)

- `security.algorithm` — e.g., `aes-256-gcm`, `argon2id`, `ml-kem-768`
- `security.key.purpose` — e.g., `SecretProtection`, `TokenSigning`
- `security.key.version` — key version integer
- `error.type` — `SecurityError` discriminant on failure spans

#### DI Registration

```csharp
// services.AddOpenTelemetry() — existing user code
builder.Services.AddOpenTelemetry()
    .WithTracing(t => t.AddEricksonLopezSecurityInstrumentation())
    .WithMetrics(m => m.AddEricksonLopezSecurityMetrics());
```

#### ActivitySource Naming Convention in Core

The core package will add (in a future minor update):

```csharp
internal static readonly ActivitySource SecurityActivitySource =
    new("EricksonLopez.Security", "1.0.0");
```

This is a zero-dependency addition using BCL types. OTel SDK subscribes to this source only when the satellite package is registered.

---

## Timeline

**LATER-1 (Target: H1 2027)**. This feature is low-urgency because:
- No competitor offers it (no catch-up pressure).
- Core instrumentation additions (ActivitySource/Meter) require minor version bumps.
- The team bandwidth in NOW and NEXT is allocated to documentation and SAML/WebAuthn parity.

**Prerequisite gate**: All NOW-phase items (documentation, migration guides, samples) must be shipped before any LATER investment begins.

---

## Consequences

- **Positive**: Becomes the only .NET security library with first-class OTel observability. Highly attractive to enterprise teams already invested in OTel (Jaeger, Tempo, Datadog, Honeycomb). Zero impact on core if not installed.
- **Negative**: Adds a new package to maintain. If `System.Diagnostics.ActivitySource` API surface changes (unlikely), minor updates to core are required. Teams not using OTel see no benefit from this investment.

---

## References

- [ADR-001: Bounded Context and Package Strategy](./adr-001-bounded-context-and-package-strategy.md)
- [product-strategy.md §8 — LATER-1](../product-strategy.md)
- [OpenTelemetry .NET SDK](https://github.com/open-telemetry/opentelemetry-dotnet)
- [OpenTelemetry Semantic Conventions for Security](https://opentelemetry.io/docs/specs/semconv/)
- [System.Diagnostics.ActivitySource — BCL](https://learn.microsoft.com/en-us/dotnet/api/system.diagnostics.activitysource)
