# ADR-017: Satellite Repository Strategy

## Status
Accepted

## Date
2026-09-01

**Date**: 2026-09-01  
**Status**: Accepted  
**Deciders**: EricksonLopez.Security Core Team

---

## Context

`EricksonLopez.Security` has grown from 4 packages (v0.x) to 17 packages in v1.0.0.
The satellite packages span multiple distinct domains:

| Package | Domain |
|---|---|
| `EricksonLopez.Security.Abstractions` | Core primitives |
| `EricksonLopez.Security` | Core implementation |
| `EricksonLopez.Security.AspNetCore` | Web integration |
| `EricksonLopez.Security.Testing` | Test infrastructure |
| `EricksonLopez.Security.Azure` | Cloud KMS |
| `EricksonLopez.Security.Aws` | Cloud KMS |
| `EricksonLopez.Security.GoogleCloud` | Cloud KMS |
| `EricksonLopez.Security.HashiCorpVault` | Cloud KMS |
| `EricksonLopez.Security.Network` | Network security (SSRF) |
| `EricksonLopez.Security.Mfa` | Authentication factors |
| `EricksonLopez.Security.WebAuthn.Fido2` | Passkey / WebAuthn |
| `EricksonLopez.Security.WebAuthn.Fido2.Mds3` | FIDO Alliance Metadata Service v3 |
| `EricksonLopez.Security.Saml2` | Enterprise SSO |
| `EricksonLopez.Security.ZeroTrust` | Authorization |
| `EricksonLopez.Security.Pki` | Certificate management |
| `EricksonLopez.Security.Privacy.Hibp` | Privacy / breach detection |
| `EricksonLopez.Security.Cryptography` | Extended crypto |
| `EricksonLopez.Security.Cryptography.Pkcs11` | HSM interop |
| `EricksonLopez.Security.Cryptography.XmlDSig` | XML crypto |
| `EricksonLopez.Security.OpenTelemetry` | Distributed tracing and metrics |
| `EricksonLopez.Security.Analyzers` | Roslyn diagnostic analyzers |

The question is whether this growth creates a perception of "monolith" that harms
discoverability, maintainability, and product positioning. Some packages (`ZeroTrust`, `Privacy.Hibp`)
have bounded contexts that could stand on their own.

---

## Decision

### Principle: Stay Together Until Forced Apart

**Verdict: Maintain all 21 packages in the current monorepo through v1.2.0.**

The marginal cost of staying together is low (shared CI, shared Directory.Build.props, shared `EricksonLopez.snk`).
The marginal cost of separation is high (separate repo setup, separate release pipelines, separate NuGet publishing, cross-repo version coordination, breaking discoverability for users who `dotnet add package EricksonLopez.Security.X`).

The "monolith perception" risk is mitigated by:
- Clear package-level README files.
- NuGet package descriptions that explain the satellite's scope.
- The `docs/architecture.md` dependency graph showing bounded contexts within the monorepo.

### Evaluation Matrix for Future Separation

A package should be **extracted to its own repository** only when ALL of:

1. It has an independent release cadence (different semver major than the core).
2. It has external contributors who only contribute to that package (indicating independent community).
3. Its domain abstraction diverges: it no longer shares `IKeyStore` / `ISecretStore` contracts with core.
4. Its NuGet download volume is ≥ 30% of the core package, indicating standalone adoption.

### Specific Package Decisions

| Package | Decision | Rationale |
|---|---|---|
| `EricksonLopez.Security.ZeroTrust` | **Stay** (v1.x) / **Evaluate extraction as `EricksonLopez.Authorization` in v2.0** | Domain is adjacent (authorization vs. cryptography). If ABAC grows independently of the crypto core, separation makes sense. |
| `EricksonLopez.Security.Privacy.Hibp` | **Stay** (v1.x) / **Evaluate extraction as `EricksonLopez.Privacy` in v2.0** | HIBP is a privacy concern, not a cryptographic one. It depends only on `HttpClient` and SHA-1, not on IKeyStore. A clear separation candidate but premature now. |
| `EricksonLopez.Security.Cryptography.Pkcs11` | **Stay** (v1.x) / **Group with XmlDSig under `EricksonLopez.Security.Enterprise` namespace** | Enterprise-only concerns with specialized HSM hardware. Grouping them reduces repository fragmentation. |
| `EricksonLopez.Security.Cryptography.XmlDSig` | **Stay** — same decision as Pkcs11. | — |
| `EricksonLopez.Security.Network` | **Stay permanently** | It's a Tier 0 safety primitive (SSRF prevention). Separating it would reduce discoverability of a security-critical component. |
| `EricksonLopez.Security.Saml2` | **Stay permanently** | SAML 2.0 depends on `ISaml2SignatureValidator` → `EricksonLopez.Security.Cryptography.XmlDSig`. Tight coupling with the crypto layer. |

### Namespace Convention

If packages are extracted in the future, the following conventions apply:

- Authorization-domain packages: `EricksonLopez.Authorization.*`
- Privacy-domain packages: `EricksonLopez.Privacy.*`
- Enterprise crypto packages: `EricksonLopez.Security.Enterprise.*`
- Core security packages: `EricksonLopez.Security.*` (current, maintained)

### Version Compatibility Invariant

All packages in `EricksonLopez.Security.*` must maintain the same major version number
as `EricksonLopez.Security.Abstractions`. This ensures consumers can safely install
any combination of satellites without assembly binding conflicts.

---

## Consequences

- **Positive**: Reduced CI/CD complexity through v1.x. Single source of truth for ADRs, tests, and architectural guides. Shared `Directory.Build.props` enforces quality invariants (AOT, nullable, warnings-as-errors) uniformly.
- **Negative**: Repository size grows. Contributors cannot granularly watch only the package they care about via GitHub notifications. This is acceptable until community size warrants the investment.
- **Trigger for re-evaluation**: If the repo grows to > 25 packages or any single satellite consistently receives > 3x more issues than the core, reconvene this decision.

---

## References

- [product-strategy.md §8 — NEXT-3 and LATER-2](../product-strategy.md)
- [ADR-001: Bounded Context and Package Strategy](./adr-001-bounded-context-and-package-strategy.md)
- [docs/architecture.md](../architecture.md)
