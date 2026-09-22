# ADR-015: Reject JWT Issuance, OAuth2 / OIDC Server Scope

## Status
Accepted — Decision to reject JWT issuance and OAuth2/OIDC server scope from EricksonLopez.Security

## Date
2026-09-01

**Deciders**: EricksonLopez.Security Core Team

---

## Context

Several security library evaluations and community comparisons have suggested adding:

1. **JWT (JSON Web Token) issuance and validation** — `JwtSecurityTokenHandler`-equivalent functionality for generating and validating JWTs signed with RSA/ECDSA.
2. **OAuth 2.0 / OpenID Connect server** — Authorization Code, Client Credentials, and PKCE grant flows; token endpoint; discovery document.

These features appear adjacent to the library's cryptographic and identity primitives. The question was formally evaluated against the bounded context defined in ADR-001.

---

## Decision

### JWT Issuance / Validation — **Permanently Rejected**

EricksonLopez.Security will **not** implement JWT token issuance or validation.

**Justification**:

1. **Mature alternatives exist** — `Microsoft.IdentityModel.Tokens` (maintained by Microsoft Identity team), `System.IdentityModel.Tokens.Jwt`, and `Microsoft.AspNetCore.Authentication.JwtBearer` are battle-tested, broadly audited, and NuGet-shipped with ASP.NET Core. Duplicating this functionality adds no net safety for the ecosystem.

2. **Different job-to-be-done** — EricksonLopez.Security is a **security primitive layer** (opaque tokens, API keys, envelope encryption, key management). JWT is a **token format** with semantic meaning (claims, audiences, issuers). These are different responsibilities.

3. **API bloat risk** — Adding JWT parsing surface introduces a significant new attack surface (algorithm confusion attacks `none`/`RS256`/`HS256`, `kid` injection, header manipulation). The library's core invariant is "impossible to do it wrong." JWT's historical CVE surface (CVE-2018-1000531, CVE-2022-21449 "Psychic Signatures") is a concrete counter-evidence to maintaining that invariant.

4. **Scope clarity** — Users who need JWT should use the established Microsoft libraries. Users who use EricksonLopez.Security for opaque tokens + API keys do not need JWT. Serving both use cases in one package dilutes the focused bounded context.

### OAuth2 / OIDC Server — **Permanently Rejected**

EricksonLopez.Security will **not** implement an OAuth 2.0 or OpenID Connect authorization server.

**Justification**:

1. **Completely different product scope** — An OAuth2/OIDC server is an Identity Provider (IdP), not a security primitive library. It requires: token endpoint, authorization endpoint, discovery document, client registration, session management, refresh token rotation, and a persistence layer. This is a multi-year, dedicated product effort — not a feature of a crypto primitives library.

2. **Established alternatives** — [OpenIddict](https://documentation.openiddict.com) and [Duende IdentityServer](https://duendesoftware.com) have years of security auditing, compliance certifications (FAPI 1.0, FAPI 2.0), and community. Building a competing solution would be reinventing the wheel at significant security risk.

3. **ADR-001 boundary** — ADR-001 explicitly lists "OAuth/OpenID server" as a non-goal. This ADR reinforces that decision with explicit competitive analysis.

### Reference Update to ADR-001

ADR-001 Section "Explicit Non-Goals" should be cross-referenced to this ADR for traceability.

---

## Consequences

- **Positive**: Focused bounded context. Team bandwidth is preserved for differentiating features (PQC, SSRF, memory safety, AOT, migration documentation). No JWT CVE surface introduced.
- **Negative**: Users who want JWT must integrate `Microsoft.IdentityModel.Tokens` separately. EricksonLopez.Security is not positioned as a one-stop-shop for all authentication needs — this is intentional.

---

## References

- [ADR-001: Bounded Context and Package Strategy](./adr-001-bounded-context-and-package-strategy.md)
- [product-strategy.md §9 — What NOT to Build](../product-strategy.md)
- [CVE-2022-21449 — Java ECDSA "Psychic Signatures"](https://neilmadden.blog/2022/04/19/psychic-signatures-in-java/)
- [OpenIddict](https://documentation.openiddict.com) — Recommended alternative for OAuth2/OIDC server needs.
- [Duende IdentityServer](https://duendesoftware.com) — Enterprise alternative for OIDC server needs.
