# ADR-016: SAML 2.0 Profile Coverage Audit

## Status
Accepted

## Date
2026-09-01

**Date**: 2026-09-01  
**Status**: Accepted  
**Deciders**: EricksonLopez.Security Core Team

---

## Context

The competitive audit (`AUDITORIA_PARIDAD_FUNCIONAL.md`) flagged 4 SAML 2.0 capabilities as
`UNKNOWN` relative to direct competitors Sustainsys.Saml2 and ITfoxtec.Saml2:

1. **IdP-initiated SSO** — The IdP sends a `<samlp:Response>` without a prior `<samlp:AuthnRequest>`.
2. **Single Logout (SLO)** — Federated session termination via `<samlp:LogoutRequest>` / `<samlp:LogoutResponse>`.
3. **SP Metadata endpoint** — Publishing `<md:EntityDescriptor>` XML for IdP configuration.
4. **EncryptedAssertion** — Decryption of `<saml:EncryptedAssertion>` payloads.

This ADR documents the results of the internal audit of the 27 source files in
`EricksonLopez.Security.Saml2`, resolves each UNKNOWN to either IMPLEMENTED or GAP,
and defines the implementation decision.

---

## Audit Results

### Feature 1: SP-Initiated SSO — ✅ IMPLEMENTED

| Item | Status |
|---|---|
| `Saml2Service.CreateAuthnRequest()` | ✅ Fully implemented |
| HTTP-Redirect binding (Base64+Deflate) | ✅ Implemented |
| HTTP-POST binding | ✅ Implemented |
| NameID policy selection | ✅ Implemented |
| Optional request signing (`SpSigningCertificate`) | ✅ Implemented |
| `ProcessResponseAsync()` with `InResponseTo` correlation | ✅ Implemented |

### Feature 2: IdP-Initiated SSO — ❌ GAP (not implemented)

`ProcessResponseAsync()` accepts an optional `expectedInResponseTo` parameter but the
service does not have a dedicated `ProcessIdpInitiatedResponseAsync()` method that:

- Skips `InResponseTo` correlation (no prior AuthnRequest).
- Implements replay attack mitigation (assertion ID caching to prevent assertion reuse).
- Validates that `<samlp:Response>` does not contain an `InResponseTo` attribute.

**Decision**: Implement in v1.0.0. See NEXT-1.

### Feature 3: Single Logout (SLO) — ❌ GAP (not implemented)

No `LogoutRequest` generation, no `LogoutResponse` processing, no `LogoutResponse`
generation methods exist. `Saml2Options` has no `IdpSingleLogoutUrl` or
`SpSingleLogoutUrl` properties.

**Decision**: Implement in v1.0.0 together with IdP-initiated SSO. See NEXT-1.

### Feature 4: SP Metadata Endpoint — ❌ GAP (partial)

No `Saml2MetadataGenerator` or `EntityDescriptor` XML generation exists.
This blocks automated IdP configuration (e.g., Okta metadata import, Azure AD federation wizard).

**Decision**: Implement in v1.0.0 as part of the SLO + IdP-initiated work. The
`EntityDescriptor` must reflect `AssertionConsumerServiceUrl`, `SingleLogoutServiceUrl`,
`SpEntityId`, `SpSigningCertificate` public key, and `SpDecryptionCertificate` public key.

### Feature 5: EncryptedAssertion — ✅ IMPLEMENTED

| Item | Status |
|---|---|
| `ISaml2AssertionDecryptor` interface | ✅ Implemented |
| `Saml2AssertionDecryptor` — RSA-OAEP + AES-256 decryption | ✅ Implemented |
| Wired into `ProcessResponseAsync()` pipeline | ✅ Implemented |
| `SpDecryptionCertificate` option | ✅ Implemented |

---

## Decision

### v1.0.0 Implementation Scope for SAML

1. **IdP-initiated SSO** — New method `ProcessIdpInitiatedResponseAsync()` on `ISaml2Service` and `Saml2Service`. Assertion ID replay cache (in-memory with TTL matching assertion validity window). No `InResponseTo` requirement.

2. **Single Logout (SLO)** — New methods: `CreateLogoutRequest()`, `ProcessLogoutResponseAsync()`, `CreateLogoutResponse()`. New models: `Saml2LogoutRequest`, `Saml2LogoutResponse`. New `Saml2Options` properties: `IdpSingleLogoutUrl`, `SpSingleLogoutUrl`, `SignLogoutRequests`.

3. **SP Metadata endpoint** — New `Saml2MetadataGenerator.GenerateSpMetadata()` method returning `<md:EntityDescriptor>` XML. New model: `Saml2ServiceProviderMetadata`.

### Non-Implementation Decision

- **FIDO MDS3-equivalent for SAML (AuthnContext class verification)** — Not in scope. Edge case with low demand.
- **IdP Metadata parsing (Federation Metadata)** — Deferred. Manual certificate configuration via `IdpSigningCertificate` is sufficient for current use cases.

---

## Consequences

- **Positive**: Eliminates the SAML enterprise gap. Enables evaluation against Sustainsys in
  IdP-initiated + SLO scenarios. Compliance with ISO 27001 / SOC2 SLO requirements becomes achievable.
- **Negative**: IdP-initiated SSO without replay protection is a security anti-pattern; the
  in-memory assertion ID cache solves this but introduces a stateful dependency in the service.
  Distributed deployments must provide an `IAssertionIdCache` implementation backed by Redis or similar.

---

## References

- [ADR-001: Bounded Context and Package Strategy](./adr-001-bounded-context-and-package-strategy.md)
- [product-strategy.md §8 — NOW-4 and NEXT-1](../product-strategy.md)
- [Saml2Service.cs](../../src/EricksonLopez.Security.Saml2/Services/Saml2Service.cs)
- [SAML 2.0 Profiles Specification — OASIS](https://docs.oasis-open.org/security/saml/v2.0/saml-profiles-2.0-os.pdf)
- [SAML 2.0 Single Logout Profile](https://docs.oasis-open.org/security/saml/v2.0/saml-profiles-2.0-os.pdf#page=27)
