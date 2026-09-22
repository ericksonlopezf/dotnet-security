# ADR-028: XML Signature Wrapping (XSW) Defense and Certificate Trust Validation

## Status
Accepted

## Date
2026-09-07

**Date**: 2026-09-07  
**Status**: Accepted  
**Deciders**: EricksonLopez.Security Core Team

---

## Context

During the security audit (`MEGA-AUDITORIA`), two critical security findings were identified in `EricksonLopez.Security.Cryptography.XmlDSig`:

1. **Certificate Validation Bypass (XML-007)**: When an XML signature includes an embedded `<KeyInfo>` X.509 certificate, validating signatures without strictly evaluating the certificate's trust chain allows an attacker to generate a self-signed certificate, sign a manipulated payload, embed their public key/certificate, and achieve successful signature verification.
2. **XML Signature Wrapping (XSW) Attacks**: Traditional verification methods return only a boolean verdict (`bool IsValid`). When an XML payload contains multiple duplicate elements (e.g. an authentic signed assertion alongside a malicious unsigned assertion placed elsewhere in the DOM tree), application logic querying the DOM via XPath or tag name can inadvertently process the untrusted payload rather than the element that was cryptographically signed.

---

## Decision

### 1. Introduce `XmlVerificationOptions` with Secure Defaults
- **`RequireTrustedCertificate`**: Defaults to `true`. Embedded certificates in `<KeyInfo>` must validate against system trust stores or custom trust anchors.
- **`CustomTrustAnchors`**: Allows specifying private enterprise Root/Intermediate CA certificates without installing them into the OS machine store.
- **`CertificateTrustEvaluator`**: Provides a custom predicate (`Func<X509Certificate2, bool>`) for fine-grained PKI validation rules.
- **Deprecate `AllowUntrustedEmbeddedCertificate`**: Marked with `[Obsolete]` and explicit security warnings. Restricts its use to isolated unit testing against mocked self-signed XML payloads; prohibited in production deployments.

### 2. Introduce `XmlVerificationResult` with Signed Element Binding
To neutralize XML Signature Wrapping (anti-XSW), verification routines must return the verified node:
- **`SignedElement`**: Exposes the exact `XmlElement` that matched the cryptographic digest in `<SignedInfo>`.
- **`ReferenceUri`**: Exposes the verified reference URI (e.g., `""` or `"#elementId"`).
- **`SigningCertificate`**: Exposes the verified X.509 certificate.
- **Consumer Mandate**: Applications must extract and process attributes exclusively from `SignedElement` rather than querying the root XML document.

---

## Consequences

- **Positive**:
  - Eliminates arbitrary signature forgery via untrusted embedded certificates.
  - Prevents XML Signature Wrapping (XSW) vulnerabilities by binding application processing to the cryptographically verified element.
  - Enterprise PKI trust configuration is fully supported without OS store mutation.
- **Negative**:
  - Consumers must update call sites to inspect `XmlVerificationResult.SignedElement` rather than relying solely on boolean verification return values.

---

## References

- W3C XML Signature Syntax and Processing (Second Edition) — RFC 3275
- OWASP XML Security Cheat Sheet — XML Signature Wrapping Attacks
- Security Audit Remediation — Finding XML-007 (Certificate Trust & XSW Vulnerability)
- [ADR-016: SAML 2.0 Profile Coverage Audit](./adr-016-saml2-profile-coverage-audit.md)
