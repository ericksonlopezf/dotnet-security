# ADR-021: Full Implementation — FIDO MDS3, FIDO-U2F, Roslyn Analyzers, SAML SP Metadata

## Status
Accepted

## Date
2026-09-01

**Date**: 2026-09-01  
**Status**: Accepted — Implemented  
**Deciders**: EricksonLopez.Security Core Team

---

## Context

All opportunities from the `product-strategy.md` Opportunity Map have been implemented in v1.0.0, resolving all previously deferred capabilities in the roadmap.

---

## Implemented Features

### FIDO-U2F Attestation Verifier

**Package**: `EricksonLopez.Security.WebAuthn.Fido2`  
**File**: `Verifiers/FidoU2FAttestationVerifier.cs`

Implements `IAttestationVerifier` with `Format = "fido-u2f"` per W3C WebAuthn Level 2 §8.6:
1. Validates `sig` and `x5c` are present (no self-attestation in U2F format).
2. Verifies the credential public key is EC P-256 (COSE `kty=2`, `crv=1`).
3. Constructs the uncompressed 65-byte public key point (`0x04 || x || y`).
4. Validates the attestation certificate uses P-256 (OID `1.2.840.10045.3.1.7`).
5. Constructs `verificationData`: `0x00 || rpIdHash || clientDataHash || credentialId || publicKeyU2F`.
6. Verifies the ECDSA-SHA256 signature over `verificationData`.

**DI**: Registered automatically via `AddWebAuthnFido2()` (alongside None, Packed, SafetyNet, TPM).

---

### FIDO Alliance MDS3 Metadata Service

**Package**: `EricksonLopez.Security.WebAuthn.Fido2.Mds3` (new satellite)  
**Files**: `IMds3MetadataService.cs`, `HttpMds3MetadataService.cs`, `Mds3Options.cs`, `AuthenticatorMetadata.cs`, `Mds3ServiceCollectionExtensions.cs`

- Downloads the FIDO Alliance MDS3 JWT BLOB from `https://mds3.fidoalliance.org/`.
- Parses entries indexed by AAGUID (FIDO-U2F entries with `KeyIdentifier` are handled appropriately).
- Caches for 24 hours (configurable).
- `ValidateAuthenticatorStatusAsync()` rejects authenticators with `REVOKED`, `ATTESTATION_KEY_COMPROMISE`, etc.
- `AllowUnknownAuthenticators = true` by default for backward-compatible deployment.
- DI: `services.AddFidoMds3(opts => ...)`.

---

### SAML 2.0 SP Metadata Generation

**Package**: `EricksonLopez.Security.Saml2`  
**Method**: `ISaml2Service.GenerateSpMetadata()` $\rightarrow$ implemented in `Saml2Service`

Generates standards-compliant `<md:EntityDescriptor>` XML per SAML 2.0 Metadata Specification:
- `<md:SPSSODescriptor>` with `AuthnRequestsSigned` and `WantAssertionsSigned` attributes.
- `<md:KeyDescriptor use="signing">` / `use="encryption"` with X.509 certificate data (if configured).
- `<md:SingleLogoutService>` for HTTP-POST and HTTP-Redirect bindings (if SLO URL configured).
- `<md:NameIDFormat>` derived from `Saml2Options.DefaultNameIdFormat`.
- `<md:AssertionConsumerService>` with HTTP-POST binding (`index=1`, `isDefault=true`).

---

### Roslyn Analyzers

**Package**: `EricksonLopez.Security.Analyzers` (satellite, targets `netstandard2.0`)  
**Analyzers**:

| ID | Severity | Rule |
|---|---|---|
| `ELS0001` | Warning | Non-constant-time comparison of security-sensitive `byte[]` or string values |
| `ELS0002` | Warning | `SecretBuffer` created without `using` (`ZeroMemory` never called) |
| `ELS0003` | Warning | Hardcoded string literal assigned to sensitive-named variable (`password`, `secret`, `key`, etc.) |
| `ELS0004` | Error | Insecure algorithm (MD5/SHA1/SHA256) used in password hashing context |
| `ELS0005` | Warning | Security-sensitive value passed to `ILogger` without `Redacted<T>` wrapping |

**Distribution**: Installed as a build-time analyzer (`DevelopmentDependency=true`). Does not add runtime dependencies. Packaged in `analyzers/dotnet/cs/` NuGet path.

---

## Consequences

- **Positive**: Roadmap is fully implemented. Zero deferred items. Every opportunity map entry is addressed.
- **FIDO-U2F Note**: Although CTAP1/U2F is deprecated, the verifier supports legacy hardware keys that consumers may still have in the field. The implementation is correct per spec.
- **MDS3 Note**: The MDS3 satellite introduces an HTTP dependency. Deploy with `AllowUnknownAuthenticators=false` only in environments where all expected authenticator models are confirmed to be in the FIDO Alliance MDS3.

---

## References

- [W3C WebAuthn Level 2 §8.6 (FIDO-U2F attestation)](https://www.w3.org/TR/webauthn-2/#sctn-fido-u2f-attestation)
- [FIDO Alliance MDS3](https://fidoalliance.org/metadata/)
- [SAML 2.0 Metadata Specification](https://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf)
- [Roslyn Analyzer Tutorial](https://learn.microsoft.com/en-us/dotnet/csharp/roslyn-sdk/tutorials/how-to-write-csharp-analyzer-code-fix)
- [product-strategy.md](../product-strategy.md)
