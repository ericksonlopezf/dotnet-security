# Level 05: Protocols & Authentication Ceremonies

> **Showcase Level**: Level 5  
> **Source Code**: [`samples/EricksonLopez.Security.Sample/Levels/Level5_ProtocolsAndCeremonies.cs`](../../samples/EricksonLopez.Security.Sample/Levels/Level5_ProtocolsAndCeremonies.cs)  
> **Packages**: `EricksonLopez.Security.WebAuthn.Fido2`, `EricksonLopez.Security.Saml2`, `EricksonLopez.Security.Cryptography.XmlDSig`

---

## 1. Overview & Architectural Role

Level 5 demonstrates enterprise identity protocols and cryptographic authentication ceremonies:
- **WebAuthn / FIDO2 Level 3 Passkeys**: Cryptographic passkey registration and assertion ceremonies with CBOR/COSE parsing and attestation verifiers.
- **SAML 2.0 Service Provider (SP)**: SP-initiated Web Browser SSO, signed AuthnRequest generation, assertion decryption, and signature validation with native XML Signature Wrapping (XSW) defenses.
- **W3C XML Digital Signatures (XmlDSig)**: Enveloped and enveloping signature creation and cryptographic verification conforming to RFC 3275.

---

## 2. WebAuthn / FIDO2 Level 3 Passkeys Ceremony

### Registration Ceremony Setup

```csharp
using System.Text;
using EricksonLopez.Security.WebAuthn.Fido2.Abstractions;
using EricksonLopez.Security.WebAuthn.Fido2.Models;
using EricksonLopez.Security.WebAuthn.Fido2.Parsers;
using EricksonLopez.Security.WebAuthn.Fido2.Services;
using EricksonLopez.Security.WebAuthn.Fido2.Verifiers;
using Microsoft.Extensions.Options;

var webAuthnOptions = Options.Create(new WebAuthnOptions
{
    RpId = "identity.ericksonlopez.dev",
    RpName = "EricksonLopez Enterprise Identity",
    AllowedOrigins = { "https://identity.ericksonlopez.dev" }
});

var authDataParser = new AuthenticatorDataParser(new CoseKeyParser());
var attestationVerifiers = new IAttestationVerifier[]
{
    new NoneAttestationVerifier(),
    new PackedAttestationVerifier()
};

var webAuthnService = new WebAuthnCeremonyService(webAuthnOptions, authDataParser, attestationVerifiers);

var userEntity = new PublicKeyCredentialUserEntity(
    id: Encoding.UTF8.GetBytes("usr_fintech_cfo_001"),
    name: "cfo@enterprise.com",
    displayName: "Chief Financial Officer");

// Issue challenge for navigator.credentials.create()
var regOptions = webAuthnService.CreateRegistrationOptions(userEntity);

// Issue challenge for navigator.credentials.get()
var authOptions = webAuthnService.CreateAuthenticationOptions();
```

---

## 3. SAML 2.0 Service Provider (Anti-XSW SSO)

SAML 2.0 implementations frequently suffer from XML Signature Wrapping (XSW) attacks. `EricksonLopez.Security.Saml2` includes a dedicated `Saml2XswValidator` that inspects the DOM tree before verifying cryptographic signatures:

```csharp
using EricksonLopez.Security.Saml2.Claims;
using EricksonLopez.Security.Saml2.Cryptography;
using EricksonLopez.Security.Saml2.Models;
using EricksonLopez.Security.Saml2.Services;
using EricksonLopez.Security.Saml2.Xsw;
using Microsoft.Extensions.Options;

var samlOptions = Options.Create(new Saml2Options
{
    SpEntityId = "https://sp.ericksonlopez.dev/saml2/metadata",
    AssertionConsumerServiceUrl = "https://sp.ericksonlopez.dev/saml2/acs",
    IdpEntityId = "https://idp.okta.com/app/saml2/exk12345",
    IdpSingleSignOnUrl = "https://idp.okta.com/app/saml2/sso"
});

var xswValidator = new Saml2XswValidator();
var sigValidator = new Saml2SignatureValidator();
var decryptor = new Saml2AssertionDecryptor();
var claimsMapper = new Saml2ClaimsMapper();

var saml2Service = new Saml2Service(samlOptions, xswValidator, sigValidator, decryptor, claimsMapper);

// Generate SP-initiated AuthnRequest
var authnRequest = saml2Service.CreateAuthnRequest(relayState: "tenant_org_42");

// Generate SP Metadata XML
string spMetadataXml = saml2Service.GenerateMetadata();
```

---

## 4. W3C XML Digital Signatures (`XmlDSig`)

Signing and verifying XML payloads using RFC 3275 enveloped signatures:

```csharp
using System.Security.Cryptography.X509Certificates;
using EricksonLopez.Security.Cryptography.XmlDSig;

// XmlDigitalSignatureService supports RSA-SHA256, RSA-SHA512, and ECDSA-SHA256
var xmlSigService = new XmlDigitalSignatureService();

const string unsignedXml = "<Invoice Id=\"inv-2026-001\"><Amount Currency=\"USD\">50000.00</Amount></Invoice>";

// Signing produces a verified enveloped <ds:Signature> node
// Verification guarantees canonicalization and digest integrity

using System.Xml;
using EricksonLopez.Security.Cryptography.XmlDSig;

IXmlDigitalSignatureVerifier verifier = XmlDigitalSignatureService.Instance;

var xmlDoc = new XmlDocument { PreserveWhitespace = true };
xmlDoc.LoadXml(unsignedXml);

var verOptions = new XmlVerificationOptions();
// verOptions.CustomTrustAnchors.Add(trustedCert);

XmlVerificationResult vResult = verifier.VerifyAndExtractSignedElement(xmlDoc, verOptions);
// vResult.IsValid indicates whether signature cryptographic checks and XSW validations passed
```
