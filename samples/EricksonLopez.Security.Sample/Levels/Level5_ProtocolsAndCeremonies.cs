// Copyright © Erickson Lopez. MIT License.

using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using EricksonLopez.Security.Cryptography.XmlDSig;
using EricksonLopez.Security.Saml2.Claims;
using EricksonLopez.Security.Saml2.Cryptography;
using EricksonLopez.Security.Saml2.Models;
using EricksonLopez.Security.Saml2.Services;
using EricksonLopez.Security.Saml2.Xsw;
using EricksonLopez.Security.WebAuthn.Fido2.Abstractions;
using EricksonLopez.Security.WebAuthn.Fido2.Models;
using EricksonLopez.Security.WebAuthn.Fido2.Parsers;
using EricksonLopez.Security.WebAuthn.Fido2.Services;
using EricksonLopez.Security.WebAuthn.Fido2.Verifiers;
using Microsoft.Extensions.Options;
using System.Xml;

namespace EricksonLopez.Security.Sample.Levels;

/// <summary>
/// Level 5: Security Protocols & Authentication Ceremonies.
/// Demonstrates WebAuthn / FIDO2 Level 3 Passkeys registration and assertion options,
/// SAML 2.0 Service Provider AuthnRequest & SP metadata generation with XML Signature Wrapping (XSW) defense,
/// and W3C XML Digital Signatures (XmlDSig).
/// </summary>
public static class Level5_ProtocolsAndCeremonies
{
    public static void Run()
    {
        Console.WriteLine("\n================================================================================");
        Console.WriteLine("  LEVEL 5: SECURITY PROTOCOLS & AUTHENTICATION CEREMONIES");
        Console.WriteLine("================================================================================");

        // -------------------------------------------------------------------------
        // 1. WebAuthn / FIDO2 Level 3 Passkeys Ceremony
        // -------------------------------------------------------------------------
        Console.WriteLine("\n[1] WebAuthn / FIDO2 Level 3 Passkeys Ceremony Setup:");

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

        var regOptions = webAuthnService.CreateRegistrationOptions(userEntity);
        Console.WriteLine($"  -> WebAuthn Registration Ceremony Issued:");
        Console.WriteLine($"     RP: {regOptions.Rp.Name} ({regOptions.Rp.Id})");
        Console.WriteLine($"     User: {regOptions.User.DisplayName} ({regOptions.User.Name})");
        Console.WriteLine($"     Challenge Length: {regOptions.Challenge.Length} bytes");
        Console.WriteLine($"     Supported Algorithms Count: {regOptions.PubKeyCredParams.Count}");

        var authOptions = webAuthnService.CreateAuthenticationOptions();
        Console.WriteLine($"  -> WebAuthn Authentication (Assertion) Challenge Issued:");
        Console.WriteLine($"     Challenge: {Convert.ToHexString(authOptions.Challenge)[..16]}... (Length: {authOptions.Challenge.Length} bytes)");

        // -------------------------------------------------------------------------
        // 2. SAML 2.0 Service Provider (SP-Initiated SSO & Metadata)
        // -------------------------------------------------------------------------
        Console.WriteLine("\n[2] SAML 2.0 Web Browser SSO & Anti-XSW Service Provider:");

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

        var authnRequest = saml2Service.CreateAuthnRequest(relayState: "tenant_org_42");
        Console.WriteLine($"  -> SAML 2.0 AuthnRequest Generated:");
        Console.WriteLine($"     Request ID: {authnRequest.Id}");
        Console.WriteLine($"     Destination: {authnRequest.Destination}");
        Console.WriteLine($"     ACS URL: {authnRequest.AssertionConsumerServiceUrl}");
        Console.WriteLine($"     RelayState: {authnRequest.RelayState}");

        var spMetadata = saml2Service.GenerateSpMetadata();
        Console.WriteLine($"  -> SP EntityDescriptor Metadata XML Generated (Length: {spMetadata.Length} chars)");

        // -------------------------------------------------------------------------
        // 3. W3C XML Digital Signatures (XmlDSig)
        // -------------------------------------------------------------------------
        Console.WriteLine("\n[3] W3C XML Digital Signatures (XmlDSig) Signing & Verification:");

        using var rsaKey = RSA.Create(2048);
        var certRequest = new CertificateRequest("CN=EricksonLopez Fiscal Signer, O=EricksonLopez, C=US", rsaKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var signingCert = certRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(2));

        const string sampleXmlInvoice = "<Invoice Id=\"inv_2026_001\"><Amount Currency=\"USD\">50000.00</Amount><Customer>Acme Global</Customer></Invoice>";
        var xmlSigner = XmlDigitalSignatureService.Instance;
        IXmlDigitalSignatureVerifier verifier = xmlSigner;

        var signingOptions = new XmlSigningOptions { IncludeKeyInfo = true };
        var signResult = xmlSigner.SignXml(sampleXmlInvoice, signingCert, signingOptions);
        Console.WriteLine($"  -> XML Document Signed: {(signResult.IsSuccess ? "SUCCESS" : "FAILED")}");
        var signedXmlString = signResult.Value;

        // Verification with custom trust anchors via XmlVerificationOptions
        var verificationOptions = new XmlVerificationOptions
        {
            RequireTrustedCertificate = true,
            CustomTrustAnchors = { signingCert }
        };

        var verifyResult = verifier.VerifyXml(signedXmlString, signingCert, verificationOptions);
        Console.WriteLine($"  -> Cryptographic XML Signature Verification (IXmlDigitalSignatureVerifier): {(verifyResult.IsSuccess ? "VALID (Integrity Preserved)" : "INVALID")}");

        // Anti-XSW protection: Verify and extract signed element
        var xmlDoc = new XmlDocument { PreserveWhitespace = true };
        xmlDoc.LoadXml(signedXmlString);
        var extractResult = verifier.VerifyAndExtractSignedElement(xmlDoc, signingCert, verificationOptions);
        if (extractResult.IsSuccess)
        {
            var verifiedInfo = extractResult.Value;
            Console.WriteLine($"  -> Anti-XSW Verified Element: <{verifiedInfo.SignedElement?.LocalName}> (Ref: '{verifiedInfo.ReferenceUri}')");
            Console.WriteLine($"  -> Verified Signer: {verifiedInfo.SigningCertificate?.Subject}");
        }

        Console.WriteLine("--------------------------------------------------------------------------------");
    }
}
