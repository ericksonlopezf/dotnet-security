// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Saml2.Tests;

using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;
using AwesomeAssertions;
using EricksonLopez.Security.Saml2.Cryptography;
using Xunit;

public sealed class Saml2SignatureValidatorTests
{
    private readonly Saml2SignatureValidator _validator = new();

    [Fact]
    public void SignElement_And_VerifySignature_Success()
    {
        using var rsa = RSA.Create(2048);
        var certReq = new CertificateRequest("CN=SamlSigningTest", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var certWithKey = certReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddYears(1));
#if NET9_0_OR_GREATER
        var certPub = X509CertificateLoader.LoadCertificate(certWithKey.Export(X509ContentType.Cert));
#else
        var certPub = new X509Certificate2(certWithKey.Export(X509ContentType.Cert));
#endif

        var xml = @"<samlp:AuthnRequest xmlns:samlp=""urn:oasis:names:tc:SAML:2.0:protocol"" xmlns:saml=""urn:oasis:names:tc:SAML:2.0:assertion"" ID=""_req123"" Version=""2.0"">
  <saml:Issuer>https://sp.example.com</saml:Issuer>
</samlp:AuthnRequest>";

        var doc = new XmlDocument { XmlResolver = null, PreserveWhitespace = true };
        doc.LoadXml(xml);

        var signResult = _validator.SignElement(doc.DocumentElement!, certWithKey);
        signResult.IsSuccess.Should().BeTrue();

        doc.OuterXml.Should().Contain("<Signature");
        doc.OuterXml.Should().Contain(SignedXml.XmlDsigExcC14NTransformUrl);
        doc.OuterXml.Should().Contain(SignedXml.XmlDsigRSASHA256Url);
        doc.OuterXml.Should().Contain("<KeyInfo");
        doc.OuterXml.Should().Contain("<X509Data");
        doc.OuterXml.Should().Contain("<X509Certificate");
        doc.OuterXml.Should().Contain("http://www.w3.org/2001/10/xml-exc-c14n#");

        var ns = new XmlNamespaceManager(doc.NameTable);
        ns.AddNamespace("ds", "http://www.w3.org/2000/09/xmldsig#");
        var transformNodes = doc.SelectNodes("//ds:Reference/ds:Transforms/ds:Transform[@Algorithm='http://www.w3.org/2001/10/xml-exc-c14n#']", ns);
        transformNodes.Should().NotBeNull();
        transformNodes!.Count.Should().Be(1);

        var verifyResult = _validator.VerifySignature(doc.DocumentElement!, certPub);
        verifyResult.IsSuccess.Should().BeTrue();
    }

    [Fact]
    public void VerifySignature_LowercaseIdAttributeMismatch_ReturnsMismatch()
    {
        using var rsa = RSA.Create(2048);
        var certReq = new CertificateRequest("CN=SamlSigningTest", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var certWithKey = certReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddYears(1));

        var xml = @"<samlp:AuthnRequest xmlns:samlp=""urn:oasis:names:tc:SAML:2.0:protocol"" ID=""_initial_id"" Version=""2.0""/>";
        var doc = new XmlDocument { XmlResolver = null, PreserveWhitespace = true };
        doc.LoadXml(xml);

        _validator.SignElement(doc.DocumentElement!, certWithKey);

        // Remove uppercase ID and assign lowercase id with mismatched value
        doc.DocumentElement!.RemoveAttribute("ID");
        doc.DocumentElement!.SetAttribute("id", "_mismatched_lower_id");

        var verifyResult = _validator.VerifySignature(doc.DocumentElement!, certWithKey);
        verifyResult.IsFailure.Should().BeTrue();
        verifyResult.Error.Description.Should().Contain("does not match element ID '_mismatched_lower_id'");
    }


    [Fact]
    public void SignElement_WithoutExistingId_AutoGeneratesIdAndSigns()
    {
        using var rsa = RSA.Create(2048);
        var certReq = new CertificateRequest("CN=SamlSigningTest", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var certWithKey = certReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddYears(1));

        var xml = @"<samlp:AuthnRequest xmlns:samlp=""urn:oasis:names:tc:SAML:2.0:protocol"" Version=""2.0""/>";
        var doc = new XmlDocument { XmlResolver = null, PreserveWhitespace = true };
        doc.LoadXml(xml);

        var signResult = _validator.SignElement(doc.DocumentElement!, certWithKey);
        signResult.IsSuccess.Should().BeTrue();
        doc.DocumentElement!.GetAttribute("ID").Should().StartWith("_");
        doc.DocumentElement!.GetAttribute("ID").Length.Should().Be(33);
    }

    [Fact]
    public void SignElement_WithECDsaCertificate_ReturnsInvalidKey()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var certReq = new CertificateRequest("CN=SamlEcdsaTest", ecdsa, HashAlgorithmName.SHA256);
        using var certWithKey = certReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddYears(1));

        var xml = @"<samlp:AuthnRequest xmlns:samlp=""urn:oasis:names:tc:SAML:2.0:protocol"" ID=""_ecdsa_req"" Version=""2.0""/>";
        var doc = new XmlDocument { XmlResolver = null, PreserveWhitespace = true };
        doc.LoadXml(xml);

        var signResult = _validator.SignElement(doc.DocumentElement!, certWithKey);
        signResult.IsFailure.Should().BeTrue();
        signResult.Error.Description.Should().Contain("Could not extract RSA private key");
    }

    [Fact]
    public void SignElement_CertificateWithoutPrivateKey_ReturnsInvalidKey()
    {
        using var rsa = RSA.Create(2048);
        var certReq = new CertificateRequest("CN=SamlSigningTest", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var certWithKey = certReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddYears(1));
#if NET9_0_OR_GREATER
        var certPub = X509CertificateLoader.LoadCertificate(certWithKey.Export(X509ContentType.Cert));
#else
        var certPub = new X509Certificate2(certWithKey.Export(X509ContentType.Cert));
#endif

        var xml = @"<samlp:AuthnRequest xmlns:samlp=""urn:oasis:names:tc:SAML:2.0:protocol"" ID=""_req123"" Version=""2.0""/>";
        var doc = new XmlDocument { XmlResolver = null };
        doc.LoadXml(xml);

        var signResult = _validator.SignElement(doc.DocumentElement!, certPub);
        signResult.IsFailure.Should().BeTrue();
        signResult.Error.Description.Should().Contain("Certificate does not contain a private key");
    }

    [Fact]
    public void VerifySignature_TamperedXml_ReturnsFailure()
    {
        using var rsa = RSA.Create(2048);
        var certReq = new CertificateRequest("CN=SamlSigningTest", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var certWithKey = certReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddYears(1));

        var xml = @"<samlp:AuthnRequest xmlns:samlp=""urn:oasis:names:tc:SAML:2.0:protocol"" xmlns:saml=""urn:oasis:names:tc:SAML:2.0:assertion"" ID=""_req123"" Version=""2.0"">
  <saml:Issuer>https://sp.example.com</saml:Issuer>
</samlp:AuthnRequest>";

        var doc = new XmlDocument { XmlResolver = null, PreserveWhitespace = true };
        doc.LoadXml(xml);

        _validator.SignElement(doc.DocumentElement!, certWithKey);

        // Tamper with content
        var nsMgr = new XmlNamespaceManager(doc.NameTable);
        nsMgr.AddNamespace("saml", "urn:oasis:names:tc:SAML:2.0:assertion");
        var issuerNode = doc.SelectSingleNode("//saml:Issuer", nsMgr);
        issuerNode!.InnerText = "https://attacker.example.com";

        var verifyResult = _validator.VerifySignature(doc.DocumentElement!, certWithKey);
        verifyResult.IsFailure.Should().BeTrue();
        verifyResult.Error.Description.Should().Contain("XMLDSig signature verification failed with provided certificate.");
    }

    [Fact]
    public void VerifySignature_WrongCertificate_ReturnsFailure()
    {
        using var rsa1 = RSA.Create(2048);
        var certReq1 = new CertificateRequest("CN=SamlSigningTest1", rsa1, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert1 = certReq1.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddYears(1));

        using var rsa2 = RSA.Create(2048);
        var certReq2 = new CertificateRequest("CN=SamlSigningTest2", rsa2, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert2 = certReq2.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddYears(1));

        var xml = @"<samlp:AuthnRequest xmlns:samlp=""urn:oasis:names:tc:SAML:2.0:protocol"" ID=""_req123"" Version=""2.0""/>";
        var doc = new XmlDocument { XmlResolver = null, PreserveWhitespace = true };
        doc.LoadXml(xml);

        _validator.SignElement(doc.DocumentElement!, cert1);

        var verifyResult = _validator.VerifySignature(doc.DocumentElement!, cert2);
        verifyResult.IsFailure.Should().BeTrue();
        verifyResult.Error.Description.Should().Contain("XMLDSig signature verification failed with provided certificate.");
    }

    [Fact]
    public void VerifySignature_NoSignatureElement_ReturnsFailure()
    {
        using var rsa = RSA.Create(2048);
        var certReq = new CertificateRequest("CN=SamlSigningTest", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = certReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddYears(1));

        var xml = @"<samlp:AuthnRequest xmlns:samlp=""urn:oasis:names:tc:SAML:2.0:protocol"" ID=""_req123"" Version=""2.0""/>";
        var doc = new XmlDocument { XmlResolver = null };
        doc.LoadXml(xml);

        var verifyResult = _validator.VerifySignature(doc.DocumentElement!, cert);
        verifyResult.IsFailure.Should().BeTrue();
        verifyResult.Error.Description.Should().Contain("No XMLDSig <ds:Signature> element found");
    }

    [Fact]
    public void VerifySignature_SignatureReferenceUriMismatch_ReturnsFailure()
    {
        using var rsa = RSA.Create(2048);
        var certReq = new CertificateRequest("CN=SamlSigningTest", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var certWithKey = certReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddYears(1));

        var xml = @"<samlp:AuthnRequest xmlns:samlp=""urn:oasis:names:tc:SAML:2.0:protocol"" ID=""_target_id"" Version=""2.0""/>";
        var doc = new XmlDocument { XmlResolver = null, PreserveWhitespace = true };
        doc.LoadXml(xml);

        _validator.SignElement(doc.DocumentElement!, certWithKey);

        // Change the ID attribute on the element so URI no longer matches
        doc.DocumentElement!.SetAttribute("ID", "_modified_target_id");

        var verifyResult = _validator.VerifySignature(doc.DocumentElement!, certWithKey);
        verifyResult.IsFailure.Should().BeTrue();
        verifyResult.Error.Code.Should().Be("Security.PolicyViolation");
        verifyResult.Error.Description.Should().Contain("SAML.Signature");
        verifyResult.Error.Description.Should().Contain("does not match element ID");
    }

    [Fact]
    public void VerifySignature_SignatureWithNoReferences_ReturnsInvalidToken()
    {
        using var rsa = RSA.Create(2048);
        var certReq = new CertificateRequest("CN=SamlSigningTest", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = certReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddYears(1));

        var xml = @"<samlp:AuthnRequest xmlns:samlp=""urn:oasis:names:tc:SAML:2.0:protocol"" ID=""_req123"" Version=""2.0"">
  <Signature xmlns=""http://www.w3.org/2000/09/xmldsig#"">
    <SignedInfo>
      <CanonicalizationMethod Algorithm=""http://www.w3.org/2001/10/xml-exc-c14n#""/>
      <SignatureMethod Algorithm=""http://www.w3.org/2001/04/xmldsig-more#rsa-sha256""/>
    </SignedInfo>
    <SignatureValue>AA==</SignatureValue>
  </Signature>
</samlp:AuthnRequest>";
        var doc = new XmlDocument { XmlResolver = null, PreserveWhitespace = true };
        doc.LoadXml(xml);

        var verifyResult = _validator.VerifySignature(doc.DocumentElement!, cert);
        verifyResult.IsFailure.Should().BeTrue();
        verifyResult.Error.Description.Should().Contain("contains no signed references");
    }

    [Fact]
    public void VerifySignature_LowercaseIdAttribute_MatchesSuccessfully()
    {
        using var rsa = RSA.Create(2048);
        var certReq = new CertificateRequest("CN=SamlSigningTest", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var certWithKey = certReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddYears(1));

        var xml = @"<samlp:AuthnRequest xmlns:samlp=""urn:oasis:names:tc:SAML:2.0:protocol"" id=""_lower_req"" Version=""2.0""/>";
        var doc = new XmlDocument { XmlResolver = null, PreserveWhitespace = true };
        doc.LoadXml(xml);

        // Sign element manually with reference to _lower_req
        var signedXml = new SignedXml(doc) { SigningKey = rsa };
        var reference = new Reference { Uri = "#_lower_req" };
        reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
        signedXml.AddReference(reference);
        signedXml.ComputeSignature();
        doc.DocumentElement!.AppendChild(doc.ImportNode(signedXml.GetXml(), true));

        var verifyResult = _validator.VerifySignature(doc.DocumentElement!, certWithKey);
        verifyResult.IsSuccess.Should().BeTrue();
    }

    [Fact]
    public void SignElement_WithNextSiblingAfterIssuer_InsertsAfterIssuer()
    {
        using var rsa = RSA.Create(2048);
        var certReq = new CertificateRequest("CN=SamlSigningTest", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var certWithKey = certReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddYears(1));

        var xml = @"<samlp:AuthnRequest xmlns:samlp=""urn:oasis:names:tc:SAML:2.0:protocol"" xmlns:saml=""urn:oasis:names:tc:SAML:2.0:assertion"" ID=""_req123"" Version=""2.0"">
  <saml:Issuer>https://sp.example.com</saml:Issuer>
  <samlp:NameIDPolicy Format=""urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified""/>
</samlp:AuthnRequest>";
        var doc = new XmlDocument { XmlResolver = null, PreserveWhitespace = true };
        doc.LoadXml(xml);

        var signResult = _validator.SignElement(doc.DocumentElement!, certWithKey);
        signResult.IsSuccess.Should().BeTrue();

        var issuerNode = doc.DocumentElement!.SelectSingleNode("./*[local-name()='Issuer']");
        issuerNode!.NextSibling!.LocalName.Should().Be("Signature");
    }

    [Fact]
    public void VerifySignature_CorruptedSignatureData_ReturnsFailure()
    {
        using var rsa = RSA.Create(2048);
        var certReq = new CertificateRequest("CN=SamlSigningTest", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = certReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddYears(1));

        var xml = @"<samlp:AuthnRequest xmlns:samlp=""urn:oasis:names:tc:SAML:2.0:protocol"" ID=""_req123"" Version=""2.0"">
  <Signature xmlns=""http://www.w3.org/2000/09/xmldsig#"">
    <SignedInfo>
      <CanonicalizationMethod Algorithm=""http://invalid-canonicalization-url""/>
      <SignatureMethod Algorithm=""http://www.w3.org/2001/04/xmldsig-more#rsa-sha256""/>
      <Reference Uri=""#_req123"">
        <DigestMethod Algorithm=""http://www.w3.org/2001/04/xmlenc#sha256""/>
        <DigestValue>AA==</DigestValue>
      </Reference>
    </SignedInfo>
    <SignatureValue>AA==</SignatureValue>
  </Signature>
</samlp:AuthnRequest>";
        var doc = new XmlDocument { XmlResolver = null, PreserveWhitespace = true };
        doc.LoadXml(xml);

        var result = _validator.VerifySignature(doc.DocumentElement!, cert);
        result.IsFailure.Should().BeTrue();
        result.Error.Description.Should().Contain("XMLDSig signature evaluation error");
    }

    [Fact]
    public void VerifySignature_ReferenceWithoutUri_ReturnsMismatch()
    {
        using var rsa = RSA.Create(2048);
        var certReq = new CertificateRequest("CN=SamlSigningTest", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = certReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddYears(1));

        var xml = @"<samlp:AuthnRequest xmlns:samlp=""urn:oasis:names:tc:SAML:2.0:protocol"" ID=""_req123"" Version=""2.0"">
  <Signature xmlns=""http://www.w3.org/2000/09/xmldsig#"">
    <SignedInfo>
      <CanonicalizationMethod Algorithm=""http://www.w3.org/2001/10/xml-exc-c14n#""/>
      <SignatureMethod Algorithm=""http://www.w3.org/2001/04/xmldsig-more#rsa-sha256""/>
      <Reference>
        <DigestMethod Algorithm=""http://www.w3.org/2001/04/xmlenc#sha256""/>
        <DigestValue>AA==</DigestValue>
      </Reference>
    </SignedInfo>
    <SignatureValue>AA==</SignatureValue>
  </Signature>
</samlp:AuthnRequest>";
        var doc = new XmlDocument { XmlResolver = null, PreserveWhitespace = true };
        doc.LoadXml(xml);

        var result = _validator.VerifySignature(doc.DocumentElement!, cert);
        result.IsFailure.Should().BeTrue();
    }

    [Fact]
    public void SignElement_WhenDomOperationThrows_ReturnsEncryptionFailed()
    {
        using var rsa = RSA.Create(2048);
        var certReq = new CertificateRequest("CN=SamlThrowingSignTest", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = certReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddYears(1));

        var doc = new ThrowingXmlDocument();
        var elem = doc.CreateElement("samlp", "AuthnRequest", "urn:oasis:names:tc:SAML:2.0:protocol");
        elem.SetAttribute("ID", "_req123");
        doc.AppendChild(elem);

        var result = _validator.SignElement(elem, cert);
        result.IsFailure.Should().BeTrue();
        result.Error.Description.Should().Contain("Failed to sign XML element");
    }

    private sealed class ThrowingXmlDocument : XmlDocument
    {
        public override XmlNode ImportNode(XmlNode node, bool deep)
            => throw new InvalidOperationException("Simulated DOM import failure");
    }

    [Fact]
    public void SignElement_EcdsaCertificate_ReturnsInvalidKey()
    {
        using var ecdsa = ECDsa.Create();
        var certReq = new CertificateRequest("CN=SamlEcdsaTest", ecdsa, HashAlgorithmName.SHA256);
        using var cert = certReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddYears(1));

        var xml = @"<samlp:AuthnRequest xmlns:samlp=""urn:oasis:names:tc:SAML:2.0:protocol"" ID=""_req123"" Version=""2.0""/>";
        var doc = new XmlDocument { XmlResolver = null, PreserveWhitespace = true };
        doc.LoadXml(xml);

        var result = _validator.SignElement(doc.DocumentElement!, cert);
        result.IsFailure.Should().BeTrue();
        result.Error.Description.Should().Contain("Could not extract RSA private key");
    }

    [Fact]
    public void NullArguments_ThrowArgumentNullException()
    {
        using var rsa = RSA.Create(2048);
        var certReq = new CertificateRequest("CN=SamlSigningTest", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = certReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddYears(1));

        var doc = new XmlDocument();
        var elem = doc.CreateElement("root");

        Assert.Throws<ArgumentNullException>(() => _validator.VerifySignature(null!, cert));
        Assert.Throws<ArgumentNullException>(() => _validator.VerifySignature(elem, null!));
        Assert.Throws<ArgumentNullException>(() => _validator.SignElement(null!, cert));
        Assert.Throws<ArgumentNullException>(() => _validator.SignElement(elem, null!));
    }
}
