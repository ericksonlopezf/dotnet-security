// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Cryptography.XmlDSig.Tests;

using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;
using AwesomeAssertions;
using EricksonLopez.Security.Cryptography.XmlDSig.Tests.Fixtures;
using Xunit;

public sealed class XmlDigitalSignatureServiceTests : IClassFixture<XmlSigningCertificatesFixture>
{
    private readonly X509Certificate2 _cert;
    private readonly X509Certificate2 _publicOnlyCert;
    private readonly RSA _rsa;

    public XmlDigitalSignatureServiceTests(XmlSigningCertificatesFixture fixture)
    {
        ArgumentNullException.ThrowIfNull(fixture);
        _cert = fixture.Cert;
        _publicOnlyCert = fixture.PublicOnlyCert;
        _rsa = fixture.Rsa;
    }

    [Fact]
    public void SignXml_ValidXml_GeneratesValidEnvelopedSignature()
    {
        var sampleXml = "<ECF><Encabezado><IdDoc><eNCF>E310000000001</eNCF></IdDoc></Encabezado></ECF>";

        var signResult = XmlDigitalSignatureService.Instance.SignXml(sampleXml, _cert);

        signResult.IsSuccess.Should().BeTrue();
        var signedXml = signResult.Value;

        signedXml.Should().Contain("<Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\">");
        signedXml.Should().Contain("<SignatureValue>");
        signedXml.Should().Contain($"<Transform Algorithm=\"{SignedXml.XmlDsigC14NTransformUrl}\"");
        signedXml.Should().Contain($"<Transform Algorithm=\"{SignedXml.XmlDsigEnvelopedSignatureTransformUrl}\"");

        var verifyResult = XmlDigitalSignatureService.Instance.VerifyXml(signedXml, _cert);
        verifyResult.IsSuccess.Should().BeTrue();
        verifyResult.Value.Should().BeTrue();
    }

    [Fact]
    public void SignXml_XmlWithWhitespace_PreservesWhitespaceAndVerifiesSuccessfully()
    {
        var sampleXml = "<Doc>\n  <Element>Value</Element>\n</Doc>";

        var signResult = XmlDigitalSignatureService.Instance.SignXml(sampleXml, _cert);
        signResult.IsSuccess.Should().BeTrue();
        signResult.Value.Should().Contain("\n  <Element>Value</Element>\n");

        var verifyResult = XmlDigitalSignatureService.Instance.VerifyXml(signResult.Value, _cert);
        verifyResult.IsSuccess.Should().BeTrue();
        verifyResult.Value.Should().BeTrue();
    }

    [Fact]
    public void SignXml_WithOptions_CustomCanonicalizationAndKeyInfoFalse()
    {
        var sampleXml = "<Doc><Item>123</Item></Doc>";
        var options = new XmlSigningOptions
        {
            IncludeKeyInfo = false,
            CanonicalizationMethod = SignedXml.XmlDsigExcC14NTransformUrl,
            SignatureMethod = SignedXml.XmlDsigRSASHA256Url,
            DigestMethod = SignedXml.XmlDsigSHA256Url,
            ReferenceUri = ""
        };

        var signResult = XmlDigitalSignatureService.Instance.SignXml(sampleXml, _cert, options);
        signResult.IsSuccess.Should().BeTrue();
        signResult.Value.Should().NotContain("<KeyInfo>");

        // Verify with expected certificate (since KeyInfo is omitted)
        var verifyResult = XmlDigitalSignatureService.Instance.VerifyXml(signResult.Value, _cert);
        verifyResult.IsSuccess.Should().BeTrue();
        verifyResult.Value.Should().BeTrue();
    }

    [Fact]
    public void SignXml_XmlDocument_ValidDocument_SignsInPlace()
    {
        var doc = new XmlDocument { PreserveWhitespace = true };
        doc.LoadXml("<Invoice><Amount>100</Amount></Invoice>");

        var result = XmlDigitalSignatureService.Instance.SignXml(doc, _cert);
        result.IsSuccess.Should().BeTrue();
        result.Value.GetElementsByTagName("Signature", SignedXml.XmlDsigNamespaceUrl).Count.Should().Be(1);

        var verifyDocResult = XmlDigitalSignatureService.Instance.VerifyXml(doc, _cert);
        verifyDocResult.IsSuccess.Should().BeTrue();
        verifyDocResult.Value.Should().BeTrue();
    }

    [Fact]
    public void SignXml_XmlDocument_NullDocumentOrCert_ThrowsArgumentNullException()
    {
        var doc = new XmlDocument();
        Assert.Throws<ArgumentNullException>(() => XmlDigitalSignatureService.Instance.SignXml((XmlDocument)null!, _cert));
        Assert.Throws<ArgumentNullException>(() => XmlDigitalSignatureService.Instance.SignXml(doc, null!));
    }

    [Fact]
    public void SignXml_XmlDocument_EmptyRoot_ReturnsValidationError()
    {
        var emptyDoc = new XmlDocument();
        var result = XmlDigitalSignatureService.Instance.SignXml(emptyDoc, _cert);

        result.IsFailure.Should().BeTrue();
        result.Error.Code.Should().Be("XmlDigitalSignatureService.EmptyDocument");
    }

    [Fact]
    public void SignXml_CertificateWithoutPrivateKey_ReturnsForbiddenError()
    {
        var doc = new XmlDocument();
        doc.LoadXml("<Root />");

        var result = XmlDigitalSignatureService.Instance.SignXml(doc, _publicOnlyCert);
        result.IsFailure.Should().BeTrue();
        result.Error.Code.Should().Be("XmlDigitalSignatureService.NoPrivateKey");

        var strResult = XmlDigitalSignatureService.Instance.SignXml("<Root />", _publicOnlyCert);
        strResult.IsFailure.Should().BeTrue();
        strResult.Error.Code.Should().Be("XmlDigitalSignatureService.NoPrivateKey");
    }

    [Fact]
    public void SignXml_InvalidSignatureMethod_ThrowsArgumentException()
    {
        // XML-004 fix: XmlSigningOptions.SignatureMethod setter now validates against an allowlist
        // of approved signature method URIs. Setting an invalid value throws ArgumentException
        // immediately at property assignment — the service never receives an invalid algorithm.
        var doc = new XmlDocument();
        doc.LoadXml("<Root />");

        Assert.Throws<ArgumentException>(() =>
        {
            _ = new XmlSigningOptions { SignatureMethod = "invalid-sig-method" };
        });
    }

    [Fact]
    public void SignXml_ValidSignatureMethod_Succeeds()
    {
        // XML-004 fix: verify that valid signature methods pass allowlist validation
        var doc = new XmlDocument();
        doc.LoadXml("<Root />");
        var options = new XmlSigningOptions
        {
            SignatureMethod = SignedXml.XmlDsigRSASHA512Url // valid allowlisted method
        };
        var result = XmlDigitalSignatureService.Instance.SignXml(doc, _cert, options);
        result.IsSuccess.Should().BeTrue();
    }

    [Fact]
    public void VerifyXml_NoEmbeddedCertInSignatureAndNoExpectedCert_CallsFallbackAndReturnsInvalidSignature()
    {
        var options = new XmlSigningOptions { IncludeKeyInfo = false };
        var signResult = XmlDigitalSignatureService.Instance.SignXml("<Root />", _cert, options);
        signResult.IsSuccess.Should().BeTrue();

        var verifyResult = XmlDigitalSignatureService.Instance.VerifyXml(signResult.Value, expectedCertificate: null, new XmlVerificationOptions { AllowUntrustedEmbeddedCertificate = true });
        verifyResult.IsFailure.Should().BeTrue();
        verifyResult.Error.Code.Should().Be("XmlDigitalSignatureService.InvalidSignature");
    }

    [Fact]
    public void VerifyXml_MalformedSignatureAlgorithm_ReturnsVerificationError()
    {
        var doc = new XmlDocument();
        doc.LoadXml("<Root><Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><SignedInfo><CanonicalizationMethod Algorithm=\"unknown:invalid\"/><SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"/><Reference URI=\"\"><DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/><DigestValue>abc</DigestValue></Reference></SignedInfo><SignatureValue>abc</SignatureValue></Signature></Root>");
        var result = XmlDigitalSignatureService.Instance.VerifyXml(doc, _cert);
        result.IsFailure.Should().BeTrue();
        result.Error.Code.Should().Be("XmlDigitalSignatureService.VerificationError");
    }

    [Fact]
    public void VerifyXml_EmbeddedNonRsaCertificateInKeyInfo_ReturnsInvalidSignature()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var req = new CertificateRequest("CN=EcdsaCert", ecdsa, HashAlgorithmName.SHA256);
        using var ecdsaCert = req.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(1));
        var ecdsaBase64 = Convert.ToBase64String(ecdsaCert.Export(X509ContentType.Cert));

        var doc = new XmlDocument();
        doc.LoadXml($"""
            <Root>
                <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
                    <SignedInfo>
                        <CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315" />
                        <SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" />
                        <Reference URI="">
                            <DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256" />
                            <DigestValue>dGVzdA==</DigestValue>
                        </Reference>
                    </SignedInfo>
                    <SignatureValue>dGVzdA==</SignatureValue>
                    <KeyInfo>
                        <X509Data>
                            <X509Certificate>{ecdsaBase64}</X509Certificate>
                        </X509Data>
                    </KeyInfo>
                </Signature>
            </Root>
            """);

        var result = XmlDigitalSignatureService.Instance.VerifyXml(doc, expectedCertificate: null, new XmlVerificationOptions { AllowUntrustedEmbeddedCertificate = true });
        result.IsFailure.Should().BeTrue();
        result.Error.Code.Should().Be("XmlDigitalSignatureService.InvalidSignature");
    }

    [Fact]
    public void SignXml_String_NullOrEmptyOrInvalidXml_ReturnsFailure()
    {
        var empty1 = XmlDigitalSignatureService.Instance.SignXml("", _cert);
        empty1.IsFailure.Should().BeTrue();
        empty1.Error.Code.Should().Be("XmlDigitalSignatureService.EmptyXml");

        var empty2 = XmlDigitalSignatureService.Instance.SignXml("   ", _cert);
        empty2.IsFailure.Should().BeTrue();
        empty2.Error.Code.Should().Be("XmlDigitalSignatureService.EmptyXml");

        XmlDigitalSignatureService.Instance.SignXml("<invalid xml", _cert).IsFailure.Should().BeTrue();
    }

    [Fact]
    public void VerifyXml_NullOrEmptyOrInvalidXmlString_ReturnsFailure()
    {
        var empty1 = XmlDigitalSignatureService.Instance.VerifyXml("");
        empty1.IsFailure.Should().BeTrue();
        empty1.Error.Code.Should().Be("XmlDigitalSignatureService.EmptyXml");

        var empty2 = XmlDigitalSignatureService.Instance.VerifyXml("   ");
        empty2.IsFailure.Should().BeTrue();
        empty2.Error.Code.Should().Be("XmlDigitalSignatureService.EmptyXml");

        XmlDigitalSignatureService.Instance.VerifyXml("<unclosed xml").IsFailure.Should().BeTrue();
    }

    [Fact]
    public void VerifyXml_NullDocument_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => XmlDigitalSignatureService.Instance.VerifyXml((XmlDocument)null!));
    }

    [Fact]
    public void VerifyXml_NoSignatureInDocument_ReturnsNotFound()
    {
        var doc = new XmlDocument();
        doc.LoadXml("<UnsignedDocument />");

        var result = XmlDigitalSignatureService.Instance.VerifyXml(doc);
        result.IsFailure.Should().BeTrue();
        result.Error.Code.Should().Be("XmlDigitalSignatureService.SignatureNotFound");
    }

    [Fact]
    public void VerifyXml_ExpectedCertWithoutRsaKey_ReturnsForbidden()
    {
        var sampleXml = "<Invoice><Total>1500.00</Total></Invoice>";
        var signedXml = XmlDigitalSignatureService.Instance.SignXml(sampleXml, _cert).Value;

        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var req = new CertificateRequest("CN=EcdsaCert", ecdsa, HashAlgorithmName.SHA256);
        using var ecdsaCert = req.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(1));

        var result = XmlDigitalSignatureService.Instance.VerifyXml(signedXml, ecdsaCert);
        result.IsFailure.Should().BeTrue();
        result.Error.Code.Should().Be("XmlDigitalSignatureService.NoPublicKey");
    }

    [Fact]
    public void VerifyXml_TamperedContent_ReturnsFailure()
    {
        var sampleXml = "<Invoice><Total>1500.00</Total></Invoice>";
        var signedXml = XmlDigitalSignatureService.Instance.SignXml(sampleXml, _cert).Value;

        // Tamper with the amount in the payload
        var tamperedXml = signedXml.Replace("<Total>1500.00</Total>", "<Total>9999.00</Total>");

        var verifyResult = XmlDigitalSignatureService.Instance.VerifyXml(tamperedXml, _cert);

        verifyResult.IsFailure.Should().BeTrue();
        verifyResult.Error.Code.Should().Be("XmlDigitalSignatureService.InvalidSignature");
    }

    [Fact]
    public void VerifyXml_MismatchedExpectedCertificate_ReturnsFailure()
    {
        var sampleXml = "<Invoice><Total>500.00</Total></Invoice>";
        var signedXml = XmlDigitalSignatureService.Instance.SignXml(sampleXml, _cert).Value;

        // Create a different certificate
        using var rsaOther = RSA.Create(2048);
        var req = new CertificateRequest("CN=Attacker", rsaOther, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var otherCert = req.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(1));

        var verifyResult = XmlDigitalSignatureService.Instance.VerifyXml(signedXml, otherCert);

        verifyResult.IsFailure.Should().BeTrue();
    }

    // ── XmlSignatureCertificateExtractor ────────────────────────────────────

    [Fact]
    public void ExtractCertificate_SignedXml_ExtractsMatchingCertificate()
    {
        var sampleXml = "<Invoice><Total>1500.00</Total></Invoice>";
        var signedXml = XmlDigitalSignatureService.Instance.SignXml(sampleXml, _cert).Value;

        var extractResult = XmlSignatureCertificateExtractor.ExtractCertificate(signedXml);

        extractResult.IsSuccess.Should().BeTrue();
        extractResult.Value.Thumbprint.Should().Be(_cert.Thumbprint);
    }

    [Fact]
    public void ExtractCertificate_EmptyOrInvalidXmlString_ReturnsFailure()
    {
        var empty1 = XmlSignatureCertificateExtractor.ExtractCertificate("");
        empty1.IsFailure.Should().BeTrue();
        empty1.Error.Code.Should().Be("XmlSignatureCertificateExtractor.EmptyXml");

        var empty2 = XmlSignatureCertificateExtractor.ExtractCertificate("   ");
        empty2.IsFailure.Should().BeTrue();
        empty2.Error.Code.Should().Be("XmlSignatureCertificateExtractor.EmptyXml");

        XmlSignatureCertificateExtractor.ExtractCertificate("<invalid xml").IsFailure.Should().BeTrue();
    }

    [Fact]
    public void ExtractCertificate_NullDocument_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => XmlSignatureCertificateExtractor.ExtractCertificate((XmlDocument)null!));
    }

    [Fact]
    public void ExtractCertificate_NoSignature_ReturnsNotFound()
    {
        var doc = new XmlDocument();
        doc.LoadXml("<NoSignature />");

        var result = XmlSignatureCertificateExtractor.ExtractCertificate(doc);
        result.IsFailure.Should().BeTrue();
        result.Error.Code.Should().Be("XmlSignatureCertificateExtractor.SignatureNotFound");
    }

    [Fact]
    public void ExtractCertificate_NoX509CertificateElement_ReturnsNotFound()
    {
        var doc = new XmlDocument();
        doc.LoadXml("<Root><Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><SignedInfo /></Signature></Root>");

        var result = XmlSignatureCertificateExtractor.ExtractCertificate(doc);
        result.IsFailure.Should().BeTrue();
        result.Error.Code.Should().Be("XmlSignatureCertificateExtractor.CertificateNotFound");
    }

    [Fact]
    public void ExtractCertificate_EmptyCertificateData_ReturnsValidation()
    {
        var doc = new XmlDocument();
        doc.LoadXml("<Root><Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><KeyInfo><X509Data><X509Certificate>   </X509Certificate></X509Data></KeyInfo></Signature></Root>");

        var result = XmlSignatureCertificateExtractor.ExtractCertificate(doc);
        result.IsFailure.Should().BeTrue();
        result.Error.Code.Should().Be("XmlSignatureCertificateExtractor.EmptyCertificateData");
    }

    [Fact]
    public void ExtractCertificate_InvalidBase64CertificateData_ReturnsFailure()
    {
        var doc = new XmlDocument();
        doc.LoadXml("<Root><Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><KeyInfo><X509Data><X509Certificate>???not-valid-base64???</X509Certificate></X509Data></KeyInfo></Signature></Root>");

        var result = XmlSignatureCertificateExtractor.ExtractCertificate(doc);
        result.IsFailure.Should().BeTrue();
        result.Error.Code.Should().Be("XmlSignatureCertificateExtractor.InvalidCertificateData");
    }

    [Fact]
    public void VerifyXml_WhenExpectedCertificateNull_UntrustedSelfSignedCertificate_RejectedAsUntrusted()
    {
        var sampleXml = "<Doc><Data>Untrusted</Data></Doc>";
        var signResult = XmlDigitalSignatureService.Instance.SignXml(sampleXml, _cert);
        signResult.IsSuccess.Should().BeTrue();

        // When expectedCertificate is null, an unanchored self-signed cert in KeyInfo is rejected
        var verifyResult = XmlDigitalSignatureService.Instance.VerifyXml(signResult.Value, expectedCertificate: null);
        verifyResult.IsFailure.Should().BeTrue();
        verifyResult.Error.Code.Should().Be("XmlDigitalSignatureService.UntrustedCertificate");
    }

    [Fact]
    public void VerifyXml_WhenExpectedCertificateNull_WithTrustEvaluator_Succeeds()
    {
        var sampleXml = "<Doc><Data>TrustedViaEvaluator</Data></Doc>";
        var signResult = XmlDigitalSignatureService.Instance.SignXml(sampleXml, _cert);
        signResult.IsSuccess.Should().BeTrue();

        var options = new XmlVerificationOptions
        {
            CertificateTrustEvaluator = cert => cert.Thumbprint == _cert.Thumbprint
        };

        var verifyResult = XmlDigitalSignatureService.Instance.VerifyXml(signResult.Value, expectedCertificate: null, options);
        verifyResult.IsSuccess.Should().BeTrue();
        verifyResult.Value.Should().BeTrue();
    }

    [Fact]
    public void VerifyAndExtractSignedElement_ReturnsSignedElement_MitigatingXSW()
    {
        var sampleXml = "<Invoice><Total>1500.00</Total></Invoice>";
        var signResult = XmlDigitalSignatureService.Instance.SignXml(sampleXml, _cert);
        signResult.IsSuccess.Should().BeTrue();

        var doc = new XmlDocument { PreserveWhitespace = true };
        doc.LoadXml(signResult.Value);

        // WHEN: Calling VerifyAndExtractSignedElement
        var result = XmlDigitalSignatureService.Instance.VerifyAndExtractSignedElement(doc, _cert);

        // THEN: Verification succeeds and correctly extracts the signed root element
        result.IsSuccess.Should().BeTrue();
        result.Value.IsValid.Should().BeTrue();
        result.Value.SignedElement.Should().NotBeNull();
        result.Value.SignedElement!.Name.Should().Be("Invoice");
        result.Value.SigningCertificate.Should().NotBeNull();
        result.Value.SigningCertificate!.Thumbprint.Should().Be(_cert.Thumbprint);
    }

    [Fact]
    public void VerifyXml_WithMultipleSignatures_DefaultOptions_FailsWithMultipleSignaturesNotAllowed()
    {
        var sampleXml = "<Doc><Data>MultiSig</Data></Doc>";
        var signResult = XmlDigitalSignatureService.Instance.SignXml(sampleXml, _cert);
        signResult.IsSuccess.Should().BeTrue();

        var doc = new XmlDocument { PreserveWhitespace = true };
        doc.LoadXml(signResult.Value);

        var sigElem = doc.GetElementsByTagName("Signature", SignedXml.XmlDsigNamespaceUrl)[0]!;
        var clonedSig = sigElem.CloneNode(true);
        doc.DocumentElement!.AppendChild(clonedSig);

        var verifyResult = XmlDigitalSignatureService.Instance.VerifyXml(doc, _cert);
        verifyResult.IsFailure.Should().BeTrue();
        verifyResult.Error.Code.Should().Be("XmlDigitalSignatureService.MultipleSignaturesNotAllowed");
        verifyResult.Error.Description.Should().Contain("Found 2 <Signature> elements");
    }

    [Fact]
    public void VerifyXml_WithMultipleSignatures_WhenAllowMultipleSignaturesTrue_ProcessesSignature()
    {
        var sampleXml = "<Doc><Data Id=\"d1\">MultiSigAllowed</Data></Doc>";
        var signOptions = new XmlSigningOptions { ReferenceUri = "#d1" };
        var signResult = XmlDigitalSignatureService.Instance.SignXml(sampleXml, _cert, signOptions);
        signResult.IsSuccess.Should().BeTrue();

        var doc = new XmlDocument { PreserveWhitespace = true };
        doc.LoadXml(signResult.Value);

        var sigElem = doc.GetElementsByTagName("Signature", SignedXml.XmlDsigNamespaceUrl)[0]!;
        var clonedSig = sigElem.CloneNode(true);
        doc.DocumentElement!.AppendChild(clonedSig);

        var options = new XmlVerificationOptions
        {
            AllowMultipleSignatures = true
        };

        var verifyResult = XmlDigitalSignatureService.Instance.VerifyXml(doc, _cert, options);
        verifyResult.IsSuccess.Should().BeTrue();
        verifyResult.Value.Should().BeTrue();
    }

    [Fact]
    public void VerifyXml_WithDuplicateIds_RejectsByDefault()
    {
        // FINDING-NEW-05 / C-04: XSW mitigation via duplicate ID rejection
        var sampleXml = "<Doc><Data Id=\"dup-id\">Original</Data><Other Id=\"dup-id\">Injected</Other></Doc>";
        var signOptions = new XmlSigningOptions { ReferenceUri = "" };
        var signResult = XmlDigitalSignatureService.Instance.SignXml(sampleXml, _cert, signOptions);
        signResult.IsSuccess.Should().BeTrue();

        var verifyResult = XmlDigitalSignatureService.Instance.VerifyXml(signResult.Value, _cert);
        verifyResult.IsFailure.Should().BeTrue();
        verifyResult.Error.Code.Should().Be("XmlDigitalSignatureService.DuplicateIdDetected");
        verifyResult.Error.Description.Should().Contain("Duplicate ID 'dup-id' detected");
    }

    [Fact]
    public void VerifyXml_WithDuplicateIds_WhenAllowDuplicateIdsTrue_AllowsVerification()
    {
        var sampleXml = "<Doc><Data Id=\"dup-id\">Original</Data><Other Id=\"dup-id\">Injected</Other></Doc>";
        var signOptions = new XmlSigningOptions { ReferenceUri = "" };
        var signResult = XmlDigitalSignatureService.Instance.SignXml(sampleXml, _cert, signOptions);
        signResult.IsSuccess.Should().BeTrue();

        var options = new XmlVerificationOptions { AllowDuplicateIds = true };
        var verifyResult = XmlDigitalSignatureService.Instance.VerifyXml(signResult.Value, _cert, options);
        verifyResult.IsSuccess.Should().BeTrue();
        verifyResult.Value.Should().BeTrue();
    }

    [Fact]
    public void SignXml_ExceedingMaxCharactersInDocument_ReturnsFailure_FINDING_XML_01()
    {
        var sampleXml = "<Doc><Data>Some data that exceeds the limit</Data></Doc>";
        var options = new XmlSigningOptions
        {
            MaxCharactersInDocument = 20
        };

        var result = XmlDigitalSignatureService.Instance.SignXml(sampleXml, _cert, options);

        result.IsFailure.Should().BeTrue();
        result.Error.Code.Should().Be("XmlDigitalSignatureService.SignXmlFailed");
    }

    [Fact]
    public void VerifyXml_ExceedingMaxCharactersInDocument_ReturnsFailure_FINDING_XML_01()
    {
        var sampleXml = "<Doc><Data Id=\"d1\">TestData</Data></Doc>";
        var signResult = XmlDigitalSignatureService.Instance.SignXml(sampleXml, _cert);
        signResult.IsSuccess.Should().BeTrue();

        var options = new XmlVerificationOptions
        {
            MaxCharactersInDocument = 20
        };

        var verifyResult = XmlDigitalSignatureService.Instance.VerifyXml(signResult.Value, _cert, options);

        verifyResult.IsFailure.Should().BeTrue();
        verifyResult.Error.Code.Should().Be("XmlDigitalSignatureService.VerifyXmlFailed");
    }

    [Fact]
    public void VerifyXml_WithDisallowedTransform_ReturnsDisallowedTransformError()
    {
        var sampleXml = "<Doc Id=\"d1\"><Data>Sensitive</Data></Doc>";
        var signResult = XmlDigitalSignatureService.Instance.SignXml(sampleXml, _cert);
        signResult.IsSuccess.Should().BeTrue();

        // Inject an unauthorized transform URI into the signed XML
        var modifiedXml = signResult.Value.Replace(
            $"Algorithm=\"{SignedXml.XmlDsigC14NTransformUrl}\"",
            "Algorithm=\"http://www.w3.org/TR/1999/REC-xslt-19991116\"",
            StringComparison.Ordinal);

        var verifyResult = XmlDigitalSignatureService.Instance.VerifyXml(modifiedXml, _cert);

        verifyResult.IsFailure.Should().BeTrue();
        verifyResult.Error.Code.Should().Be("XmlDigitalSignatureService.DisallowedTransform");
    }
}

