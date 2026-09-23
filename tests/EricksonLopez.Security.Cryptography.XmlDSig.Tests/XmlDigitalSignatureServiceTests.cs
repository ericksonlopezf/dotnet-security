// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Cryptography.XmlDSig.Tests;

using System;
using System.Security.Cryptography;
using System.Text;
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
        verifyResult.Error.Description.Should().Be("XML transform algorithm 'http://www.w3.org/TR/1999/REC-xslt-19991116' is not permitted by verification policy.");
    }

    [Fact]
    public void SignXml_NullCertificate_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => XmlDigitalSignatureService.Instance.SignXml("<Doc/>", null!));
        var doc = new XmlDocument();
        doc.LoadXml("<Doc/>");
        Assert.Throws<ArgumentNullException>(() => XmlDigitalSignatureService.Instance.SignXml(doc, null!));
    }

    [Fact]
    public void SignXml_WithCustomSignatureMethod_AppliesSignatureMethodAlgorithm()
    {
        var sampleXml = "<Doc><Item>512</Item></Doc>";
        var options = new XmlSigningOptions
        {
            SignatureMethod = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512",
            CanonicalizationMethod = SignedXml.XmlDsigExcC14NTransformUrl
        };

        var signResult = XmlDigitalSignatureService.Instance.SignXml(sampleXml, _cert, options);
        signResult.IsSuccess.Should().BeTrue();
        signResult.Value.Should().Contain("Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha512\"");
        signResult.Value.Should().Contain($"Algorithm=\"{SignedXml.XmlDsigExcC14NTransformUrl}\"");
    }

    [Fact]
    public void VerifyXml_WithNullAllowedTransformAlgorithms_BypassesTransformCheck()
    {
        var sampleXml = "<Doc Id=\"d1\"><Data>Sensitive</Data></Doc>";
        var signResult = XmlDigitalSignatureService.Instance.SignXml(sampleXml, _cert);
        signResult.IsSuccess.Should().BeTrue();

        var options = new XmlVerificationOptions { AllowedTransformAlgorithms = null! };
        var verifyResult = XmlDigitalSignatureService.Instance.VerifyXml(signResult.Value, _cert, options);
        verifyResult.IsSuccess.Should().BeTrue();
    }

    [Fact]
    public void VerifyXml_WithCustomTrustAnchors_WhenNotMatching_ReturnsUntrustedCertificateError()
    {
        var sampleXml = "<Doc Id=\"d1\"><Data>Sensitive</Data></Doc>";
        var signResult = XmlDigitalSignatureService.Instance.SignXml(sampleXml, _cert);
        signResult.IsSuccess.Should().BeTrue();

        using var otherRsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=UnrelatedRoot", otherRsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var unrelatedAnchor = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(10));

        var options = new XmlVerificationOptions
        {
            CustomTrustAnchors = new List<X509Certificate2> { unrelatedAnchor }
        };

        var verifyResult = XmlDigitalSignatureService.Instance.VerifyXml(signResult.Value, expectedCertificate: null, options: options);
        verifyResult.IsFailure.Should().BeTrue();
        verifyResult.Error.Code.Should().Be("XmlDigitalSignatureService.UntrustedCertificate");
        verifyResult.Error.Description.Should().Be("The embedded certificate in KeyInfo does not chain to any configured custom trust anchor.");
    }

    [Fact]
    public void VerifyXml_WithCustomTrustAnchors_WhenMatching_Succeeds()
    {
        var sampleXml = "<Doc Id=\"d1\"><Data>Sensitive</Data></Doc>";
        var signResult = XmlDigitalSignatureService.Instance.SignXml(sampleXml, _cert);
        signResult.IsSuccess.Should().BeTrue();

        var options = new XmlVerificationOptions
        {
            CustomTrustAnchors = new List<X509Certificate2> { _cert }
        };

        var verifyResult = XmlDigitalSignatureService.Instance.VerifyXml(signResult.Value, expectedCertificate: null, options: options);
        verifyResult.IsSuccess.Should().BeTrue();
    }

    [Fact]
    public void VerifyXml_WithRequireTrustedCertificate_WhenSelfSigned_ReturnsUntrustedCertificateError()
    {
        var sampleXml = "<Doc Id=\"d1\"><Data>Sensitive</Data></Doc>";
        var signResult = XmlDigitalSignatureService.Instance.SignXml(sampleXml, _cert);
        signResult.IsSuccess.Should().BeTrue();

        var options = new XmlVerificationOptions
        {
            RequireTrustedCertificate = true
        };

        var verifyResult = XmlDigitalSignatureService.Instance.VerifyXml(signResult.Value, expectedCertificate: null, options: options);
        verifyResult.IsFailure.Should().BeTrue();
        verifyResult.Error.Code.Should().Be("XmlDigitalSignatureService.UntrustedCertificate");
        verifyResult.Error.Description.Should().Contain("The embedded certificate in KeyInfo is not trusted and does not chain to a trusted CA root.");
        verifyResult.Error.Description.Should().Contain("To verify safely, provide the expected certificate, configure custom trust anchors, or specify a CertificateTrustEvaluator.");
    }

    [Fact]
    public void VerifyXml_WithMalformedReferenceId_ReturnsInvalidReferenceIdError()
    {
        var longId = new string('a', 257);
        var xmlLong = $"<Doc Id=\"{longId}\"><Data>Sensitive</Data></Doc>";
        var signLong = XmlDigitalSignatureService.Instance.SignXml(xmlLong, _cert, new XmlSigningOptions { ReferenceUri = $"#{longId}" });
        signLong.IsSuccess.Should().BeTrue();
        var resLong = XmlDigitalSignatureService.Instance.VerifyXml(signLong.Value, _cert);
        resLong.IsFailure.Should().BeTrue();
        resLong.Error.Code.Should().Be("XmlDigitalSignatureService.InvalidReferenceId");
        resLong.Error.Description.Should().Be("Malformed signature reference ID format.");

        var xmlColon = "<Doc Id=\"foo:bar\"><Data>Sensitive</Data></Doc>";
        var signColon = XmlDigitalSignatureService.Instance.SignXml(xmlColon, _cert, new XmlSigningOptions { ReferenceUri = "#foo:bar" });
        if (signColon.IsSuccess)
        {
            var resColon = XmlDigitalSignatureService.Instance.VerifyXml(signColon.Value, _cert);
            resColon.IsFailure.Should().BeTrue();
            resColon.Error.Code.Should().Be("XmlDigitalSignatureService.InvalidReferenceId");
        }
    }

    [Fact]
    public void VerifyXml_WithRootReferenceUri_SetsSignedElementToDocumentElement()
    {
        var sampleXml = "<Doc><Data>Sensitive</Data></Doc>";
        var options = new XmlSigningOptions { ReferenceUri = "" };
        var signResult = XmlDigitalSignatureService.Instance.SignXml(sampleXml, _cert, options);
        signResult.IsSuccess.Should().BeTrue();

        var doc = new XmlDocument { PreserveWhitespace = true };
        doc.LoadXml(signResult.Value);
        var verifyResult = XmlDigitalSignatureService.Instance.VerifyXml(doc, _cert);
        verifyResult.IsSuccess.Should().BeTrue();
    }

    [Fact]
    public void VerifyXmlDetailed_WithLowercaseAndUppercaseIdAttributes_FindElementByIdSafeResolvesElement()
    {
        // Lowercase id="sec_lower"
        var xmlLower = "<Doc><Section id=\"sec_lower\"><Data>HelloLower</Data></Section></Doc>";
        var signLower = XmlDigitalSignatureService.Instance.SignXml(xmlLower, _cert, new XmlSigningOptions { ReferenceUri = "#sec_lower" });
        signLower.IsSuccess.Should().BeTrue();

        var docLower = new XmlDocument { PreserveWhitespace = true };
        docLower.LoadXml(signLower.Value);
        var resLower = XmlDigitalSignatureService.Instance.VerifyAndExtractSignedElement(docLower, _cert);
        resLower.IsSuccess.Should().BeTrue();
        resLower.Value.SignedElement.Should().NotBeNull();
        resLower.Value.SignedElement!.GetAttribute("id").Should().Be("sec_lower");

        // Uppercase ID="sec_upper"
        var xmlUpper = "<Doc><Section ID=\"sec_upper\"><Data>HelloUpper</Data></Section></Doc>";
        var signUpper = XmlDigitalSignatureService.Instance.SignXml(xmlUpper, _cert, new XmlSigningOptions { ReferenceUri = "#sec_upper" });
        signUpper.IsSuccess.Should().BeTrue();

        var docUpper = new XmlDocument { PreserveWhitespace = true };
        docUpper.LoadXml(signUpper.Value);
        var resUpper = XmlDigitalSignatureService.Instance.VerifyAndExtractSignedElement(docUpper, _cert);
        resUpper.IsSuccess.Should().BeTrue();
        resUpper.Value.SignedElement.Should().NotBeNull();
        resUpper.Value.SignedElement!.GetAttribute("ID").Should().Be("sec_upper");
    }

    [Fact]
    public void VerifyXmlDetailed_WithExcessiveXmlNesting_ThrowsAndReturnsVerificationError()
    {
        // Create an XML document with > 64 levels of nesting
        var sb = new System.Text.StringBuilder();
        for (int i = 0; i < 70; i++)
        {
            sb.Append($"<Level{i}>");
        }
        sb.Append("<Target id=\"deep_target\"><Data>Deep</Data></Target>");
        for (int i = 69; i >= 0; i--)
        {
            sb.Append($"</Level{i}>");
        }

        var deepXml = sb.ToString();
        var signDeep = XmlDigitalSignatureService.Instance.SignXml(deepXml, _cert, new XmlSigningOptions { ReferenceUri = "#deep_target" });
        signDeep.IsSuccess.Should().BeTrue();

        var docDeep = new XmlDocument { PreserveWhitespace = true };
        docDeep.LoadXml(signDeep.Value);
        var verifyDeep = XmlDigitalSignatureService.Instance.VerifyAndExtractSignedElement(docDeep, _cert);
        verifyDeep.IsFailure.Should().BeTrue();
        verifyDeep.Error.Code.Should().Be("XmlDigitalSignatureService.VerificationError");
        verifyDeep.Error.Description.Should().Contain("maximum permitted nesting depth");
    }

    [Fact]
    public void VerifyXmlDetailed_DisallowedTransformAlgorithm_ReturnsDisallowedTransformError()
    {
        var sampleXml = "<Doc Id=\"doc1\"><Data>Sensitive</Data></Doc>";
        var signResult = XmlDigitalSignatureService.Instance.SignXml(sampleXml, _cert, new XmlSigningOptions { ReferenceUri = "#doc1" });
        signResult.IsSuccess.Should().BeTrue();

        var options = new XmlVerificationOptions
        {
            AllowedTransformAlgorithms = new HashSet<string> { "http://unrelated-transform-not-used" }
        };

        var doc = new XmlDocument { PreserveWhitespace = true };
        doc.LoadXml(signResult.Value);
        var verifyResult = XmlDigitalSignatureService.Instance.VerifyAndExtractSignedElement(doc, _cert, options);
        verifyResult.IsFailure.Should().BeTrue();
        verifyResult.Error.Code.Should().Be("XmlDigitalSignatureService.DisallowedTransform");
        verifyResult.Error.Description.Should().Contain("is not permitted by verification policy");
    }

    [Fact]
    public void VerifyXml_IsValidXmlId_BoundariesAndCharacters()
    {
        // Boundary 256 characters (valid)
        var exact256 = new string('a', 256);
        var xml256 = $"<Doc Id=\"{exact256}\"><Data>OK</Data></Doc>";
        var sign256 = XmlDigitalSignatureService.Instance.SignXml(xml256, _cert, new XmlSigningOptions { ReferenceUri = $"#{exact256}" });
        sign256.IsSuccess.Should().BeTrue();
        var verify256 = XmlDigitalSignatureService.Instance.VerifyXml(sign256.Value, _cert);
        verify256.IsSuccess.Should().BeTrue();

        // Starts with underscore (valid)
        var underscoreId = "_valid-id.name_123";
        var xmlUnderscore = $"<Doc Id=\"{underscoreId}\"><Data>OK</Data></Doc>";
        var signUnderscore = XmlDigitalSignatureService.Instance.SignXml(xmlUnderscore, _cert, new XmlSigningOptions { ReferenceUri = $"#{underscoreId}" });
        signUnderscore.IsSuccess.Should().BeTrue();
        var verifyUnderscore = XmlDigitalSignatureService.Instance.VerifyXml(signUnderscore.Value, _cert);
        verifyUnderscore.IsSuccess.Should().BeTrue();

        // Starts with digit (invalid)
        var digitId = "1starts-with-digit";
        var xmlDigit = $"<Doc Id=\"{digitId}\"><Data>OK</Data></Doc>";
        var signDigit = XmlDigitalSignatureService.Instance.SignXml(xmlDigit, _cert, new XmlSigningOptions { ReferenceUri = $"#{digitId}" });
        if (signDigit.IsSuccess)
        {
            var verifyDigit = XmlDigitalSignatureService.Instance.VerifyXml(signDigit.Value, _cert);
            verifyDigit.IsFailure.Should().BeTrue();
            verifyDigit.Error.Code.Should().Be("XmlDigitalSignatureService.InvalidReferenceId");
        }

        // Contains invalid character (e.g. '$')
        var dollarId = "id$with$dollar";
        var xmlDollar = $"<Doc Id=\"{dollarId}\"><Data>OK</Data></Doc>";
        var signDollar = XmlDigitalSignatureService.Instance.SignXml(xmlDollar, _cert, new XmlSigningOptions { ReferenceUri = $"#{dollarId}" });
        if (signDollar.IsSuccess)
        {
            var verifyDollar = XmlDigitalSignatureService.Instance.VerifyXml(signDollar.Value, _cert);
            verifyDollar.IsFailure.Should().BeTrue();
            verifyDollar.Error.Code.Should().Be("XmlDigitalSignatureService.InvalidReferenceId");
        }
    }

    [Fact]
    public void SignXml_NonExistentReferenceUri_ReturnsComputationFailedError()
    {
        var doc = new XmlDocument { PreserveWhitespace = true };
        doc.LoadXml("<Doc><Data>Val</Data></Doc>");
        var options = new XmlSigningOptions { ReferenceUri = "#nonexistent_element" };
        var result = XmlDigitalSignatureService.Instance.SignXml(doc, _cert, options);
        result.IsFailure.Should().BeTrue();
        result.Error.Code.Should().Be("XmlDigitalSignatureService.ComputationFailed");
        result.Error.Description.Should().Contain("Failed to compute XML signature");
    }

    [Fact]
    public void VerifyXml_SignatureWithoutReferences_ReturnsInvalidSignatureError()
    {
        var xmlWithoutRefs = @"<Doc><Signature xmlns=""http://www.w3.org/2000/09/xmldsig#""><SignedInfo><CanonicalizationMethod Algorithm=""http://www.w3.org/TR/2001/REC-xml-c14n-20010315""/><SignatureMethod Algorithm=""http://www.w3.org/2001/04/xmldsig-more#rsa-sha256""/></SignedInfo><SignatureValue>AA==</SignatureValue></Signature></Doc>";
        var result = XmlDigitalSignatureService.Instance.VerifyXml(xmlWithoutRefs, _cert);
        result.IsFailure.Should().BeTrue();
        result.Error.Code.Should().Be("XmlDigitalSignatureService.InvalidSignature");
    }

    [Theory]
    [InlineData("valid_id-1.test", true)]
    [InlineData("_underscoreValid", true)]
    [InlineData("1startsWithDigit", false)]
    [InlineData("id$withDollar", false)]
    [InlineData("id withSpace", false)]
    [InlineData("id#withHash", false)]
    [InlineData("", false)]
    [InlineData(null, false)]
    public void IsValidXmlId_ValidatesCorrectly(string? id, bool expected)
    {
        XmlDigitalSignatureService.IsValidXmlId(id!).Should().Be(expected);
    }

    [Fact]
    public void IsValidXmlId_LengthBoundaries()
    {
        XmlDigitalSignatureService.IsValidXmlId(new string('a', 256)).Should().BeTrue();
        XmlDigitalSignatureService.IsValidXmlId(new string('a', 257)).Should().BeFalse();
    }

    [Fact]
    public void FindElementByIdSafe_TargetNotFound_ReturnsNullWithoutThrowing()
    {
        var doc = new XmlDocument();
        doc.LoadXml("<Root><Child Id=\"other\"/></Root>");
        var found = XmlDigitalSignatureService.FindElementByIdSafe(doc, "missing");
        found.Should().BeNull();
    }

    [Fact]
    public void FindElementByIdSafe_MatchesId_id_and_ID_Attributes()
    {
        var doc1 = new XmlDocument();
        doc1.LoadXml("<Root><Child Id=\"target1\"/></Root>");
        XmlDigitalSignatureService.FindElementByIdSafe(doc1, "target1").Should().NotBeNull();

        var doc2 = new XmlDocument();
        doc2.LoadXml("<Root><Child id=\"target2\"/></Root>");
        XmlDigitalSignatureService.FindElementByIdSafe(doc2, "target2").Should().NotBeNull();

        var doc3 = new XmlDocument();
        doc3.LoadXml("<Root><Child ID=\"target3\"/></Root>");
        XmlDigitalSignatureService.FindElementByIdSafe(doc3, "target3").Should().NotBeNull();
    }

    [Fact]
    public void FindElementByIdSafe_TraversesMultipleChildNodes()
    {
        var doc = new XmlDocument();
        doc.LoadXml("<Root><Child1/><Child2/><Child3 Id=\"foundMe\"/></Root>");
        var found = XmlDigitalSignatureService.FindElementByIdSafe(doc, "foundMe");
        found.Should().NotBeNull();
        found!.GetAttribute("Id").Should().Be("foundMe");
    }

    [Fact]
    public void FindElementByIdSafe_NestingDepthBoundaries()
    {
        // doc64: root N0 is depth 1, ..., N62 is depth 63, Target is depth 64 (valid boundary <= 64)
        var xmlDepth64 = new StringBuilder();
        for (int i = 0; i < 63; i++) xmlDepth64.Append($"<N{i}>");
        xmlDepth64.Append("<Target Id=\"target\"/>");
        for (int i = 62; i >= 0; i--) xmlDepth64.Append($"</N{i}>");

        var doc64 = new XmlDocument();
        doc64.LoadXml(xmlDepth64.ToString());
        var found = XmlDigitalSignatureService.FindElementByIdSafe(doc64, "target");
        found.Should().NotBeNull();

        // doc65: root N0 is depth 1, ..., N63 is depth 64, Target is depth 65 (exceeds 64)
        var xmlDepth65 = new StringBuilder();
        for (int i = 0; i < 64; i++) xmlDepth65.Append($"<N{i}>");
        xmlDepth65.Append("<Target Id=\"target\"/>");
        for (int i = 63; i >= 0; i--) xmlDepth65.Append($"</N{i}>");

        var doc65 = new XmlDocument();
        doc65.LoadXml(xmlDepth65.ToString());
        var act = () => XmlDigitalSignatureService.FindElementByIdSafe(doc65, "target");
        act.Should().Throw<CryptographicException>()
            .WithMessage("*maximum permitted nesting depth*");
    }

    [Fact]
    public void VerifyXml_CertificateTrustEvaluator_ReturnsFalse_ReturnsUntrustedCertificateError()
    {
        var signResult = XmlDigitalSignatureService.Instance.SignXml("<Doc><Item>123</Item></Doc>", _cert);
        var options = new XmlVerificationOptions
        {
            AllowUntrustedEmbeddedCertificate = false,
            CertificateTrustEvaluator = _ => false
        };
        var verifyResult = XmlDigitalSignatureService.Instance.VerifyXml(signResult.Value, expectedCertificate: null, options: options);
        verifyResult.IsFailure.Should().BeTrue();
        verifyResult.Error.Code.Should().Be("XmlDigitalSignatureService.UntrustedCertificate");
        verifyResult.Error.Description.Should().Be("The embedded certificate in KeyInfo failed custom trust policy validation.");
    }

    [Fact]
    public void VerifyXml_NoExpectedCertificateAndNoKeyInfo_ReturnsCertificateNotFound()
    {
        var signResultNoKeyInfo = XmlDigitalSignatureService.Instance.SignXml("<Doc><Item>123</Item></Doc>", _cert, new XmlSigningOptions { IncludeKeyInfo = false });
        var optionsNoCert = new XmlVerificationOptions { AllowUntrustedEmbeddedCertificate = false };
        var verifyResultNoCert = XmlDigitalSignatureService.Instance.VerifyXml(signResultNoKeyInfo.Value, expectedCertificate: null, options: optionsNoCert);
        verifyResultNoCert.IsFailure.Should().BeTrue();
        verifyResultNoCert.Error.Code.Should().Be("XmlDigitalSignatureService.CertificateNotFound");
        verifyResultNoCert.Error.Description.Should().Be("No expected certificate was provided and no valid certificate was found in KeyInfo.");
    }
}

