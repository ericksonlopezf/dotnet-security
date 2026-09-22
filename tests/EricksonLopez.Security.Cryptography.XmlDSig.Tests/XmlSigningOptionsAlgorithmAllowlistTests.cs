// Copyright © Erickson Lopez. MIT License.
// Regression tests for XML-003/004: XmlSigningOptions algorithm allowlist validation

namespace EricksonLopez.Security.Cryptography.XmlDSig.Tests;

using System;
using System.Security.Cryptography.Xml;
using AwesomeAssertions;
using Xunit;

/// <summary>
/// Regression tests for XML-003 and XML-004: XmlSigningOptions must reject
/// disallowed/weak algorithm URIs to prevent weak algorithm selection attacks.
/// </summary>
public sealed class XmlSigningOptionsAlgorithmAllowlistTests
{
    // ── XML-003: CanonicalizationMethod Allowlist ──────────────────────────────

    [Fact]
    public void CanonicalizationMethod_DefaultC14N_IsValid()
    {
        var options = new XmlSigningOptions();
        options.CanonicalizationMethod.Should().Be(SignedXml.XmlDsigC14NTransformUrl);
    }

    [Theory]
    [InlineData("http://www.w3.org/TR/2001/REC-xml-c14n-20010315")]          // C14N
    [InlineData("http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments")] // C14N with comments
    [InlineData("http://www.w3.org/2001/10/xml-exc-c14n#")]                  // Exclusive C14N
    [InlineData("http://www.w3.org/2001/10/xml-exc-c14n#WithComments")]      // Exclusive C14N with comments
    public void CanonicalizationMethod_AllowedValues_DoNotThrow(string uri)
    {
        var options = new XmlSigningOptions();
        var act = () => options.CanonicalizationMethod = uri;
        act.Should().NotThrow(because: $"'{uri}' is a safe, approved canonicalization method");
        options.CanonicalizationMethod.Should().Be(uri);
    }

    [Theory]
    [InlineData("http://www.w3.org/TR/1999/REC-xpath-19991116")]   // XPath transform — dangerous!
    [InlineData("http://www.w3.org/2002/06/xmldsig-filter2")]       // XPath Filter 2 — dangerous!
    [InlineData("http://unknown-algorithm.example.com/algo")]        // Unknown algorithm
    [InlineData("")]                                                 // Empty string
    public void CanonicalizationMethod_ForbiddenValues_ThrowArgumentException(string uri)
    {
        // XML-003 regression: before fix, any string could be set.
        // After fix: only allowed C14N variants are accepted.
        var options = new XmlSigningOptions();
        var act = () => options.CanonicalizationMethod = uri;
        act.Should().ThrowExactly<ArgumentException>(
            because: $"'{uri}' is not an approved canonicalization method and must be rejected")
            .WithMessage($"Canonicalization method '{uri}' is not in the list of approved algorithms. Use one of: {string.Join(", ", XmlSigningOptions.AllowedCanonicalizationMethods)}*");
    }

    // ── XML-004: SignatureMethod Allowlist ─────────────────────────────────────

    [Fact]
    public void SignatureMethod_DefaultRsaSha256_IsValid()
    {
        var options = new XmlSigningOptions();
        options.SignatureMethod.Should().Be(SignedXml.XmlDsigRSASHA256Url);
    }

    [Theory]
    [InlineData("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256")] // RSA-SHA256
    [InlineData("http://www.w3.org/2001/04/xmldsig-more#rsa-sha384")] // RSA-SHA384
    [InlineData("http://www.w3.org/2001/04/xmldsig-more#rsa-sha512")] // RSA-SHA512
    public void SignatureMethod_AllowedValues_DoNotThrow(string uri)
    {
        var options = new XmlSigningOptions();
        var act = () => options.SignatureMethod = uri;
        act.Should().NotThrow(because: $"'{uri}' is an approved signature method");
        options.SignatureMethod.Should().Be(uri);
    }

    [Theory]
    [InlineData("http://www.w3.org/2000/09/xmldsig#rsa-sha1")]   // RSA-SHA1 — WEAK, must be blocked
    [InlineData("http://www.w3.org/2001/04/xmldsig-more#md5")]   // MD5 — WEAK, must be blocked
    [InlineData("http://attacker.example.com/custom-algo")]       // Unknown algorithm
    [InlineData("")]                                              // Empty string
    public void SignatureMethod_ForbiddenValues_ThrowArgumentException(string uri)
    {
        // XML-004 regression: before fix, RSA-SHA1 could be set, producing weak signatures.
        // After fix: only SHA-256, SHA-384, SHA-512 are accepted.
        var options = new XmlSigningOptions();
        var act = () => options.SignatureMethod = uri;
        act.Should().ThrowExactly<ArgumentException>(
            because: $"'{uri}' is either weak or unknown and must be rejected to prevent weak signature attacks")
            .WithMessage($"Signature method '{uri}' is not in the list of approved algorithms. Weak methods (e.g., RSA-SHA1) are not permitted. Use one of: {string.Join(", ", XmlSigningOptions.AllowedSignatureMethods)}*");
    }

    [Fact]
    public void SignatureMethod_RsaSha1_IsExplicitlyBlocked()
    {
        // This is the critical regression test: RSA-SHA1 was the original vulnerability.
        var options = new XmlSigningOptions();
        var act = () => options.SignatureMethod = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
        act.Should().ThrowExactly<ArgumentException>(
            because: "RSA-SHA1 produces weak signatures that can be forged with chosen-prefix attacks and must be explicitly rejected");
    }

    // ── DigestMethod Allowlist ─────────────────────────────────────────────────

    [Fact]
    public void DigestMethod_DefaultSha256_IsValid()
    {
        var options = new XmlSigningOptions();
        options.DigestMethod.Should().Be(SignedXml.XmlDsigSHA256Url);
    }

    [Theory]
    [InlineData("http://www.w3.org/2001/04/xmlenc#sha256")]  // SHA-256
    [InlineData("http://www.w3.org/2001/04/xmldsig-more#sha384")]  // SHA-384 (note: xmldsig-more, not xmlenc)
    [InlineData("http://www.w3.org/2001/04/xmlenc#sha512")]  // SHA-512
    public void DigestMethod_AllowedValues_DoNotThrow(string uri)
    {
        var options = new XmlSigningOptions();
        var act = () => options.DigestMethod = uri;
        act.Should().NotThrow(because: $"'{uri}' is an approved digest method");
        options.DigestMethod.Should().Be(uri);
    }

    [Theory]
    [InlineData("http://www.w3.org/2000/09/xmldsig#sha1")]   // SHA-1 — WEAK
    [InlineData("http://www.w3.org/2001/04/xmldsig-more#md5")] // MD5 — WEAK
    [InlineData("")]                                            // Empty
    public void DigestMethod_ForbiddenValues_ThrowArgumentException(string uri)
    {
        var options = new XmlSigningOptions();
        var act = () => options.DigestMethod = uri;
        act.Should().ThrowExactly<ArgumentException>(
            because: $"'{uri}' is a weak or unknown digest and must be rejected")
            .WithMessage($"Digest method '{uri}' is not in the list of approved algorithms. Use one of: {string.Join(", ", XmlSigningOptions.AllowedDigestMethods)}*");
    }

    // ── Immutable Defaults ─────────────────────────────────────────────────────

    [Fact]
    public void XmlSigningOptions_Defaults_AreSecure()
    {
        // All defaults must be strong algorithm URIs
        var options = new XmlSigningOptions();

        options.CanonicalizationMethod.Should().Be(SignedXml.XmlDsigC14NTransformUrl);
        options.SignatureMethod.Should().Be(SignedXml.XmlDsigRSASHA256Url);
        options.DigestMethod.Should().Be(SignedXml.XmlDsigSHA256Url);
        options.IncludeKeyInfo.Should().BeTrue();
        options.ReferenceUri.Should().Be(string.Empty);
    }

    [Fact]
    public void AllowedSets_ArePubliclyAccessible_ForPolicyEnforcement()
    {
        // The allowed algorithm sets are public so PEPs can use them for their own validation
        XmlSigningOptions.AllowedSignatureMethods.Should().NotBeEmpty();
        XmlSigningOptions.AllowedCanonicalizationMethods.Should().NotBeEmpty();
        XmlSigningOptions.AllowedDigestMethods.Should().NotBeEmpty();

        // RSA-SHA1 must not be in the allowed signature methods
        XmlSigningOptions.AllowedSignatureMethods.Should().NotContain(
            "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
            because: "RSA-SHA1 is weak and must never be in the approved list");
    }

    [Fact]
    public void XmlVerificationOptions_AllowedTransformAlgorithms_ContainsExpectedStandardAlgorithms()
    {
        var options = new XmlVerificationOptions();
        options.AllowedTransformAlgorithms.Should().Contain([
            "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
            "http://www.w3.org/TR/2001/REC-xml-c14n-20010315",
            "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments",
            "http://www.w3.org/2001/10/xml-exc-c14n#",
            "http://www.w3.org/2001/10/xml-exc-c14n#WithComments",
            "http://www.w3.org/2000/09/xmldsig#base64"
        ]);
        options.AllowedTransformAlgorithms.Should().NotContain("");
    }
}
