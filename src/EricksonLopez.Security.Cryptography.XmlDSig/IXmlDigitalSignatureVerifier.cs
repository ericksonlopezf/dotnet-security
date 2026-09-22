// Copyright © Erickson Lopez. MIT License.
using System.Security.Cryptography.X509Certificates;
using System.Xml;
using EricksonLopez.Result;

namespace EricksonLopez.Security.Cryptography.XmlDSig;

/// <summary>
/// Defines capabilities for verifying W3C XML Digital Signatures (XMLDSig).
/// </summary>
public interface IXmlDigitalSignatureVerifier
{
    /// <summary>
    /// Verifies the digital signature in an XML string.
    /// </summary>
    /// <param name="xmlContent">The signed XML content.</param>
    /// <param name="expectedCertificate">Optional expected certificate. If omitted, uses embedded certificate in KeyInfo.</param>
    /// <returns>A successful result with <see langword="true"/> if signature is valid, or an error describing the verification failure.</returns>
    Result<bool> VerifyXml(string xmlContent, X509Certificate2? expectedCertificate = null);

    /// <summary>
    /// Verifies the digital signature in an XML string with custom verification options.
    /// </summary>
    /// <param name="xmlContent">The signed XML content.</param>
    /// <param name="expectedCertificate">Optional expected certificate.</param>
    /// <param name="options">Optional verification options.</param>
    /// <returns>A successful result with <see langword="true"/> if signature is valid, or an error describing the verification failure.</returns>
    Result<bool> VerifyXml(string xmlContent, X509Certificate2? expectedCertificate, XmlVerificationOptions? options);

    /// <summary>
    /// Verifies the digital signature in an <see cref="XmlDocument"/>.
    /// </summary>
    /// <param name="document">The signed XML document.</param>
    /// <param name="expectedCertificate">Optional expected certificate. If omitted, uses embedded certificate in KeyInfo.</param>
    /// <returns>A successful result with <see langword="true"/> if signature is valid, or an error describing the verification failure.</returns>
    Result<bool> VerifyXml(XmlDocument document, X509Certificate2? expectedCertificate = null);

    /// <summary>
    /// Verifies the digital signature in an <see cref="XmlDocument"/> with custom verification options.
    /// </summary>
    /// <param name="document">The signed XML document.</param>
    /// <param name="expectedCertificate">Optional expected certificate.</param>
    /// <param name="options">Optional verification options.</param>
    /// <returns>A successful result with <see langword="true"/> if signature is valid, or an error describing the verification failure.</returns>
    Result<bool> VerifyXml(XmlDocument document, X509Certificate2? expectedCertificate, XmlVerificationOptions? options);

    /// <summary>
    /// Verifies the digital signature in an <see cref="XmlDocument"/> and extracts the cryptographically verified
    /// signed <see cref="XmlElement"/>, mitigating XML Signature Wrapping (XSW) attacks.
    /// </summary>
    /// <param name="document">The signed XML document.</param>
    /// <param name="expectedCertificate">Optional expected certificate.</param>
    /// <param name="options">Optional verification options.</param>
    /// <returns>A result containing the <see cref="XmlVerificationResult"/> on success, or an error describing failure.</returns>
    Result<XmlVerificationResult> VerifyAndExtractSignedElement(
        XmlDocument document,
        X509Certificate2? expectedCertificate = null,
        XmlVerificationOptions? options = null);
}
