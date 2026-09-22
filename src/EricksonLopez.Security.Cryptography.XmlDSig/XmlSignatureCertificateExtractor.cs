// Copyright © Erickson Lopez. MIT License.
using System;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;
using EricksonLopez.Result;

namespace EricksonLopez.Security.Cryptography.XmlDSig;

/// <summary>
/// Provides utility methods for extracting embedded X.509 certificates from XML Digital Signatures (&lt;Signature&gt; elements).
/// </summary>
public static class XmlSignatureCertificateExtractor
{
    /// <summary>
    /// Extracts the first embedded <see cref="X509Certificate2"/> from an XML string containing an XMLDSig signature.
    /// </summary>
    /// <param name="xmlContent">The raw XML content.</param>
    /// <returns>A successful result containing the certificate, or an error if missing or invalid.</returns>
    public static Result<X509Certificate2> ExtractCertificate(string xmlContent)
    {
        if (string.IsNullOrWhiteSpace(xmlContent))
        {
            return Error.Validation("XmlSignatureCertificateExtractor.EmptyXml", "XML content cannot be null or empty.");
        }

        try
        {
            var doc = new XmlDocument();
            // Stryker disable once Initializer : Required for defense-in-depth OWASP XML DTD security configuration
            using var reader = XmlReader.Create(new System.IO.StringReader(xmlContent), new XmlReaderSettings
            {
                DtdProcessing = DtdProcessing.Prohibit,
                XmlResolver = null
            });
            doc.Load(reader);
            return ExtractCertificate(doc);
        }
        catch (Exception ex)
        {
            return Error.Failure("XmlSignatureCertificateExtractor.XmlLoadFailed", $"Failed to parse XML document: {ex.Message}");
        }
    }

    /// <summary>
    /// Extracts the first embedded <see cref="X509Certificate2"/> from an <see cref="XmlDocument"/> containing an XMLDSig signature.
    /// </summary>
    /// <param name="document">The XML document.</param>
    /// <returns>A successful result containing the certificate, or an error if missing or invalid.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="document"/> is <see langword="null"/></exception>
    public static Result<X509Certificate2> ExtractCertificate(XmlDocument document)
    {
        ArgumentNullException.ThrowIfNull(document);

        var signatureNodes = document.GetElementsByTagName("Signature", SignedXml.XmlDsigNamespaceUrl);
        if (signatureNodes.Count == 0)
        {
            return Error.NotFound("XmlSignatureCertificateExtractor.SignatureNotFound", "No <Signature> element found in the document.");
        }

        var signatureElement = (XmlElement)signatureNodes[0]!;
        var certNodes = signatureElement.GetElementsByTagName("X509Certificate", SignedXml.XmlDsigNamespaceUrl);
        if (certNodes.Count == 0)
        {
            return Error.NotFound("XmlSignatureCertificateExtractor.CertificateNotFound", "No <X509Certificate> element found inside the <Signature>.");
        }

        var certBase64 = certNodes[0]!.InnerText.Trim();
        if (string.IsNullOrEmpty(certBase64))
        {
            return Error.Validation("XmlSignatureCertificateExtractor.EmptyCertificateData", "The <X509Certificate> node contains empty data.");
        }

        try
        {
            var rawBytes = Convert.FromBase64String(certBase64);
#if NET9_0_OR_GREATER
            var certificate = X509CertificateLoader.LoadCertificate(rawBytes);
#else
#pragma warning disable SYSLIB0057
            var certificate = new X509Certificate2(rawBytes);
#pragma warning restore SYSLIB0057
#endif
            return Result<X509Certificate2>.Success(certificate);
        }
        catch (Exception ex)
        {
            return Error.Failure("XmlSignatureCertificateExtractor.InvalidCertificateData", $"Failed to decode X.509 certificate from Base64: {ex.Message}");
        }
    }
}
