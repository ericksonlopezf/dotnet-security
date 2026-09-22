// Copyright © Erickson Lopez. MIT License.
using System.Security.Cryptography.X509Certificates;
using System.Xml;
using EricksonLopez.Result;

namespace EricksonLopez.Security.Cryptography.XmlDSig;

/// <summary>
/// Defines capabilities for generating W3C XML Digital Signatures (XMLDSig).
/// </summary>
public interface IXmlDigitalSigner
{
    /// <summary>
    /// Signs an XML string using the specified X.509 certificate and options, returning the signed XML string.
    /// </summary>
    /// <param name="xmlContent">The raw XML content to sign.</param>
    /// <param name="certificate">The X.509 certificate containing an accessible RSA private key.</param>
    /// <param name="options">Optional XML signing options.</param>
    /// <returns>A successful result containing the signed XML text, or an error describing the failure.</returns>
    Result<string> SignXml(string xmlContent, X509Certificate2 certificate, XmlSigningOptions? options = null);

    /// <summary>
    /// Signs an <see cref="XmlDocument"/> in-place using the specified X.509 certificate and options.
    /// </summary>
    /// <param name="document">The XML document to sign.</param>
    /// <param name="certificate">The X.509 certificate containing an accessible RSA private key.</param>
    /// <param name="options">Optional XML signing options.</param>
    /// <returns>A successful result containing the signed <see cref="XmlDocument"/>, or an error describing the failure.</returns>
    Result<XmlDocument> SignXml(XmlDocument document, X509Certificate2 certificate, XmlSigningOptions? options = null);
}
