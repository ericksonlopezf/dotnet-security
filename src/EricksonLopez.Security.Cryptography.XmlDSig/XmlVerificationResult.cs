// Copyright © Erickson Lopez. MIT License.
namespace EricksonLopez.Security.Cryptography.XmlDSig;

using System.Security.Cryptography.X509Certificates;
using System.Xml;

/// <summary>
/// Encapsulates the verified XML element, reference URI, and signing certificate
/// resulting from a successful cryptographic XML signature validation.
/// Protects against XML Signature Wrapping (XSW) attacks by binding the verified element.
/// </summary>
public sealed class XmlVerificationResult
{
    /// <summary>
    /// Gets a value indicating whether cryptographic signature verification succeeded.
    /// </summary>
    public bool IsValid { get; }

    /// <summary>
    /// Gets the verified <see cref="XmlElement"/> that was actually signed in the signature manifest.
    /// Consumers must process this element rather than untrusted sibling or parent nodes to prevent XSW attacks.
    /// </summary>
    public XmlElement? SignedElement { get; }

    /// <summary>
    /// Gets the signature reference URI (e.g. "" for whole document, or "#elementId").
    /// </summary>
    public string? ReferenceUri { get; }

    /// <summary>
    /// Gets the certificate that verified the signature, if available.
    /// </summary>
    public X509Certificate2? SigningCertificate { get; }

    /// <summary>
    /// Initializes a new instance of the <see cref="XmlVerificationResult"/> class.
    /// </summary>
    /// <param name="isValid">A value indicating whether cryptographic signature verification succeeded</param>
    /// <param name="signedElement">The verified XML element from the signature manifest</param>
    /// <param name="referenceUri">The signature reference URI</param>
    /// <param name="signingCertificate">The certificate that verified the signature</param>
    public XmlVerificationResult(
        bool isValid,
        XmlElement? signedElement,
        string? referenceUri,
        X509Certificate2? signingCertificate)
    {
        IsValid = isValid;
        SignedElement = signedElement;
        ReferenceUri = referenceUri;
        SigningCertificate = signingCertificate;
    }
}
