// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Saml2.Abstractions;

using System.Security.Cryptography.X509Certificates;
using System.Xml;
using EricksonLopez.Result;
using EricksonLopez.Security.Saml2.Enums;
using Result = global::EricksonLopez.Result.Result;

/// <summary>
/// Defines the contract for validating XMLDSig digital signatures on SAML 2.0 messages and assertions.
/// </summary>
public interface ISaml2SignatureValidator
{
    /// <summary>
    /// Verifies the digital signature on a specific XML element against the provided certificate.
    /// </summary>
    /// <param name="element">The XML element containing or targeted by the XMLDSig signature.</param>
    /// <param name="certificate">The trusted certificate.</param>
    /// <returns>A result indicating whether the signature is cryptographically valid.</returns>
    Result VerifySignature(XmlElement element, X509Certificate2 certificate);

    /// <summary>
    /// Signs an XML element using the provided certificate and appends the XMLDSig signature block.
    /// </summary>
    /// <param name="element">The target XML element.</param>
    /// <param name="certificate">The signing certificate with private key.</param>
    /// <returns>A result indicating whether the signing operation succeeded.</returns>
    Result SignElement(XmlElement element, X509Certificate2 certificate);
}
