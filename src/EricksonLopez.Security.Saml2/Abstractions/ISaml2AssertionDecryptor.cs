// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Saml2.Abstractions;

using System.Security.Cryptography.X509Certificates;
using System.Xml;
using EricksonLopez.Result;

/// <summary>
/// Defines the contract for decrypting SAML 2.0 <c>&lt;saml:EncryptedAssertion&gt;</c> XML payloads.
/// </summary>
public interface ISaml2AssertionDecryptor
{
    /// <summary>
    /// Decrypts an encrypted assertion element using the Service Provider's private key.
    /// </summary>
    /// <param name="encryptedAssertionElement">The <c>&lt;saml:EncryptedAssertion&gt;</c> XML element.</param>
    /// <param name="decryptionCertificate">The certificate containing the SP private key.</param>
    /// <returns>A result containing the decrypted <c>&lt;saml:Assertion&gt;</c> XML element on success.</returns>
    Result<XmlElement> DecryptAssertion(XmlElement encryptedAssertionElement, X509Certificate2 decryptionCertificate);
}
