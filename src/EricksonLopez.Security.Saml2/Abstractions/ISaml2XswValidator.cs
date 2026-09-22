// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Saml2.Abstractions;

using System.Xml;
using EricksonLopez.Result;

/// <summary>
/// Defines the defense contract against XML Signature Wrapping (XSW) vulnerabilities (XSW1 to XSW8).
/// </summary>
public interface ISaml2XswValidator
{
    /// <summary>
    /// Validates the XML document structure to ensure the verified signed element matches the exact
    /// element consumed by the business logic, rejecting any malicious signature wrapping or element injection.
    /// </summary>
    /// <param name="document">The XML document containing the SAML response.</param>
    /// <returns>A result containing the validated canonical assertion XML element on success.</returns>
    Result<XmlElement> ValidateAndExtractAssertion(XmlDocument document);
}
