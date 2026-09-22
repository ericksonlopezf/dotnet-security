// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Saml2.Enums;

/// <summary>
/// Defines SAML 2.0 protocol binding profiles.
/// </summary>
public enum Saml2Binding
{
    /// <summary>
    /// Specifies the HTTP POST binding (<c>urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST</c>).
    /// </summary>
    HttpPost = 1,

    /// <summary>
    /// Specifies the HTTP Redirect binding (<c>urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect</c>).
    /// </summary>
    HttpRedirect = 2,

    /// <summary>
    /// Specifies the HTTP Artifact binding (<c>urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact</c>).
    /// </summary>
    HttpArtifact = 3,

    /// <summary>
    /// Specifies the SOAP binding (<c>urn:oasis:names:tc:SAML:2.0:bindings:SOAP</c>).
    /// </summary>
    Soap = 4
}
