// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Saml2.Enums;

/// <summary>
/// Defines top-level SAML 2.0 response status codes.
/// </summary>
public enum Saml2StatusCode
{
    /// <summary>
    /// Specifies that the request succeeded (<c>urn:oasis:names:tc:SAML:2.0:status:Success</c>).
    /// </summary>
    Success = 1,

    /// <summary>
    /// Specifies that the request could not be fulfilled due to requester error (<c>urn:oasis:names:tc:SAML:2.0:status:Requester</c>).
    /// </summary>
    Requester = 2,

    /// <summary>
    /// Specifies that the request could not be fulfilled due to responder error (<c>urn:oasis:names:tc:SAML:2.0:status:Responder</c>).
    /// </summary>
    Responder = 3,

    /// <summary>
    /// Specifies that the responder does not support the request version (<c>urn:oasis:names:tc:SAML:2.0:status:VersionMismatch</c>).
    /// </summary>
    VersionMismatch = 4,

    /// <summary>
    /// Specifies that authentication failed at the Identity Provider (<c>urn:oasis:names:tc:SAML:2.0:status:AuthnFailed</c>).
    /// </summary>
    AuthnFailed = 5
}
