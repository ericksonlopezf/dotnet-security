// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Saml2.Enums;

/// <summary>
/// Defines standard SAML 2.0 NameID format identifiers.
/// </summary>
public enum Saml2NameIdFormat
{
    /// <summary>
    /// Specifies the unspecified NameID format (<c>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</c>).
    /// </summary>
    Unspecified = 0,

    /// <summary>
    /// Specifies the email address NameID format (<c>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</c>).
    /// </summary>
    EmailAddress = 1,

    /// <summary>
    /// Specifies the persistent pseudorandom NameID format (<c>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</c>).
    /// </summary>
    Persistent = 2,

    /// <summary>
    /// Specifies the transient session-only NameID format (<c>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</c>).
    /// </summary>
    Transient = 3,

    /// <summary>
    /// Specifies the X.509 Subject Name format (<c>urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName</c>).
    /// </summary>
    X509SubjectName = 4
}
