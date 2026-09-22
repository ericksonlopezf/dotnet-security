// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Saml2.Enums;

/// <summary>
/// Specifies the location of an XML digital signature within a SAML 2.0 message.
/// </summary>
public enum Saml2SignatureLocation
{
    /// <summary>
    /// Specifies that the signature is placed at the top-level <c>&lt;samlp:Response&gt;</c> element.
    /// </summary>
    Response = 1,

    /// <summary>
    /// Specifies that the signature is placed inside individual <c>&lt;saml:Assertion&gt;</c> elements.
    /// </summary>
    Assertion = 2,

    /// <summary>
    /// Specifies that both the Response and the Assertion elements are digitally signed.
    /// </summary>
    Both = 3
}
