// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Saml2.Models;

using EricksonLopez.Security.Saml2.Enums;

/// <summary>
/// Represents the status payload of a SAML 2.0 response.
/// </summary>
public sealed record Saml2Status
{
    /// <summary>
    /// Gets the primary status code.
    /// </summary>
    public Saml2StatusCode Code { get; init; }

    /// <summary>
    /// Gets the optional secondary sub-status code URI string.
    /// </summary>
    public string? SubCode { get; init; }

    /// <summary>
    /// Gets the optional human-readable status message from the IdP.
    /// </summary>
    public string? Message { get; init; }

    /// <summary>
    /// Gets a value indicating whether the status code indicates successful authentication.
    /// </summary>
    public bool IsSuccess => Code == Saml2StatusCode.Success;

    /// <summary>
    /// Initializes a new instance of the <see cref="Saml2Status"/> record with the specified status code and optional details.
    /// </summary>
    /// <param name="code">The primary status code.</param>
    /// <param name="subCode">The optional secondary sub-status code URI string.</param>
    /// <param name="message">The optional human-readable status message from the Identity Provider.</param>
    public Saml2Status(Saml2StatusCode code, string? subCode = null, string? message = null)
    {
        Code = code;
        SubCode = subCode;
        Message = message;
    }
}
