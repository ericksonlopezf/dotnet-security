// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Saml2.Models;

using System;

/// <summary>
/// Represents a SAML 2.0 AuthnStatement detailing the authentication event.
/// </summary>
public sealed record Saml2AuthnStatement
{
    /// <summary>
    /// Gets the instant at which the authentication took place at the IdP.
    /// </summary>
    public DateTimeOffset AuthnInstant { get; init; }

    /// <summary>
    /// Gets the optional session index identifier assigned by the IdP.
    /// </summary>
    public string? SessionIndex { get; init; }

    /// <summary>
    /// Gets the optional session expiration timestamp.
    /// </summary>
    public DateTimeOffset? SessionNotOnOrAfter { get; init; }

    /// <summary>
    /// Gets the authentication context class reference URI (e.g. PasswordProtectedTransport).
    /// </summary>
    public string? AuthnContextClassRef { get; init; }

    /// <summary>
    /// Initializes a new instance of the <see cref="Saml2AuthnStatement"/> record with the specified authentication event details.
    /// </summary>
    /// <param name="authnInstant">The instant at which the authentication took place at the Identity Provider.</param>
    /// <param name="sessionIndex">The optional session index identifier assigned by the Identity Provider.</param>
    /// <param name="sessionNotOnOrAfter">The optional session expiration timestamp.</param>
    /// <param name="authnContextClassRef">The optional authentication context class reference URI.</param>
    public Saml2AuthnStatement(
        DateTimeOffset authnInstant,
        string? sessionIndex = null,
        DateTimeOffset? sessionNotOnOrAfter = null,
        string? authnContextClassRef = null)
    {
        AuthnInstant = authnInstant;
        SessionIndex = sessionIndex;
        SessionNotOnOrAfter = sessionNotOnOrAfter;
        AuthnContextClassRef = authnContextClassRef;
    }
}
