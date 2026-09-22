// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Saml2.Models;

using System;
using System.Security.Claims;

/// <summary>
/// Represents the validated output of a SAML 2.0 authentication response ceremony.
/// </summary>
public sealed record Saml2AuthenticationResult
{
    /// <summary>
    /// Gets the principal identity constructed from the SAML assertion and attributes.
    /// </summary>
    public ClaimsPrincipal Principal { get; init; }

    /// <summary>
    /// Gets the validated SAML 2.0 assertion.
    /// </summary>
    public Saml2Assertion Assertion { get; init; }

    /// <summary>
    /// Gets the Identity Provider Entity ID.
    /// </summary>
    public string Issuer => Assertion.Issuer;

    /// <summary>
    /// Gets the primary NameID value.
    /// </summary>
    public string NameId => Assertion.Subject.NameId.Value;

    /// <summary>
    /// Gets the optional session index for single logout (SLO).
    /// </summary>
    public string? SessionIndex => Assertion.AuthnStatement?.SessionIndex;

    /// <summary>
    /// Initializes a new instance of the <see cref="Saml2AuthenticationResult"/> record with the validated principal and assertion.
    /// </summary>
    /// <param name="principal">The authenticated claims principal constructed from the assertion.</param>
    /// <param name="assertion">The validated SAML 2.0 assertion.</param>
    /// <exception cref="ArgumentNullException"><paramref name="principal"/> or <paramref name="assertion"/> is <see langword="null"/></exception>
    public Saml2AuthenticationResult(ClaimsPrincipal principal, Saml2Assertion assertion)
    {
        Principal = principal ?? throw new ArgumentNullException(nameof(principal));
        Assertion = assertion ?? throw new ArgumentNullException(nameof(assertion));
    }
}
