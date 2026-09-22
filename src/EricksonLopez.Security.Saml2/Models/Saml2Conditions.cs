// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Saml2.Models;

using System;
using System.Collections.Generic;

/// <summary>
/// Represents the validity conditions and audience restrictions for a SAML 2.0 assertion.
/// </summary>
public sealed record Saml2Conditions
{
    /// <summary>
    /// Gets the earliest instant at which the assertion is valid.
    /// </summary>
    public DateTimeOffset? NotBefore { get; init; }

    /// <summary>
    /// Gets the instant at which the assertion expires and is no longer valid.
    /// </summary>
    public DateTimeOffset? NotOnOrAfter { get; init; }

    /// <summary>
    /// Gets the list of valid audience URIs (Entity IDs) allowed to consume the assertion.
    /// </summary>
    public IReadOnlyList<string> Audiences { get; init; }

    /// <summary>
    /// Initializes a new instance of the <see cref="Saml2Conditions"/> record with optional validity window and audience constraints.
    /// </summary>
    /// <param name="notBefore">The optional earliest instant at which the assertion is valid.</param>
    /// <param name="notOnOrAfter">The optional instant at which the assertion expires.</param>
    /// <param name="audiences">The optional list of valid audience URIs allowed to consume the assertion.</param>
    public Saml2Conditions(
        DateTimeOffset? notBefore = null,
        DateTimeOffset? notOnOrAfter = null,
        IReadOnlyList<string>? audiences = null)
    {
        NotBefore = notBefore;
        NotOnOrAfter = notOnOrAfter;
        Audiences = audiences ?? Array.Empty<string>();
    }
}
