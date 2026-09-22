// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Saml2.Models;

using System;
using EricksonLopez.Security.Saml2.Enums;

/// <summary>
/// Represents a SAML 2.0 NameID element containing the principal's identifier.
/// </summary>
public sealed record Saml2NameId
{
    /// <summary>
    /// Gets the NameID value string.
    /// </summary>
    public string Value { get; init; }

    /// <summary>
    /// Gets the NameID format identifier.
    /// </summary>
    public Saml2NameIdFormat Format { get; init; }

    /// <summary>
    /// Gets the optional NameQualifier string.
    /// </summary>
    public string? NameQualifier { get; init; }

    /// <summary>
    /// Gets the optional SPNameQualifier string.
    /// </summary>
    public string? SpNameQualifier { get; init; }

    /// <summary>
    /// Initializes a new instance of the <see cref="Saml2NameId"/> record with the specified identifier and optional qualifiers.
    /// </summary>
    /// <param name="value">The NameID value string.</param>
    /// <param name="format">The NameID format identifier.</param>
    /// <param name="nameQualifier">The optional NameQualifier string.</param>
    /// <param name="spNameQualifier">The optional SPNameQualifier string.</param>
    /// <exception cref="ArgumentException"><paramref name="value"/> is <see langword="null"/>, empty, or whitespace</exception>
    public Saml2NameId(string value, Saml2NameIdFormat format = Saml2NameIdFormat.Unspecified, string? nameQualifier = null, string? spNameQualifier = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        Value = value;
        Format = format;
        NameQualifier = nameQualifier;
        SpNameQualifier = spNameQualifier;
    }
}
