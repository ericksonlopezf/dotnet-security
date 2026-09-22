// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Saml2.Models;

using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;

/// <summary>
/// Represents a SAML 2.0 user attribute emitted by the Identity Provider.
/// </summary>
[SuppressMessage("Naming", "CA1711:Identifiers should not have incorrect suffix", Justification = "Standard SAML 2.0 Attribute specification nomenclature.")]
public sealed record Saml2Attribute
{
    /// <summary>
    /// Gets the attribute name (URI or friendly string).
    /// </summary>
    public string Name { get; init; }

    /// <summary>
    /// Gets the optional friendly name of the attribute.
    /// </summary>
    public string? FriendlyName { get; init; }

    /// <summary>
    /// Gets the attribute name format URI.
    /// </summary>
    public string? NameFormat { get; init; }

    /// <summary>
    /// Gets the list of string values for the attribute.
    /// </summary>
    public IReadOnlyList<string> Values { get; init; }

    /// <summary>
    /// Initializes a new instance of the <see cref="Saml2Attribute"/> record with the specified attribute details.
    /// </summary>
    /// <param name="name">The attribute name URI or friendly identifier.</param>
    /// <param name="values">The list of attribute string values.</param>
    /// <param name="friendlyName">The optional human-readable attribute friendly name.</param>
    /// <param name="nameFormat">The optional URI classifying the attribute name format.</param>
    /// <exception cref="ArgumentException"><paramref name="name"/> is <see langword="null"/>, empty, or whitespace</exception>
    public Saml2Attribute(
        string name,
        IReadOnlyList<string> values,
        string? friendlyName = null,
        string? nameFormat = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        Name = name;
        Values = values ?? Array.Empty<string>();
        FriendlyName = friendlyName;
        NameFormat = nameFormat;
    }
}
