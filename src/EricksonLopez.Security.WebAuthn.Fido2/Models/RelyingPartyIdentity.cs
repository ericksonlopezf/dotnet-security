// Copyright © Erickson Lopez. MIT License.

using System;

namespace EricksonLopez.Security.WebAuthn.Fido2.Models;

/// <summary>
/// Represents the Relying Party (RP) identity in WebAuthn ceremonies.
/// </summary>
public sealed record RelyingPartyIdentity
{
    /// <summary>
    /// Gets the unique Relying Party identifier (domain name, e.g. "example.com" or "localhost").
    /// </summary>
    public string Id { get; init; }

    /// <summary>
    /// Gets the human-palatable name of the Relying Party (e.g. "EricksonLopez Corporation").
    /// </summary>
    public string Name { get; init; }

    /// <summary>
    /// Gets an optional icon URL for the Relying Party.
    /// </summary>
    public string? Icon { get; init; }

    /// <summary>
    /// Initializes a new instance of the <see cref="RelyingPartyIdentity"/> record.
    /// </summary>
    /// <param name="id">The RP identifier domain name.</param>
    /// <param name="name">The RP display name.</param>
    /// <param name="icon">The optional icon URL.</param>
    /// <exception cref="ArgumentException"><paramref name="id"/> or <paramref name="name"/> is <see langword="null"/>, empty, or whitespace</exception>
    public RelyingPartyIdentity(string id, string name, string? icon = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(id);
        ArgumentException.ThrowIfNullOrWhiteSpace(name);

        Id = id;
        Name = name;
        Icon = icon;
    }
}
