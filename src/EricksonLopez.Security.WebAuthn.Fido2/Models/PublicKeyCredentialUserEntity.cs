// Copyright © Erickson Lopez. MIT License.

using System;

namespace EricksonLopez.Security.WebAuthn.Fido2.Models;

/// <summary>
/// Represents a user account entity for which a public key credential is created.
/// </summary>
public sealed record PublicKeyCredentialUserEntity
{
    /// <summary>
    /// Gets the user handle (an opaque byte sequence identifying the user account, max 64 bytes).
    /// </summary>
    public byte[] Id { get; init; }

    /// <summary>
    /// Gets the user's account identifier (e.g. username or email address).
    /// </summary>
    public string Name { get; init; }

    /// <summary>
    /// Gets the user's friendly display name (e.g. "Erickson Lopez").
    /// </summary>
    public string DisplayName { get; init; }

    /// <summary>
    /// Gets an optional icon URL for the user entity.
    /// </summary>
    public string? Icon { get; init; }

    /// <summary>
    /// Initializes a new instance of the <see cref="PublicKeyCredentialUserEntity"/> record with the specified user account details.
    /// </summary>
    /// <param name="id">The user handle opaque byte sequence identifying the user account (between 1 and 64 bytes).</param>
    /// <param name="name">The user's account identifier (e.g., username or email address).</param>
    /// <param name="displayName">The user's friendly display name.</param>
    /// <param name="icon">The optional icon URL for the user entity.</param>
    /// <exception cref="ArgumentNullException"><paramref name="id"/> is <see langword="null"/></exception>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="id"/> length is 0 or greater than 64 bytes</exception>
    /// <exception cref="ArgumentException"><paramref name="name"/> or <paramref name="displayName"/> is <see langword="null"/>, empty, or whitespace</exception>
    public PublicKeyCredentialUserEntity(byte[] id, string name, string displayName, string? icon = null)
    {
        ArgumentNullException.ThrowIfNull(id);
        if (id.Length == 0 || id.Length > 64)
        {
            throw new ArgumentOutOfRangeException(nameof(id), "User ID must be between 1 and 64 bytes in length.");
        }
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        ArgumentException.ThrowIfNullOrWhiteSpace(displayName);

        Id = id;
        Name = name;
        DisplayName = displayName;
        Icon = icon;
    }
}
