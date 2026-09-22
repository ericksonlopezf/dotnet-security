// Copyright © Erickson Lopez. MIT License.

using System;

namespace EricksonLopez.Security.WebAuthn.Fido2.Models;

/// <summary>
/// Represents the raw response payload returned from the client browser after <c>navigator.credentials.get()</c>.
/// </summary>
public sealed record AuthenticatorAssertionRawResponse
{
    /// <summary>
    /// Gets the base64url-encoded credential identifier.
    /// </summary>
    public string Id { get; init; }

    /// <summary>
    /// Gets the raw binary credential ID.
    /// </summary>
    public byte[] RawId { get; init; }

    /// <summary>
    /// Gets the UTF-8 JSON bytes of clientDataJSON.
    /// </summary>
    public byte[] ClientDataJson { get; init; }

    /// <summary>
    /// Gets the raw binary authenticatorData bytes.
    /// </summary>
    public byte[] AuthenticatorData { get; init; }

    /// <summary>
    /// Gets the raw binary signature produced by the authenticator over <c>authData || SHA256(clientDataJSON)</c>.
    /// </summary>
    public byte[] Signature { get; init; }

    /// <summary>
    /// Gets the optional user handle (opaque user identifier returned in discoverable / passkey flows).
    /// </summary>
    public byte[]? UserHandle { get; init; }

    /// <summary>
    /// Initializes a new instance of the <see cref="AuthenticatorAssertionRawResponse"/> record with the specified response components.
    /// </summary>
    /// <param name="id">The base64url-encoded credential identifier.</param>
    /// <param name="rawId">The raw binary credential ID.</param>
    /// <param name="clientDataJson">The UTF-8 JSON bytes of clientDataJSON.</param>
    /// <param name="authenticatorData">The raw binary authenticatorData bytes.</param>
    /// <param name="signature">The raw binary signature produced by the authenticator.</param>
    /// <param name="userHandle">The optional user handle.</param>
    /// <exception cref="ArgumentNullException"><paramref name="rawId"/>, <paramref name="clientDataJson"/>, <paramref name="authenticatorData"/>, or <paramref name="signature"/> is <see langword="null"/></exception>
    /// <exception cref="ArgumentException"><paramref name="id"/> is <see langword="null"/>, empty, or whitespace</exception>
    public AuthenticatorAssertionRawResponse(
        string id,
        byte[] rawId,
        byte[] clientDataJson,
        byte[] authenticatorData,
        byte[] signature,
        byte[]? userHandle = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(id);
        ArgumentNullException.ThrowIfNull(rawId);
        ArgumentNullException.ThrowIfNull(clientDataJson);
        ArgumentNullException.ThrowIfNull(authenticatorData);
        ArgumentNullException.ThrowIfNull(signature);

        Id = id;
        RawId = rawId;
        ClientDataJson = clientDataJson;
        AuthenticatorData = authenticatorData;
        Signature = signature;
        UserHandle = userHandle;
    }
}
