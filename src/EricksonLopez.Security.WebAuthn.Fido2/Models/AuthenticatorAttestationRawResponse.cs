// Copyright © Erickson Lopez. MIT License.

using System;

namespace EricksonLopez.Security.WebAuthn.Fido2.Models;

/// <summary>
/// Represents the raw response payload returned from the client browser after <c>navigator.credentials.create()</c>.
/// </summary>
public sealed record AuthenticatorAttestationRawResponse
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
    /// Gets the raw CBOR-encoded bytes of attestationObject.
    /// </summary>
    public byte[] AttestationObject { get; init; }

    /// <summary>
    /// Initializes a new instance of the <see cref="AuthenticatorAttestationRawResponse"/> record with the specified response components.
    /// </summary>
    /// <param name="id">The base64url-encoded credential identifier.</param>
    /// <param name="rawId">The raw binary credential ID.</param>
    /// <param name="clientDataJson">The UTF-8 JSON bytes of clientDataJSON.</param>
    /// <param name="attestationObject">The raw CBOR-encoded bytes of attestationObject.</param>
    /// <exception cref="ArgumentNullException"><paramref name="rawId"/>, <paramref name="clientDataJson"/>, or <paramref name="attestationObject"/> is <see langword="null"/></exception>
    /// <exception cref="ArgumentException"><paramref name="id"/> is <see langword="null"/>, empty, or whitespace</exception>
    public AuthenticatorAttestationRawResponse(string id, byte[] rawId, byte[] clientDataJson, byte[] attestationObject)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(id);
        ArgumentNullException.ThrowIfNull(rawId);
        ArgumentNullException.ThrowIfNull(clientDataJson);
        ArgumentNullException.ThrowIfNull(attestationObject);

        Id = id;
        RawId = rawId;
        ClientDataJson = clientDataJson;
        AttestationObject = attestationObject;
    }
}
