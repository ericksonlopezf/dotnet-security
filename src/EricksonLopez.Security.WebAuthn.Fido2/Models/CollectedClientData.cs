// Copyright © Erickson Lopez. MIT License.

using System;

namespace EricksonLopez.Security.WebAuthn.Fido2.Models;

/// <summary>
/// Represents the parsed JSON data sent by the browser client in <c>clientDataJSON</c>.
/// </summary>
public sealed record CollectedClientData
{
    /// <summary>
    /// Gets the operation type (<c>webauthn.create</c> for registration, <c>webauthn.get</c> for authentication).
    /// </summary>
    public string Type { get; init; }

    /// <summary>
    /// Gets the base64url-encoded challenge sent by the server.
    /// </summary>
    public string Challenge { get; init; }

    /// <summary>
    /// Gets the fully-qualified origin of the caller (e.g. <c>https://example.com:443</c>).
    /// </summary>
    public string Origin { get; init; }

    /// <summary>
    /// Gets a value indicating whether the request was executed in a cross-origin iframe context.
    /// </summary>
    public bool? CrossOrigin { get; init; }

    /// <summary>
    /// Gets the raw UTF-8 bytes of the client data JSON.
    /// </summary>
    public byte[] RawClientDataJson { get; init; }

    /// <summary>
    /// Initializes a new instance of the <see cref="CollectedClientData"/> record with the specified client data parameters.
    /// </summary>
    /// <param name="type">The operation type (<c>webauthn.create</c> or <c>webauthn.get</c>).</param>
    /// <param name="challenge">The base64url-encoded challenge sent by the server.</param>
    /// <param name="origin">The fully-qualified origin of the caller.</param>
    /// <param name="rawClientDataJson">The raw UTF-8 bytes of the client data JSON.</param>
    /// <param name="crossOrigin">The optional value indicating whether the request was executed in a cross-origin iframe context.</param>
    /// <exception cref="ArgumentNullException"><paramref name="rawClientDataJson"/> is <see langword="null"/></exception>
    /// <exception cref="ArgumentException"><paramref name="type"/>, <paramref name="challenge"/>, or <paramref name="origin"/> is <see langword="null"/>, empty, or whitespace</exception>
    public CollectedClientData(string type, string challenge, string origin, byte[] rawClientDataJson, bool? crossOrigin = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(type);
        ArgumentException.ThrowIfNullOrWhiteSpace(challenge);
        ArgumentException.ThrowIfNullOrWhiteSpace(origin);
        ArgumentNullException.ThrowIfNull(rawClientDataJson);

        Type = type;
        Challenge = challenge;
        Origin = origin;
        RawClientDataJson = rawClientDataJson;
        CrossOrigin = crossOrigin;
    }
}
