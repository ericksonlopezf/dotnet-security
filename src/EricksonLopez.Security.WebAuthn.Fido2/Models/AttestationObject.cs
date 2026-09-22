// Copyright © Erickson Lopez. MIT License.

using System;

namespace EricksonLopez.Security.WebAuthn.Fido2.Models;

/// <summary>
/// Represents the parsed WebAuthn attestation object (CBOR map containing fmt, attStmt, and authData).
/// </summary>
public sealed record AttestationObject
{
    /// <summary>
    /// Gets the attestation format identifier.
    /// </summary>
    public string Format => Statement.Format;

    /// <summary>
    /// Gets the parsed authenticator data.
    /// </summary>
    public AuthenticatorData AuthenticatorData { get; init; }

    /// <summary>
    /// Gets the parsed attestation statement.
    /// </summary>
    public AttestationStatement Statement { get; init; }

    /// <summary>
    /// Gets the raw CBOR-encoded attestation object bytes.
    /// </summary>
    public byte[] RawBytes { get; init; }

    /// <summary>
    /// Initializes a new instance of the <see cref="AttestationObject"/> record with the specified authenticator data, statement, and raw bytes.
    /// </summary>
    /// <param name="authenticatorData">The parsed authenticator data.</param>
    /// <param name="statement">The parsed attestation statement.</param>
    /// <param name="rawBytes">The raw CBOR-encoded attestation object bytes.</param>
    /// <exception cref="ArgumentNullException"><paramref name="authenticatorData"/>, <paramref name="statement"/>, or <paramref name="rawBytes"/> is <see langword="null"/></exception>
    public AttestationObject(AuthenticatorData authenticatorData, AttestationStatement statement, byte[] rawBytes)
    {
        AuthenticatorData = authenticatorData ?? throw new ArgumentNullException(nameof(authenticatorData));
        Statement = statement ?? throw new ArgumentNullException(nameof(statement));
        RawBytes = rawBytes ?? throw new ArgumentNullException(nameof(rawBytes));
    }
}
