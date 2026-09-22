// Copyright © Erickson Lopez. MIT License.

using System;
using System.Collections.Generic;

namespace EricksonLopez.Security.WebAuthn.Fido2.Models;

/// <summary>
/// Represents the parsed attestation statement from an attestation object.
/// </summary>
public sealed record AttestationStatement
{
    /// <summary>
    /// Gets the attestation format identifier (e.g. "none", "packed", "fido-u2f", "android-key", "tpm", "apple").
    /// </summary>
    public string Format { get; init; }

    /// <summary>
    /// Gets the signature bytes if present in the attestation statement.
    /// </summary>
    public byte[]? Signature { get; init; }

    /// <summary>
    /// Gets the algorithm identifier if present in the attestation statement.
    /// </summary>
    public long? Algorithm { get; init; }

    /// <summary>
    /// Gets the X.509 certificate chain (x5c) encoded as raw DER bytes if present.
    /// </summary>
    public IReadOnlyList<byte[]>? X5c { get; init; }

    /// <summary>
    /// Gets the raw CBOR map representing the attestation statement.
    /// </summary>
    public byte[] RawBytes { get; init; }

    /// <summary>
    /// Initializes a new instance of the <see cref="AttestationStatement"/> record with the specified format and statement data.
    /// </summary>
    /// <param name="format">The attestation format identifier (e.g., "none", "packed", "tpm").</param>
    /// <param name="rawBytes">The raw CBOR bytes of the attestation statement.</param>
    /// <param name="signature">The optional signature bytes if present in the statement.</param>
    /// <param name="algorithm">The optional COSE algorithm identifier.</param>
    /// <param name="x5c">The optional X.509 certificate chain encoded as raw DER bytes.</param>
    /// <exception cref="ArgumentNullException"><paramref name="rawBytes"/> is <see langword="null"/></exception>
    /// <exception cref="ArgumentException"><paramref name="format"/> is <see langword="null"/>, empty, or whitespace</exception>
    public AttestationStatement(
        string format,
        byte[] rawBytes,
        byte[]? signature = null,
        long? algorithm = null,
        IReadOnlyList<byte[]>? x5c = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(format);
        Format = format;
        RawBytes = rawBytes ?? throw new ArgumentNullException(nameof(rawBytes));
        Signature = signature;
        Algorithm = algorithm;
        X5c = x5c;
    }
}
