// Copyright © Erickson Lopez. MIT License.

using System;
using EricksonLopez.Security.WebAuthn.Fido2.Enums;

namespace EricksonLopez.Security.WebAuthn.Fido2.Models;

/// <summary>
/// Represents a parsed COSE public key extracted from an authenticator's attested credential data.
/// </summary>
public sealed record CosePublicKey
{
    /// <summary>
    /// Gets the COSE Key Type (e.g. EC2 = 2, RSA = 3, OKP = 1).
    /// </summary>
    public CoseKeyType KeyType { get; init; }

    /// <summary>
    /// Gets the cryptographic algorithm identifier (e.g. ES256 = -7, RS256 = -257, EdDSA = -8).
    /// </summary>
    public CoseAlgorithmIdentifier Algorithm { get; init; }

    /// <summary>
    /// Gets the curve identifier for EC2 or OKP keys (e.g. P-256 = 1, Ed25519 = 6).
    /// </summary>
    public CoseEllipticCurve? Curve { get; init; }

    /// <summary>
    /// Gets the X coordinate bytes for EC2 keys, or public key bytes for OKP (Ed25519) keys.
    /// </summary>
    public byte[]? X { get; init; }

    /// <summary>
    /// Gets the Y coordinate bytes for EC2 keys.
    /// </summary>
    public byte[]? Y { get; init; }

    /// <summary>
    /// Gets the RSA Modulus (N) bytes for RSA keys.
    /// </summary>
    public byte[]? Modulus { get; init; }

    /// <summary>
    /// Gets the RSA Public Exponent (E) bytes for RSA keys.
    /// </summary>
    public byte[]? Exponent { get; init; }

    /// <summary>
    /// Gets the raw CBOR-encoded bytes of the COSE Key.
    /// </summary>
    public byte[] RawBytes { get; init; }

    /// <summary>
    /// Initializes a new instance of the <see cref="CosePublicKey"/> record with the specified key parameters.
    /// </summary>
    /// <param name="keyType">The COSE Key Type (e.g., EC2, RSA, OKP).</param>
    /// <param name="algorithm">The cryptographic algorithm identifier.</param>
    /// <param name="rawBytes">The raw CBOR-encoded bytes of the COSE Key.</param>
    /// <param name="curve">The optional curve identifier for EC2 or OKP keys.</param>
    /// <param name="x">The optional X coordinate or public key bytes.</param>
    /// <param name="y">The optional Y coordinate bytes for EC2 keys.</param>
    /// <param name="modulus">The optional RSA modulus (N) bytes.</param>
    /// <param name="exponent">The optional RSA public exponent (E) bytes.</param>
    /// <exception cref="ArgumentNullException"><paramref name="rawBytes"/> is <see langword="null"/></exception>
    public CosePublicKey(
        CoseKeyType keyType,
        CoseAlgorithmIdentifier algorithm,
        byte[] rawBytes,
        CoseEllipticCurve? curve = null,
        byte[]? x = null,
        byte[]? y = null,
        byte[]? modulus = null,
        byte[]? exponent = null)
    {
        KeyType = keyType;
        Algorithm = algorithm;
        RawBytes = rawBytes ?? throw new ArgumentNullException(nameof(rawBytes));
        Curve = curve;
        X = x;
        Y = y;
        Modulus = modulus;
        Exponent = exponent;
    }
}
