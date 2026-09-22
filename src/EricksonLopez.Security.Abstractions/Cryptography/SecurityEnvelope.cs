// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Abstractions.Cryptography;

using System;
using EricksonLopez.Security.Abstractions.Primitives;

/// <summary>
/// Represents a self-contained, versioned, authenticated cryptographic envelope.
/// Encapsulates format version, algorithm descriptor, key identifier, key version, nonce, auth tag,
/// optional associated data, and ciphertext.
/// </summary>
/// <param name="FormatVersion">The envelope binary format version (e.g., 1).</param>
/// <param name="Algorithm">The applied AEAD algorithm.</param>
/// <param name="KeyId">The identifier of the key that encrypted the payload.</param>
/// <param name="KeyVersion">The version of the key that encrypted the payload.</param>
/// <param name="Nonce">The cryptographic initialization nonce.</param>
/// <param name="Tag">The AEAD authentication tag.</param>
/// <param name="Ciphertext">The encrypted payload.</param>
/// <param name="AssociatedData">The optional authenticated associated data bound to the envelope.</param>
public sealed record SecurityEnvelope(
    byte FormatVersion,
    AeadAlgorithm Algorithm,
    KeyIdentifier KeyId,
    KeyVersion KeyVersion,
    ReadOnlyMemory<byte> Nonce,
    ReadOnlyMemory<byte> Tag,
    ReadOnlyMemory<byte> Ciphertext,
    ReadOnlyMemory<byte> AssociatedData = default)
{
    /// <summary>Gets the binary format version number used when serializing new envelopes.</summary>
    public const byte CurrentFormatVersion = 1;

    /// <summary>
    /// Gets the total payload length in bytes.
    /// </summary>
    public int CiphertextLength => Ciphertext.Length;

    /// <summary>
    /// Gets a value indicating whether associated data is present.
    /// </summary>
    public bool HasAssociatedData => !AssociatedData.IsEmpty;

    /// <inheritdoc/>
    public override string ToString() =>
        $"SecurityEnvelope {{ KeyId = {KeyId}, KeyVersion = {KeyVersion}, Algorithm = {Algorithm}, PayloadLength = {CiphertextLength} bytes, HasAad = {HasAssociatedData} }}";
}
