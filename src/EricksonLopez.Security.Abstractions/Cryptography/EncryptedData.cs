// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Abstractions.Cryptography;

using System;

/// <summary>
/// Encapsulates the output of an AEAD encryption operation: ciphertext, authentication tag, and initialization nonce.
/// </summary>
/// <param name="Ciphertext">The encrypted payload bytes.</param>
/// <param name="Tag">The 128-bit (16-byte) AEAD authentication tag.</param>
/// <param name="Nonce">The unique 96-bit (12-byte) initialization nonce.</param>
public readonly record struct EncryptedData(
    ReadOnlyMemory<byte> Ciphertext,
    ReadOnlyMemory<byte> Tag,
    ReadOnlyMemory<byte> Nonce)
{
    /// <summary>
    /// Gets the length of the ciphertext in bytes.
    /// </summary>
    public int CiphertextLength => Ciphertext.Length;

    /// <summary>
    /// Gets the length of the authentication tag in bytes.
    /// </summary>
    public int TagLength => Tag.Length;

    /// <summary>
    /// Gets the length of the nonce in bytes.
    /// </summary>
    public int NonceLength => Nonce.Length;
}
