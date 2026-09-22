// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Abstractions.Primitives;

using System;

/// <summary>
/// Represents a strongly-typed immutable container for a cryptographic Initialization Vector (IV) or nonce (number used once).
/// Enforces positive byte length (variable non-empty length supported; standard AES-GCM length is 12 bytes / 96 bits as defined by <see cref="AesGcmStandardLength"/>) and safe copying.
/// </summary>
public readonly struct Nonce : IEquatable<Nonce>
{
    private readonly byte[] _bytes;

    /// <summary>
    /// Standard AES-GCM recommended nonce length (96 bits = 12 bytes).
    /// </summary>
    public const int AesGcmStandardLength = 12;

    /// <summary>
    /// Gets the length of the nonce in bytes.
    /// </summary>
    public int Length => _bytes?.Length ?? 0;

    /// <summary>
    /// Gets a readonly span over the nonce bytes.
    /// </summary>
    public ReadOnlySpan<byte> Span => _bytes;

    /// <summary>
    /// Gets a readonly memory over the nonce bytes.
    /// </summary>
    public ReadOnlyMemory<byte> Memory => _bytes;

    /// <summary>
    /// Initializes a new instance of the <see cref="Nonce"/> struct with the specified byte array.
    /// </summary>
    /// <param name="bytes">The nonce byte array (cannot be empty).</param>
    /// <exception cref="ArgumentNullException"><paramref name="bytes"/> is <see langword="null"/></exception>
    /// <exception cref="ArgumentException"><paramref name="bytes"/> is empty</exception>
    public Nonce(byte[] bytes)
    {
        ArgumentNullException.ThrowIfNull(bytes);
        if (bytes.Length == 0)
        {
            throw new ArgumentException("Nonce bytes cannot be empty.", nameof(bytes));
        }

        _bytes = (byte[])bytes.Clone();
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="Nonce"/> struct by copying from a readonly span.
    /// </summary>
    /// <param name="span">The nonce byte span.</param>
    /// <exception cref="ArgumentException"><paramref name="span"/> is empty</exception>
    public Nonce(ReadOnlySpan<byte> span)
    {
        if (span.IsEmpty)
        {
            throw new ArgumentException("Nonce span cannot be empty.", nameof(span));
        }

        _bytes = span.ToArray();
    }

    /// <summary>
    /// Safely copies the nonce bytes to a destination span.
    /// </summary>
    /// <param name="destination">The destination byte span where the nonce bytes will be copied.</param>
    public void CopyTo(Span<byte> destination) => Span.CopyTo(destination);

    /// <inheritdoc />
    public bool Equals(Nonce other) => Span.SequenceEqual(other.Span);

    /// <inheritdoc />
    public override bool Equals(object? obj) => obj is Nonce other && Equals(other);

    /// <inheritdoc />
    public override int GetHashCode()
    {
        if (_bytes is null || _bytes.Length == 0)
        {
            return 0;
        }

        HashCode hash = default;
        hash.AddBytes(_bytes);
        return hash.ToHashCode();
    }

    /// <inheritdoc />
    public override string ToString() => $"Nonce({Length} bytes: {Convert.ToHexString(Span)})";

    /// <summary>
    /// Determines whether two <see cref="Nonce"/> values are equal.
    /// </summary>
    /// <param name="left">The first instance to compare.</param>
    /// <param name="right">The second instance to compare.</param>
    /// <returns><see langword="true"/> if the operands are equal; otherwise, <see langword="false"/>.</returns>
    public static bool operator ==(Nonce left, Nonce right) => left.Equals(right);

    /// <summary>
    /// Determines whether two <see cref="Nonce"/> values are not equal.
    /// </summary>
    /// <param name="left">The first instance to compare.</param>
    /// <param name="right">The second instance to compare.</param>
    /// <returns><see langword="true"/> if the operands are not equal; otherwise, <see langword="false"/>.</returns>
    public static bool operator !=(Nonce left, Nonce right) => !left.Equals(right);
}
