// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Abstractions.Primitives;

using System;

/// <summary>
/// Represents a strongly-typed immutable container for cryptographic salt bytes.
/// </summary>
public readonly struct Salt : IEquatable<Salt>
{
    private readonly byte[] _bytes;

    /// <summary>
    /// Standard password hashing recommended salt length (128 bits = 16 bytes).
    /// </summary>
    public const int DefaultLength = 16;

    /// <summary>
    /// Gets the length of the salt in bytes.
    /// </summary>
    public int Length => _bytes?.Length ?? 0;

    /// <summary>
    /// Gets a readonly span over the salt bytes.
    /// </summary>
    public ReadOnlySpan<byte> Span => _bytes;

    /// <summary>
    /// Gets a readonly memory over the salt bytes.
    /// </summary>
    public ReadOnlyMemory<byte> Memory => _bytes;

    /// <summary>
    /// Initializes a new instance of the <see cref="Salt"/> struct.
    /// </summary>
    /// <param name="bytes">The salt byte array.</param>
    /// <exception cref="ArgumentNullException"><paramref name="bytes"/> is <see langword="null"/></exception>
    /// <exception cref="ArgumentException"><paramref name="bytes"/> is empty</exception>
    public Salt(byte[] bytes)
    {
        ArgumentNullException.ThrowIfNull(bytes);
        if (bytes.Length == 0)
        {
            throw new ArgumentException("Salt bytes cannot be empty.", nameof(bytes));
        }

        _bytes = (byte[])bytes.Clone();
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="Salt"/> struct from a readonly span.
    /// </summary>
    /// <param name="span">The readonly byte span containing the salt bytes.</param>
    /// <exception cref="ArgumentException"><paramref name="span"/> is empty</exception>
    public Salt(ReadOnlySpan<byte> span)
    {
        if (span.IsEmpty)
        {
            throw new ArgumentException("Salt span cannot be empty.", nameof(span));
        }

        _bytes = span.ToArray();
    }

    /// <summary>
    /// Safely copies the salt bytes to the destination span.
    /// </summary>
    /// <param name="destination">The destination byte span where the salt bytes will be copied.</param>
    public void CopyTo(Span<byte> destination) => Span.CopyTo(destination);

    /// <inheritdoc />
    public bool Equals(Salt other) => Span.SequenceEqual(other.Span);

    /// <inheritdoc />
    public override bool Equals(object? obj) => obj is Salt other && Equals(other);

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
    public override string ToString() => $"Salt({Length} bytes)";

    /// <summary>
    /// Determines whether two <see cref="Salt"/> values are equal.
    /// </summary>
    /// <param name="left">The first instance to compare.</param>
    /// <param name="right">The second instance to compare.</param>
    /// <returns><see langword="true"/> if the operands are equal; otherwise, <see langword="false"/>.</returns>
    public static bool operator ==(Salt left, Salt right) => left.Equals(right);

    /// <summary>
    /// Determines whether two <see cref="Salt"/> values are not equal.
    /// </summary>
    /// <param name="left">The first instance to compare.</param>
    /// <param name="right">The second instance to compare.</param>
    /// <returns><see langword="true"/> if the operands are not equal; otherwise, <see langword="false"/>.</returns>
    public static bool operator !=(Salt left, Salt right) => !left.Equals(right);
}
