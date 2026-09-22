// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Abstractions.Primitives;

using System;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;

/// <summary>
/// Represents a strongly-typed immutable SHA-256 cryptographic fingerprint for tokens, certificates, and artifacts.
/// </summary>
[DebuggerDisplay("{HexValue,nq}")]
public readonly record struct Fingerprint : IEquatable<Fingerprint>, IComparable<Fingerprint>
{
    /// <summary>
    /// Gets the hex-encoded uppercase SHA-256 fingerprint string.
    /// </summary>
    public string HexValue { get; }

    /// <summary>
    /// Initializes a new instance of the <see cref="Fingerprint"/> struct from a hex string.
    /// </summary>
    /// <param name="hexValue">The hex-encoded fingerprint string.</param>
    /// <exception cref="ArgumentException"><paramref name="hexValue"/> is <see langword="null"/>, empty, or consists only of white-space characters</exception>
    public Fingerprint(string hexValue)
    {
        if (string.IsNullOrWhiteSpace(hexValue))
        {
            throw new ArgumentException("Fingerprint hex value cannot be null, empty, or whitespace.", nameof(hexValue));
        }

        HexValue = hexValue.Trim().ToUpperInvariant();
    }

    /// <summary>
    /// Computes a SHA-256 fingerprint from a UTF-8 string.
    /// </summary>
    /// <param name="input">The input string.</param>
    /// <returns>A new <see cref="Fingerprint"/>.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="input"/> is <see langword="null"/></exception>
    public static Fingerprint FromUtf8String(string input)
    {
        ArgumentNullException.ThrowIfNull(input);
        Span<byte> hash = stackalloc byte[32];
        SHA256.HashData(Encoding.UTF8.GetBytes(input), hash);
        return new(Convert.ToHexString(hash));
    }

    /// <summary>
    /// Computes a SHA-256 fingerprint from raw byte span.
    /// </summary>
    /// <param name="data">The byte span.</param>
    /// <returns>A new <see cref="Fingerprint"/>.</returns>
    public static Fingerprint FromBytes(ReadOnlySpan<byte> data)
    {
        Span<byte> hash = stackalloc byte[32];
        SHA256.HashData(data, hash);
        return new(Convert.ToHexString(hash));
    }

    /// <inheritdoc />
    public int CompareTo(Fingerprint other) => string.Compare(HexValue, other.HexValue, StringComparison.OrdinalIgnoreCase);

    /// <inheritdoc />
    public override string ToString() => HexValue ?? string.Empty;

    /// <summary>
    /// Determines whether one <see cref="Fingerprint"/> is less than another.
    /// </summary>
    /// <param name="left">The first instance to compare.</param>
    /// <param name="right">The second instance to compare.</param>
    /// <returns><see langword="true"/> if the left operand is less than the right; otherwise, <see langword="false"/>.</returns>
    public static bool operator <(Fingerprint left, Fingerprint right) => left.CompareTo(right) < 0;

    /// <summary>
    /// Determines whether one <see cref="Fingerprint"/> is less than or equal to another.
    /// </summary>
    /// <param name="left">The first instance to compare.</param>
    /// <param name="right">The second instance to compare.</param>
    /// <returns><see langword="true"/> if the left operand is less than or equal to the right; otherwise, <see langword="false"/>.</returns>
    public static bool operator <=(Fingerprint left, Fingerprint right) => left.CompareTo(right) <= 0;

    /// <summary>
    /// Determines whether one <see cref="Fingerprint"/> is greater than another.
    /// </summary>
    /// <param name="left">The first instance to compare.</param>
    /// <param name="right">The second instance to compare.</param>
    /// <returns><see langword="true"/> if the left operand is greater than the right; otherwise, <see langword="false"/>.</returns>
    public static bool operator >(Fingerprint left, Fingerprint right) => left.CompareTo(right) > 0;

    /// <summary>
    /// Determines whether one <see cref="Fingerprint"/> is greater than or equal to another.
    /// </summary>
    /// <param name="left">The first instance to compare.</param>
    /// <param name="right">The second instance to compare.</param>
    /// <returns><see langword="true"/> if the left operand is greater than or equal to the right; otherwise, <see langword="false"/>.</returns>
    public static bool operator >=(Fingerprint left, Fingerprint right) => left.CompareTo(right) >= 0;
}
