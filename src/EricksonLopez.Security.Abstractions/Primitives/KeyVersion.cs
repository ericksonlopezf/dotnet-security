// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Abstractions.Primitives;

using System;
using System.Diagnostics;

/// <summary>
/// Represents a strongly-typed immutable integer version for cryptographic keys.
/// Enforces positive integer version invariants (>= 1).
/// </summary>
[DebuggerDisplay("v{Value}")]
public readonly record struct KeyVersion : IEquatable<KeyVersion>, IComparable<KeyVersion>
{
    /// <summary>
    /// Gets the initial key version (v1).
    /// </summary>
    public static readonly KeyVersion Initial = new(1);

    /// <summary>
    /// Gets the underlying integer version number.
    /// </summary>
    public int Value { get; }

    /// <summary>
    /// Initializes a new instance of the <see cref="KeyVersion"/> struct with the specified integer version.
    /// </summary>
    /// <param name="value">The version number (must be >= 1).</param>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="value"/> is less than 1</exception>
    public KeyVersion(int value)
    {
        if (value < 1)
        {
            throw new ArgumentOutOfRangeException(nameof(value), value, "Key version must be a positive integer greater than or equal to 1.");
        }

        Value = value;
    }

    /// <summary>
    /// Produces the next incremental key version.
    /// </summary>
    /// <returns>A new <see cref="KeyVersion"/> with <see cref="Value"/> incremented by 1.</returns>
    public KeyVersion Next() => new(Value + 1);

    /// <inheritdoc />
    public int CompareTo(KeyVersion other) => Value.CompareTo(other.Value);

    /// <inheritdoc />
    public override string ToString() => $"v{Value}";

    /// <summary>
    /// Implicitly converts an integer to a <see cref="KeyVersion"/>.
    /// </summary>
    /// <param name="value">The version number to convert.</param>
    /// <returns>A new <see cref="KeyVersion"/> wrapping <paramref name="value"/>.</returns>
    public static implicit operator KeyVersion(int value) => new(value);

    /// <summary>
    /// Implicitly converts a <see cref="KeyVersion"/> to an integer.
    /// </summary>
    /// <param name="version">The <see cref="KeyVersion"/> instance to convert.</param>
    /// <returns>The underlying integer version value.</returns>
    public static implicit operator int(KeyVersion version) => version.Value;

    /// <summary>
    /// Determines whether one <see cref="KeyVersion"/> is greater than another.
    /// </summary>
    /// <param name="left">The first instance to compare.</param>
    /// <param name="right">The second instance to compare.</param>
    /// <returns><see langword="true"/> if the left operand is greater than the right; otherwise, <see langword="false"/>.</returns>
    public static bool operator >(KeyVersion left, KeyVersion right) => left.Value > right.Value;

    /// <summary>
    /// Determines whether one <see cref="KeyVersion"/> is less than another.
    /// </summary>
    /// <param name="left">The first instance to compare.</param>
    /// <param name="right">The second instance to compare.</param>
    /// <returns><see langword="true"/> if the left operand is less than the right; otherwise, <see langword="false"/>.</returns>
    public static bool operator <(KeyVersion left, KeyVersion right) => left.Value < right.Value;

    /// <summary>
    /// Determines whether one <see cref="KeyVersion"/> is greater than or equal to another.
    /// </summary>
    /// <param name="left">The first instance to compare.</param>
    /// <param name="right">The second instance to compare.</param>
    /// <returns><see langword="true"/> if the left operand is greater than or equal to the right; otherwise, <see langword="false"/>.</returns>
    public static bool operator >=(KeyVersion left, KeyVersion right) => left.Value >= right.Value;

    /// <summary>
    /// Determines whether one <see cref="KeyVersion"/> is less than or equal to another.
    /// </summary>
    /// <param name="left">The first instance to compare.</param>
    /// <param name="right">The second instance to compare.</param>
    /// <returns><see langword="true"/> if the left operand is less than or equal to the right; otherwise, <see langword="false"/>.</returns>
    public static bool operator <=(KeyVersion left, KeyVersion right) => left.Value <= right.Value;
}
