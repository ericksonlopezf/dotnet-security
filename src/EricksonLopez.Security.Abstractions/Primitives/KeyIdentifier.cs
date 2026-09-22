// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Abstractions.Primitives;

using System;
using System.Diagnostics;

/// <summary>
/// Represents a strongly-typed immutable identifier for cryptographic keys, key rings, and secrets.
/// Enforces non-empty invariants and provides URL-safe string representations.
/// </summary>
[DebuggerDisplay("{Value,nq}")]
public readonly record struct KeyIdentifier : IEquatable<KeyIdentifier>, IComparable<KeyIdentifier>
{
    /// <summary>
    /// Gets the underlying string value of the key identifier.
    /// </summary>
    public string Value { get; }

    /// <summary>
    /// Initializes a new instance of the <see cref="KeyIdentifier"/> struct with the specified value.
    /// </summary>
    /// <param name="value">The key identifier string (cannot be null, empty, or whitespace).</param>
    /// <exception cref="ArgumentException"><paramref name="value"/> is <see langword="null"/>, empty, or consists only of white-space characters</exception>
    public KeyIdentifier(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new ArgumentException("Key identifier cannot be null, empty, or whitespace.", nameof(value));
        }

        Value = value.Trim();
    }

    /// <summary>
    /// Generates a new random, unique <see cref="KeyIdentifier"/> based on a 32-character hexadecimal UUIDv4 representation (Guid "N" format without hyphens).
    /// </summary>
    /// <returns>A new unique <see cref="KeyIdentifier"/>.</returns>
    public static KeyIdentifier New() => new(Guid.NewGuid().ToString("N"));

    /// <summary>
    /// Generates a new <see cref="KeyIdentifier"/> with a given semantic prefix (e.g., "key_sec" producing "key_sec-4fecdac2ba87e980abc123456789abcd").
    /// </summary>
    /// <param name="prefix">The semantic prefix (cannot be null, empty, or whitespace).</param>
    /// <returns>A new unique prefixed <see cref="KeyIdentifier"/>.</returns>
    /// <exception cref="ArgumentException"><paramref name="prefix"/> is <see langword="null"/>, empty, or consists only of white-space characters</exception>
    public static KeyIdentifier Prefixed(string prefix)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(prefix);
        return new($"{prefix.Trim().TrimEnd('-')}-{Guid.NewGuid():N}");
    }

    /// <summary>
    /// Attempts to create a <see cref="KeyIdentifier"/> from a raw string.
    /// </summary>
    /// <param name="value">The raw string.</param>
    /// <param name="identifier">When successful, the created <see cref="KeyIdentifier"/>.</param>
    /// <returns><see langword="true"/> if valid; otherwise, <see langword="false"/>.</returns>
    public static bool TryCreate(string? value, out KeyIdentifier identifier)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            identifier = default;
            return false;
        }

        identifier = new KeyIdentifier(value);
        return true;
    }

    /// <inheritdoc />
    public int CompareTo(KeyIdentifier other) => string.Compare(Value, other.Value, StringComparison.OrdinalIgnoreCase);

    /// <inheritdoc />
    public override string ToString() => Value ?? string.Empty;

    /// <summary>
    /// Implicitly converts a string to a <see cref="KeyIdentifier"/>.
    /// </summary>
    /// <param name="value">The string value to convert.</param>
    /// <returns>A new <see cref="KeyIdentifier"/> wrapping <paramref name="value"/>.</returns>
    public static implicit operator KeyIdentifier(string value) => new(value);

    /// <summary>
    /// Implicitly converts a <see cref="KeyIdentifier"/> to a string.
    /// </summary>
    /// <param name="identifier">The <see cref="KeyIdentifier"/> instance to convert.</param>
    /// <returns>The underlying string identifier.</returns>
    public static implicit operator string(KeyIdentifier identifier) => identifier.Value;

    /// <summary>
    /// Determines whether one <see cref="KeyIdentifier"/> is less than another.
    /// </summary>
    /// <param name="left">The first instance to compare.</param>
    /// <param name="right">The second instance to compare.</param>
    /// <returns><see langword="true"/> if the left operand is less than the right; otherwise, <see langword="false"/>.</returns>
    public static bool operator <(KeyIdentifier left, KeyIdentifier right) => left.CompareTo(right) < 0;

    /// <summary>
    /// Determines whether one <see cref="KeyIdentifier"/> is less than or equal to another.
    /// </summary>
    /// <param name="left">The first instance to compare.</param>
    /// <param name="right">The second instance to compare.</param>
    /// <returns><see langword="true"/> if the left operand is less than or equal to the right; otherwise, <see langword="false"/>.</returns>
    public static bool operator <=(KeyIdentifier left, KeyIdentifier right) => left.CompareTo(right) <= 0;

    /// <summary>
    /// Determines whether one <see cref="KeyIdentifier"/> is greater than another.
    /// </summary>
    /// <param name="left">The first instance to compare.</param>
    /// <param name="right">The second instance to compare.</param>
    /// <returns><see langword="true"/> if the left operand is greater than the right; otherwise, <see langword="false"/>.</returns>
    public static bool operator >(KeyIdentifier left, KeyIdentifier right) => left.CompareTo(right) > 0;

    /// <summary>
    /// Determines whether one <see cref="KeyIdentifier"/> is greater than or equal to another.
    /// </summary>
    /// <param name="left">The first instance to compare.</param>
    /// <param name="right">The second instance to compare.</param>
    /// <returns><see langword="true"/> if the left operand is greater than or equal to the right; otherwise, <see langword="false"/>.</returns>
    public static bool operator >=(KeyIdentifier left, KeyIdentifier right) => left.CompareTo(right) >= 0;
}
