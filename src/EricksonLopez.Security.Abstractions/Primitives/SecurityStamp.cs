// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Abstractions.Primitives;

using System;
using System.Diagnostics;

/// <summary>
/// Represents a strongly-typed immutable security stamp that invalidates user sessions, refresh tokens,
/// and authorization caches when security-critical state changes.
/// </summary>
[DebuggerDisplay("{Value,nq}")]
public readonly record struct SecurityStamp : IEquatable<SecurityStamp>
{
    /// <summary>
    /// Gets the raw string representation of the security stamp.
    /// </summary>
    public string Value { get; }

    /// <summary>
    /// Initializes a new instance of the <see cref="SecurityStamp"/> struct with the specified value.
    /// </summary>
    /// <param name="value">The security stamp value.</param>
    /// <exception cref="ArgumentException"><paramref name="value"/> is <see langword="null"/>, empty, or consists only of white-space characters</exception>
    public SecurityStamp(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new ArgumentException("Security stamp cannot be null, empty, or whitespace.", nameof(value));
        }

        Value = value.Trim();
    }

    /// <summary>
    /// Generates a new random, unique security stamp.
    /// </summary>
    /// <returns>A new <see cref="SecurityStamp"/> backed by a random UUID-based value.</returns>
    public static SecurityStamp New() => new(Guid.NewGuid().ToString("N"));

    /// <summary>
    /// Attempts to parse a string into a <see cref="SecurityStamp"/>.
    /// </summary>
    /// <param name="value">The raw string.</param>
    /// <param name="stamp">When successful, the created <see cref="SecurityStamp"/>.</param>
    /// <returns><see langword="true"/> if valid; otherwise, <see langword="false"/>.</returns>
    public static bool TryCreate(string? value, out SecurityStamp stamp)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            stamp = default;
            return false;
        }

        stamp = new SecurityStamp(value);
        return true;
    }

    /// <inheritdoc />
    public override string ToString() => Value ?? string.Empty;

    /// <summary>
    /// Implicitly converts a string to a <see cref="SecurityStamp"/>.
    /// </summary>
    /// <param name="value">The string value to convert.</param>
    /// <returns>A new <see cref="SecurityStamp"/> wrapping <paramref name="value"/>.</returns>
    public static implicit operator SecurityStamp(string value) => new(value);

    /// <summary>
    /// Implicitly converts a <see cref="SecurityStamp"/> to a string.
    /// </summary>
    /// <param name="stamp">The <see cref="SecurityStamp"/> instance to convert.</param>
    /// <returns>The underlying security stamp string value.</returns>
    public static implicit operator string(SecurityStamp stamp) => stamp.Value;
}
