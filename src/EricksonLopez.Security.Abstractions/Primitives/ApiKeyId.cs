// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Abstractions.Primitives;

using System;
using System.Diagnostics;

/// <summary>
/// Represents a strongly-typed immutable identifier for an issued API key.
/// </summary>
[DebuggerDisplay("{Value,nq}")]
public readonly record struct ApiKeyId : IEquatable<ApiKeyId>, IComparable<ApiKeyId>
{
    /// <summary>
    /// Gets the raw string identifier of the API key.
    /// </summary>
    public string Value { get; }

    /// <summary>
    /// Initializes a new instance of the <see cref="ApiKeyId"/> struct.
    /// </summary>
    /// <param name="value">The unique identifier value.</param>
    /// <exception cref="ArgumentException"><paramref name="value"/> is <see langword="null"/>, empty, or consists only of white-space characters</exception>
    public ApiKeyId(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new ArgumentException("API key ID cannot be null, empty, or whitespace.", nameof(value));
        }

        Value = value.Trim();
    }

    /// <summary>
    /// Generates a new random unique <see cref="ApiKeyId"/>.
    /// </summary>
    /// <returns>A new <see cref="ApiKeyId"/>.</returns>
    public static ApiKeyId New() => new(Guid.NewGuid().ToString("N"));

    /// <inheritdoc />
    public int CompareTo(ApiKeyId other) => string.Compare(Value, other.Value, StringComparison.OrdinalIgnoreCase);

    /// <inheritdoc />
    public override string ToString() => Value ?? string.Empty;

    /// <summary>
    /// Implicitly converts a string to an <see cref="ApiKeyId"/>.
    /// </summary>
    /// <param name="value">The string value to convert.</param>
    /// <returns>A new <see cref="ApiKeyId"/> wrapping <paramref name="value"/>.</returns>
    public static implicit operator ApiKeyId(string value) => new(value);

    /// <summary>
    /// Implicitly converts an <see cref="ApiKeyId"/> to a string.
    /// </summary>
    /// <param name="id">The <see cref="ApiKeyId"/> instance to convert.</param>
    /// <returns>The underlying string identifier.</returns>
    public static implicit operator string(ApiKeyId id) => id.Value;

    /// <summary>
    /// Determines whether one <see cref="ApiKeyId"/> is less than another.
    /// </summary>
    /// <param name="left">The first instance to compare.</param>
    /// <param name="right">The second instance to compare.</param>
    /// <returns><see langword="true"/> if the left operand is less than the right; otherwise, <see langword="false"/>.</returns>
    public static bool operator <(ApiKeyId left, ApiKeyId right) => left.CompareTo(right) < 0;

    /// <summary>
    /// Determines whether one <see cref="ApiKeyId"/> is less than or equal to another.
    /// </summary>
    /// <param name="left">The first instance to compare.</param>
    /// <param name="right">The second instance to compare.</param>
    /// <returns><see langword="true"/> if the left operand is less than or equal to the right; otherwise, <see langword="false"/>.</returns>
    public static bool operator <=(ApiKeyId left, ApiKeyId right) => left.CompareTo(right) <= 0;

    /// <summary>
    /// Determines whether one <see cref="ApiKeyId"/> is greater than another.
    /// </summary>
    /// <param name="left">The first instance to compare.</param>
    /// <param name="right">The second instance to compare.</param>
    /// <returns><see langword="true"/> if the left operand is greater than the right; otherwise, <see langword="false"/>.</returns>
    public static bool operator >(ApiKeyId left, ApiKeyId right) => left.CompareTo(right) > 0;

    /// <summary>
    /// Determines whether one <see cref="ApiKeyId"/> is greater than or equal to another.
    /// </summary>
    /// <param name="left">The first instance to compare.</param>
    /// <param name="right">The second instance to compare.</param>
    /// <returns><see langword="true"/> if the left operand is greater than or equal to the right; otherwise, <see langword="false"/>.</returns>
    public static bool operator >=(ApiKeyId left, ApiKeyId right) => left.CompareTo(right) >= 0;
}
