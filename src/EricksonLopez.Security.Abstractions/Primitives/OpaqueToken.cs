// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Abstractions.Primitives;

using System;
using System.Diagnostics;

/// <summary>
/// Represents a strongly-typed immutable container for cryptographically random opaque tokens.
/// Redacts the underlying token in <see cref="ToString"/> to prevent log leakage.
/// </summary>
[DebuggerDisplay("[REDACTED OPAQUE TOKEN]")]
public readonly record struct OpaqueToken : IEquatable<OpaqueToken>
{
    private readonly string? _value;

    /// <summary>
    /// Gets the raw plaintext token string. Access must be restricted to verification boundaries.
    /// </summary>
    public string Value => _value ?? string.Empty;

    /// <summary>
    /// Gets the length of the token string.
    /// </summary>
    public int Length => _value?.Length ?? 0;

    /// <summary>
    /// Gets a value indicating whether this token is empty.
    /// </summary>
    public bool IsEmpty => string.IsNullOrEmpty(_value);

    /// <summary>
    /// Initializes a new instance of the <see cref="OpaqueToken"/> struct.
    /// </summary>
    /// <param name="value">The plaintext token string.</param>
    /// <exception cref="ArgumentException"><paramref name="value"/> is <see langword="null"/>, empty, or consists only of white-space characters</exception>
    public OpaqueToken(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new ArgumentException("Token value cannot be null, empty, or whitespace.", nameof(value));
        }

        _value = value;
    }

    /// <summary>
    /// Returns a redacted placeholder to prevent leaking the token in logs and traces.
    /// </summary>
    /// <returns>A constant redacted string.</returns>
    public override string ToString() => "[REDACTED TOKEN]";

    /// <summary>
    /// Compares two <see cref="OpaqueToken"/> instances for equality.
    /// </summary>
    /// <param name="other">The other <see cref="OpaqueToken"/> instance to compare with.</param>
    /// <returns><see langword="true"/> if the tokens are equal; otherwise, <see langword="false"/>.</returns>
    public bool Equals(OpaqueToken other) => string.Equals(_value, other._value, StringComparison.Ordinal);

    /// <inheritdoc />
    public override int GetHashCode() => _value is not null ? string.GetHashCode(_value, StringComparison.Ordinal) : 0;
}
