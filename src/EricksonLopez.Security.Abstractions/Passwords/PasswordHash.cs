// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Abstractions.Passwords;

using System;
using System.Diagnostics;

/// <summary>
/// Represents a strongly-typed immutable container for a stored, self-describing password hash string.
/// </summary>
[DebuggerDisplay("[REDACTED PASSWORD HASH]")]
public readonly record struct PasswordHash : IEquatable<PasswordHash>
{
    private readonly string? _value;

    /// <summary>
    /// Gets the raw formatted hash string (e.g. "$pbkdf2-sha512$i=210000$...").
    /// </summary>
    public string Value => _value ?? string.Empty;

    /// <summary>
    /// Initializes a new instance of the <see cref="PasswordHash"/> struct.
    /// </summary>
    /// <param name="value">The hash string.</param>
    /// <exception cref="ArgumentException"><paramref name="value"/> is <see langword="null"/>, empty, or consists only of white-space characters</exception>
    public PasswordHash(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new ArgumentException("Password hash string cannot be null, empty, or whitespace.", nameof(value));
        }

        _value = value.Trim();
    }

    /// <summary>
    /// Returns a redacted marker to prevent hash leakage in logs.
    /// </summary>
    /// <returns>A redacted string marker.</returns>
    public override string ToString() => "[REDACTED PASSWORD HASH]";

    /// <summary>
    /// Implicitly converts a string to a <see cref="PasswordHash"/>.
    /// </summary>
    /// <param name="value">The hash string to convert.</param>
    /// <returns>A new <see cref="PasswordHash"/> wrapping <paramref name="value"/>.</returns>
    public static implicit operator PasswordHash(string value) => new(value);

    /// <summary>
    /// Implicitly converts a <see cref="PasswordHash"/> to a string.
    /// </summary>
    /// <param name="hash">The <see cref="PasswordHash"/> instance to convert.</param>
    /// <returns>The underlying password hash string.</returns>
    public static implicit operator string(PasswordHash hash) => hash.Value;
}
