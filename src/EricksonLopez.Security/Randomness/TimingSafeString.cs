// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Randomness;

using System;
using System.Diagnostics;

/// <summary>
/// Represents a readonly wrapper for strings that uses constant-time comparison in <see cref="Equals(TimingSafeString)"/>
/// and <see cref="operator =="/> to prevent timing side-channel attacks on credentials, tokens, and HMACs.
/// </summary>
[DebuggerDisplay("[TIMING-SAFE STRING]")]
public readonly struct TimingSafeString : IEquatable<TimingSafeString>
{
    private readonly string? _value;

    /// <summary>
    /// Gets the length of the string in characters.
    /// </summary>
    public int Length => _value?.Length ?? 0;

    /// <summary>
    /// Gets a value indicating whether this instance holds an empty string.
    /// </summary>
    public bool IsEmpty => string.IsNullOrEmpty(_value);

    /// <summary>
    /// Initializes a new instance of the <see cref="TimingSafeString"/> struct.
    /// </summary>
    /// <param name="value">The string value.</param>
    public TimingSafeString(string? value)
    {
        _value = value;
    }

    /// <summary>
    /// Returns a read-only character span representing the underlying characters.
    /// </summary>
    /// <returns>A read-only span representing the underlying characters.</returns>
    /// <remarks>
    /// <strong>Lifetime Note (TSS-03):</strong> The returned <see cref="ReadOnlySpan{T}"/> is directly
    /// bound to the underlying <see langword="string"/> field of this <see cref="TimingSafeString"/> instance.
    /// The span must not be stored beyond the lifetime of this instance \u2014 it will become invalid if the
    /// instance is garbage collected. In practice, consume the span immediately within the same call scope
    /// and do not pass it to asynchronous continuations, background threads, or stored delegates.
    /// </remarks>
    public ReadOnlySpan<char> AsSpan() => _value.AsSpan();

    /// <inheritdoc />
    public bool Equals(TimingSafeString other) => ConstantTimeComparer.Equals(_value, other._value);

    /// <inheritdoc />
    public override bool Equals(object? obj) => obj is TimingSafeString other && Equals(other);

    /// <inheritdoc />
    /// <remarks>
    /// <strong>Security Warning (SC-002):</strong> This method returns a standard, non-constant-time hash code
    /// derived from the underlying string. Using <see cref="TimingSafeString"/> as a key in a
    /// <see cref="System.Collections.Generic.Dictionary{TKey,TValue}"/> or
    /// <see cref="System.Collections.Generic.HashSet{T}"/> will NOT preserve constant-time properties
    /// because dictionary bucket lookups use this hash code with ordinary timing. Use
    /// <see cref="Equals(TimingSafeString)"/> or <see cref="operator ==(TimingSafeString, TimingSafeString)"/>
    /// for constant-time comparisons. This method is hidden in IDE auto-complete to discourage misuse.
    /// </remarks>
    [System.ComponentModel.EditorBrowsable(System.ComponentModel.EditorBrowsableState.Never)]
    public override int GetHashCode() => _value is not null ? string.GetHashCode(_value, StringComparison.Ordinal) : 0;


    /// <inheritdoc />
    public override string ToString() => "[REDACTED TIMING-SAFE STRING]";

    /// <summary>
    /// Converts a string to a <see cref="TimingSafeString"/> instance.
    /// </summary>
    /// <param name="value">The string value to wrap.</param>
    /// <returns>A new <see cref="TimingSafeString"/> wrapping <paramref name="value"/>.</returns>
    public static implicit operator TimingSafeString(string? value) => new(value);

    /// <summary>
    /// Determines whether two <see cref="TimingSafeString"/> instances represent the same value using constant-time comparison.
    /// </summary>
    /// <param name="left">The first instance to compare.</param>
    /// <param name="right">The second instance to compare.</param>
    /// <returns><see langword="true"/> if both instances represent the same value; otherwise, <see langword="false"/>.</returns>
    public static bool operator ==(TimingSafeString left, TimingSafeString right) => left.Equals(right);

    /// <summary>
    /// Determines whether two <see cref="TimingSafeString"/> instances represent different values using constant-time comparison.
    /// </summary>
    /// <param name="left">The first instance to compare.</param>
    /// <param name="right">The second instance to compare.</param>
    /// <returns><see langword="true"/> if instances represent different values; otherwise, <see langword="false"/>.</returns>
    public static bool operator !=(TimingSafeString left, TimingSafeString right) => !left.Equals(right);
}
