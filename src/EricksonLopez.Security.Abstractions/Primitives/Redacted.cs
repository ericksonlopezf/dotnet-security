// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Abstractions.Primitives;

using System;
using System.Collections.Generic;
using System.Diagnostics;

/// <summary>
/// Represents a memory-safe, allocation-conscious wrapper for sensitive data that prevents accidental leakage
/// in logs, exception messages, telemetry traces, and debugger tooltips.
/// </summary>
/// <typeparam name="T">The type of the sensitive value.</typeparam>
[DebuggerDisplay("[REDACTED]")]
public readonly struct Redacted<T> : IEquatable<Redacted<T>>
{
    private const string s_defaultMask = "[REDACTED]";
    private readonly T? _value;
    private readonly bool _hasValue;

    /// <summary>
    /// Initializes a new instance of the <see cref="Redacted{T}"/> struct with the specified sensitive value.
    /// </summary>
    /// <param name="value">The sensitive value to protect.</param>
    public Redacted(T? value)
    {
        _value = value;
        _hasValue = value is not null;
    }

    /// <summary>
    /// Gets a value indicating whether this instance holds a non-<see langword="null"/> sensitive value.
    /// </summary>
    public bool HasValue => _hasValue;

    /// <summary>
    /// Gets the underlying sensitive value for explicitly authorized operations.
    /// </summary>
    /// <remarks>
    /// Restricts access strictly to cryptographic and validation boundaries.
    /// </remarks>
    public T? UnsafeValue => _value;

    /// <summary>
    /// Returns the constant redaction marker <c>[REDACTED]</c> to prevent accidental leakage when logged or printed.
    /// </summary>
    /// <returns>A redacted string constant.</returns>
    public override string ToString() => s_defaultMask;

    /// <inheritdoc />
    public bool Equals(Redacted<T> other)
    {
        if (!_hasValue && !other._hasValue)
        {
            return true;
        }

        if (_hasValue != other._hasValue)
        {
            return false;
        }

        if (_value is string strA && other._value is string strB)
        {
            if (strA.Length != strB.Length)
            {
                return false;
            }

            return System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(
                System.Runtime.InteropServices.MemoryMarshal.AsBytes(strA.AsSpan()),
                System.Runtime.InteropServices.MemoryMarshal.AsBytes(strB.AsSpan()));
        }

        if (_value is byte[] bytesA && other._value is byte[] bytesB)
        {
            return System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(bytesA, bytesB);
        }

        return EqualityComparer<T?>.Default.Equals(_value, other._value);
    }

    /// <inheritdoc />
    public override bool Equals(object? obj) => obj is Redacted<T> other && Equals(other);

    /// <inheritdoc />
    public override int GetHashCode() => _hasValue ? EqualityComparer<T?>.Default.GetHashCode(_value!) : 0;

    /// <summary>
    /// Implicitly wraps a sensitive value in a <see cref="Redacted{T}"/> container.
    /// </summary>
    /// <param name="value">The sensitive value.</param>
    /// <returns>A new <see cref="Redacted{T}"/> container wrapping <paramref name="value"/>.</returns>
    public static implicit operator Redacted<T>(T? value) => new(value);

    /// <summary>
    /// Determines whether two <see cref="Redacted{T}"/> instances are equal.
    /// </summary>
    /// <param name="left">The first instance to compare.</param>
    /// <param name="right">The second instance to compare.</param>
    /// <returns><see langword="true"/> if the operands are equal; otherwise, <see langword="false"/>.</returns>
    public static bool operator ==(Redacted<T> left, Redacted<T> right) => left.Equals(right);

    /// <summary>
    /// Determines whether two <see cref="Redacted{T}"/> instances are not equal.
    /// </summary>
    /// <param name="left">The first instance to compare.</param>
    /// <param name="right">The second instance to compare.</param>
    /// <returns><see langword="true"/> if the operands are not equal; otherwise, <see langword="false"/>.</returns>
    public static bool operator !=(Redacted<T> left, Redacted<T> right) => !left.Equals(right);
}
