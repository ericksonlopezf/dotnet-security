// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Randomness;

using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using EricksonLopez.Security.Abstractions.Randomness;

/// <summary>
/// Provides side-channel resistant constant-time comparison primitives wrapping <see cref="CryptographicOperations.FixedTimeEquals"/>.
/// </summary>
public sealed class ConstantTimeComparer : IConstantTimeComparer
{
    /// <summary>
    /// Initializes a new instance of the <see cref="ConstantTimeComparer"/> class.
    /// </summary>
    public ConstantTimeComparer()
    {
    }

    /// <summary>
    /// Gets the shared singleton instance of <see cref="ConstantTimeComparer"/>.
    /// </summary>
    public static readonly ConstantTimeComparer Shared = new();

    /// <inheritdoc />
    [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
    public bool FixedTimeEquals(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right)
    {
        if (left.Length != right.Length)
        {
            return false;
        }

        return CryptographicOperations.FixedTimeEquals(left, right);
    }

    /// <inheritdoc />
    /// <remarks>
    /// <strong>Encoding Note (CTC-04):</strong> This overload compares the UTF-16 LE byte representation
    /// of the two character spans, as stored in memory by the .NET runtime. This is correct and safe for
    /// all comparisons of <see langword="string"/>-derived spans (e.g., <c>token.AsSpan()</c>, <c>header.AsSpan()</c>).
    /// <para>
    /// Do <em>not</em> use this overload to compare characters reconstructed from different source encodings
    /// (e.g., a <c>char[]</c> decoded from UTF-8 bytes vs a native .NET string). The UTF-16 LE byte layout
    /// must be identical for both operands, which is guaranteed when both originate from .NET <see langword="string"/> objects.
    /// </para>
    /// </remarks>
    [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
    public bool FixedTimeEquals(ReadOnlySpan<char> left, ReadOnlySpan<char> right)
    {
        if (left.Length != right.Length)
        {
            return false;
        }

        return CryptographicOperations.FixedTimeEquals(MemoryMarshal.AsBytes(left), MemoryMarshal.AsBytes(right));
    }

    /// <inheritdoc />
    [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
    public bool FixedTimeEqualsSecure(ReadOnlySpan<char> left, ReadOnlySpan<char> right)
    {
        if (left.Length != right.Length)
        {
            Span<byte> dummy = stackalloc byte[1];
            CryptographicOperations.FixedTimeEquals(dummy, dummy);
            return false;
        }

        return CryptographicOperations.FixedTimeEquals(MemoryMarshal.AsBytes(left), MemoryMarshal.AsBytes(right));
    }

    /// <inheritdoc />
    [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
    public bool FixedTimeEqualsSecure(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right)
    {
        if (left.Length != right.Length)
        {
            Span<byte> dummy = stackalloc byte[1];
            CryptographicOperations.FixedTimeEquals(dummy, dummy);
            return false;
        }

        return CryptographicOperations.FixedTimeEquals(left, right);
    }


    /// <summary>
    /// Compares two strings in constant time, resistant to value-based timing side channels.
    /// </summary>
    /// <param name="left">The left string.</param>
    /// <param name="right">The right string.</param>
    /// <returns><see langword="true"/> if strings are identical in constant time; otherwise, <see langword="false"/>.</returns>
    /// <remarks>
    /// <para>
    /// <strong>Note (SC-NULL-001):</strong> When exactly one argument is <see langword="null"/>,
    /// this method executes a dummy constant-time comparison before returning <see langword="false"/>
    /// to prevent a timing side-channel that would otherwise reveal whether either string is <see langword="null"/>
    /// ahead of the constant-time comparison. This protects callers that pass hashes or tokens
    /// where a missing/null value could have a distinct timing signature.
    /// </para>
    /// </remarks>
    [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
    public static bool Equals(string? left, string? right)
    {
        if (left is null && right is null)
        {
            return true;
        }

        if (left is null || right is null)
        {
            // AUDIT-FIX-05 (SC-NULL-001): execute a dummy constant-time comparison before
            // returning false to prevent a timing oracle on null vs. non-null strings.
            // Without this, an attacker could distinguish "left is null" from "left is non-null"
            // by measuring whether the FixedTimeEquals call was executed.
            Span<byte> dummy = stackalloc byte[1];
            CryptographicOperations.FixedTimeEquals(dummy, dummy);
            return false;
        }

        return Shared.FixedTimeEqualsSecure(left.AsSpan(), right.AsSpan());
    }
}

