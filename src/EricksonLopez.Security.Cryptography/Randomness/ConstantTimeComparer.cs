// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Cryptography.Randomness;

using System;
using System.Security.Cryptography;
using EricksonLopez.Security.Abstractions.Randomness;

/// <summary>
/// Provides side-channel resistant constant-time comparisons over sensitive buffers.
/// </summary>
public sealed class ConstantTimeComparer : IConstantTimeComparer
{
    /// <inheritdoc/>
    public bool FixedTimeEquals(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        FixedTimeEqualsSecure(left, right);

    /// <inheritdoc/>
    public bool FixedTimeEquals(ReadOnlySpan<char> left, ReadOnlySpan<char> right) =>
        FixedTimeEqualsSecure(left, right);

    /// <inheritdoc/>
    public bool FixedTimeEqualsSecure(ReadOnlySpan<char> left, ReadOnlySpan<char> right)
    {
        Span<byte> leftHash = stackalloc byte[32];
        Span<byte> rightHash = stackalloc byte[32];

        SHA256.HashData(System.Runtime.InteropServices.MemoryMarshal.AsBytes(left), leftHash);
        SHA256.HashData(System.Runtime.InteropServices.MemoryMarshal.AsBytes(right), rightHash);

        bool matches = CryptographicOperations.FixedTimeEquals(leftHash, rightHash);

        CryptographicOperations.ZeroMemory(leftHash);
        CryptographicOperations.ZeroMemory(rightHash);

        return matches;
    }

    /// <inheritdoc/>
    public bool FixedTimeEqualsSecure(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right)
    {
        Span<byte> leftHash = stackalloc byte[32];
        Span<byte> rightHash = stackalloc byte[32];

        SHA256.HashData(left, leftHash);
        SHA256.HashData(right, rightHash);

        bool matches = CryptographicOperations.FixedTimeEquals(leftHash, rightHash);

        CryptographicOperations.ZeroMemory(leftHash);
        CryptographicOperations.ZeroMemory(rightHash);

        return matches;
    }
}
