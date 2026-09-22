// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Cryptography.Randomness;

using System;
using System.Security.Cryptography;
using EricksonLopez.Security.Abstractions.Randomness;

/// <summary>
/// Provides a cryptographically secure pseudo-random number generator (CSPRNG) implementation.
/// </summary>
public sealed class CryptographicRandomNumberGenerator : ICryptographicRandomNumberGenerator
{
    /// <inheritdoc/>
    public void Fill(Span<byte> destination)
    {
        RandomNumberGenerator.Fill(destination);
    }

    /// <inheritdoc/>
    public int GetInt32(int fromInclusive, int toExclusive)
    {
        return RandomNumberGenerator.GetInt32(fromInclusive, toExclusive);
    }

    /// <inheritdoc/>
    public byte[] GetBytes(int count)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(count);
        return RandomNumberGenerator.GetBytes(count);
    }
}
