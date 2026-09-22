// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Abstractions.Randomness;

using System;

/// <summary>
/// Defines contracts for cryptographically secure pseudo-random number generators (CSPRNG).
/// </summary>
public interface ICryptographicRandomNumberGenerator
{
    /// <summary>
    /// Fills the destination byte span with cryptographically strong random bytes.
    /// </summary>
    /// <param name="destination">The destination span.</param>
    void Fill(Span<byte> destination);

    /// <summary>
    /// Generates a cryptographically strong random integer within the specified range.
    /// </summary>
    /// <param name="fromInclusive">The inclusive lower bound.</param>
    /// <param name="toExclusive">The exclusive upper bound.</param>
    /// <returns>A cryptographically strong random integer within the specified range.</returns>
    int GetInt32(int fromInclusive, int toExclusive);

    /// <summary>
    /// Allocates and fills a byte array with cryptographically strong random bytes.
    /// </summary>
    /// <param name="count">The number of bytes to generate.</param>
    /// <returns>A byte array containing cryptographically strong random bytes.</returns>
    byte[] GetBytes(int count);
}
