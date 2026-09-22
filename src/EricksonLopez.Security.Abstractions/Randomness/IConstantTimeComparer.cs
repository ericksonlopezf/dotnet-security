// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Abstractions.Randomness;

using System;

/// <summary>
/// Defines contracts for side-channel resistant constant-time comparisons over sensitive buffers.
/// </summary>
public interface IConstantTimeComparer
{
    /// <summary>
    /// Compares two byte spans for equality in execution time independent of data values,
    /// preventing side-channel timing attacks.
    /// </summary>
    /// <param name="left">The left byte span.</param>
    /// <param name="right">The right byte span.</param>
    /// <returns><see langword="true"/> if byte contents are identical and equal length; otherwise, <see langword="false"/>.</returns>
    bool FixedTimeEquals(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right);

    /// <summary>
    /// Compares two character spans for equality in constant time.
    /// </summary>
    /// <param name="left">The left character span.</param>
    /// <param name="right">The right character span.</param>
    /// <returns><see langword="true"/> if characters are identical; otherwise, <see langword="false"/>.</returns>
    bool FixedTimeEquals(ReadOnlySpan<char> left, ReadOnlySpan<char> right);

    /// <summary>
    /// Compares two character spans for equality in constant time, eliminating length-leakage side channels
    /// by hashing both inputs with a cryptographic digest before constant-time evaluation.
    /// </summary>
    /// <param name="left">The left character span.</param>
    /// <param name="right">The right character span.</param>
    /// <returns><see langword="true"/> if both spans are identical; otherwise, <see langword="false"/>.</returns>
    bool FixedTimeEqualsSecure(ReadOnlySpan<char> left, ReadOnlySpan<char> right);

    /// <summary>
    /// Compares two byte spans for equality in constant time, eliminating length-leakage side channels
    /// by hashing both inputs with a cryptographic digest before constant-time evaluation.
    /// </summary>
    /// <param name="left">The left byte span.</param>
    /// <param name="right">The right byte span.</param>
    /// <returns><see langword="true"/> if both spans are identical; otherwise, <see langword="false"/>.</returns>
    bool FixedTimeEqualsSecure(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right);
}
