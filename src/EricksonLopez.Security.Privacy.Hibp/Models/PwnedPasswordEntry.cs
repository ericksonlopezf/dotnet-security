// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Privacy.Hibp.Models;

using System;

/// <summary>
/// Represents an entry returned from the HIBP range search API containing a SHA-1 hash suffix and breach frequency count.
/// </summary>
public sealed record PwnedPasswordEntry
{
    /// <summary>
    /// Gets the 35-character uppercase hexadecimal SHA-1 hash suffix.
    /// </summary>
    public string Suffix { get; init; }

    /// <summary>
    /// Gets the number of times this password appeared in known data breaches.
    /// </summary>
    public long BreachCount { get; init; }

    /// <summary>
    /// Initializes a new instance of the <see cref="PwnedPasswordEntry"/> record with the specified hash suffix and breach frequency count.
    /// </summary>
    /// <param name="suffix">The 35-character uppercase hexadecimal SHA-1 hash suffix.</param>
    /// <param name="breachCount">The number of times this password appeared in known data breaches.</param>
    /// <exception cref="ArgumentException"><paramref name="suffix"/> is <see langword="null"/>, empty, or whitespace</exception>
    public PwnedPasswordEntry(string suffix, long breachCount)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(suffix);
        Suffix = suffix;
        BreachCount = breachCount;
    }
}
