// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Privacy.Hibp.Models;

using System;

/// <summary>
/// Represents the result of querying a password against the HIBP breached database.
/// </summary>
public sealed record PwnedPasswordCheckResult
{
    /// <summary>
    /// Gets a value indicating whether the password was found in known data breaches.
    /// </summary>
    public bool IsPwned => BreachCount > 0;

    /// <summary>
    /// Gets the number of times this password appeared in known breaches (0 if clean).
    /// </summary>
    public long BreachCount { get; init; }

    /// <summary>
    /// Gets the 5-character SHA-1 prefix representing the k-Anonymity range lookup.
    /// </summary>
    public string HashPrefix { get; init; }

    /// <summary>
    /// Initializes a new instance of the <see cref="PwnedPasswordCheckResult"/> record with the specified hash prefix and breach count.
    /// </summary>
    /// <param name="hashPrefix">Five-character SHA-1 prefix representing the k-Anonymity range lookup.</param>
    /// <param name="breachCount">Total number of observed occurrences in breached databases.</param>
    /// <exception cref="ArgumentException"><paramref name="hashPrefix"/> is <see langword="null"/>, empty, or whitespace</exception>
    public PwnedPasswordCheckResult(string hashPrefix, long breachCount)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(hashPrefix);
        HashPrefix = hashPrefix;
        BreachCount = breachCount;
    }
}
