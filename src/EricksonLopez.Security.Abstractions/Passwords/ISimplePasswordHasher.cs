// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Abstractions.Passwords;

/// <summary>
/// Defines a simplified password hasher contract designed for application-level authentication flows.
/// </summary>
public interface ISimplePasswordHasher
{
    /// <summary>
    /// Computes a cryptographically salted password hash for the specified password.
    /// </summary>
    /// <param name="password">The plaintext password to hash.</param>
    /// <returns>A standardized, self-describing password hash string.</returns>
    string Hash(string password);

    /// <summary>
    /// Verifies a plaintext password against a stored hashed password string.
    /// </summary>
    /// <param name="password">The candidate password to verify.</param>
    /// <param name="hash">The stored hashed password string.</param>
    /// <returns><see langword="true"/> if the password matches the hash; otherwise, <see langword="false"/>.</returns>
    bool Verify(string password, string hash);

    /// <summary>
    /// Determines whether the given stored password hash requires rehashing due to parameter updates
    /// or algorithm evolution.
    /// </summary>
    /// <param name="hash">The stored hash string.</param>
    /// <returns><see langword="true"/> if the hash should be regenerated with current parameters; otherwise, <see langword="false"/>.</returns>
    bool NeedsRehash(string hash);
}
