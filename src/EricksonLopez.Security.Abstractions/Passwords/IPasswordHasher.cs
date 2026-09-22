// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Abstractions.Passwords;

using System;

/// <summary>
/// Defines the contract for modern, adaptive password hashing, constant-time verification,
/// and automatic rehash detection.
/// </summary>
public interface IPasswordHasher
{
    /// <summary>
    /// Gets the primary password hashing algorithm implemented by this instance.
    /// </summary>
    PasswordHashAlgorithm Algorithm { get; }

    /// <summary>
    /// Computes a cryptographically salted and parameterized password hash for the specified password.
    /// </summary>
    /// <param name="password">The plaintext password character span. Must not exceed 256 characters.</param>
    /// <returns>A standardized, self-describing password hash string.</returns>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="password"/> length exceeds 256 characters.</exception>
    string HashPassword(ReadOnlySpan<char> password);

    /// <summary>
    /// Verifies a plaintext password against a stored hashed password using constant-time evaluation.
    /// </summary>
    /// <param name="password">The candidate password character span to verify</param>
    /// <param name="hashedPassword">The stored hashed password string to evaluate</param>
    /// <returns>A <see cref="PasswordVerificationResult"/> indicating success, success with rehash required, or failure.</returns>
    PasswordVerificationResult VerifyPassword(ReadOnlySpan<char> password, string hashedPassword);

    /// <summary>
    /// Determines whether the given stored password hash requires rehashing due to parameter updates
    /// or algorithm evolution.
    /// </summary>
    /// <param name="hashedPassword">The stored hash string to evaluate</param>
    /// <returns><see langword="true"/> if the hash should be regenerated with current parameters; otherwise, <see langword="false"/>.</returns>
    bool NeedsRehash(string hashedPassword);
}
