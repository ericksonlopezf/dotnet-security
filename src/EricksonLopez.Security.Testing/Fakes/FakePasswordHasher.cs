// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Testing.Fakes;

using System;
using EricksonLopez.Security.Abstractions.Passwords;

/// <summary>
/// Provides a deterministic test double implementation of <see cref="IPasswordHasher"/> designed
/// for high-speed unit testing without computational PBKDF2/Argon2 hashing overhead.
/// </summary>
public sealed class FakePasswordHasher : IPasswordHasher
{
    private const string Prefix = "$fake_test_hash$";

    /// <summary>
    /// Gets or sets a value indicating whether <see cref="NeedsRehash"/> should return <see langword="true"/>.
    /// </summary>
    public bool SimulateNeedsRehash { get; set; }

    /// <summary>
    /// Gets the simulated password hash algorithm.
    /// </summary>
    public PasswordHashAlgorithm Algorithm => PasswordHashAlgorithm.Pbkdf2HmacSha512;

    /// <inheritdoc />
    public string HashPassword(ReadOnlySpan<char> password) => $"{Prefix}{new string(password)}";

    /// <inheritdoc />
    public PasswordVerificationResult VerifyPassword(ReadOnlySpan<char> password, string hashedPassword)
    {
        if (string.IsNullOrWhiteSpace(hashedPassword) || !hashedPassword.StartsWith(Prefix, StringComparison.Ordinal))
        {
            return PasswordVerificationResult.Failed;
        }

        var expectedPlaintext = hashedPassword[Prefix.Length..];
        bool matches = password.SequenceEqual(expectedPlaintext.AsSpan());

        if (!matches)
        {
            return PasswordVerificationResult.Failed;
        }

        return SimulateNeedsRehash ? PasswordVerificationResult.SuccessRehashNeeded : PasswordVerificationResult.Success;
    }

    /// <inheritdoc />
    public bool NeedsRehash(string hashedPassword) => SimulateNeedsRehash;
}
