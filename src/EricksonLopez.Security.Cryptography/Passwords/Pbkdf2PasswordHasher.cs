// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Cryptography.Passwords;

using System;
using System.Security.Cryptography;
using System.Text;
using EricksonLopez.Security.Abstractions.Passwords;
using EricksonLopez.Security.Abstractions.Randomness;

/// <summary>
/// Provides password hashing using PBKDF2 (HMAC-SHA512) per format <c>PBKDF2.V1$&lt;iterations&gt;$&lt;salt&gt;$&lt;hash&gt;</c>, compatible with Native AOT and zero dependencies.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Tier 1 — Direct Cryptographic Primitive</strong>: This hasher is part of
/// <c>EricksonLopez.Security.Cryptography</c> and targets direct use in standalone cryptographic
/// workflows. It uses <strong>600,000 PBKDF2-HMAC-SHA512 iterations</strong> and the
/// <c>PBKDF2.V1$</c> modular crypt prefix.
/// </para>
/// <para>
/// <strong>Format incompatibility with Tier 2</strong>: The hash format produced by this hasher
/// (<c>PBKDF2.V1$&lt;iterations&gt;$&lt;salt&gt;$&lt;hash&gt;</c>) is <strong>not interchangeable</strong>
/// with the format produced by <c>EricksonLopez.Security.Passwords.Pbkdf2PasswordHasher</c>
/// (<c>$pbkdf2-sha512$i=210000$s=&lt;salt&gt;$&lt;hash&gt;</c>). Mixing hashes from both classes in
/// the same verification path will cause <c>PasswordVerificationResult.Failed</c>.
/// See ADR-023 (Dual PBKDF2 Password Hasher Archetypes) for full rationale.
/// </para>
/// <para>
/// <strong>Choosing the right hasher</strong>:
/// <list type="bullet">
/// <item>Use this hasher for direct cryptographic derivation workflows where hash format interop is not required.</item>
/// <item>Use <c>EricksonLopez.Security.Passwords.Pbkdf2PasswordHasher</c> (Tier 2) with <c>CompositePasswordHasher</c> for application password management with multi-algorithm migration support.</item>
/// </list>
/// </para>
/// </remarks>
public sealed class Pbkdf2PasswordHasher : IPasswordHasher
{
    /// <summary>
    /// Defines the default number of PBKDF2 iterations (600,000) recommended by OWASP for SHA-512 password hashing.
    /// </summary>
    public const int DefaultIterations = 600_000;

    // Maximum iteration count accepted from a stored hash string during verification.
    // Hashes claiming more than this value are rejected immediately without computing (DoS prevention, FINDING-NEW-01).
    // Bound to 600,000 iterations per OWASP/NIST guidelines to prevent CPU exhaustion.
    private const int MaxStoredIterations = 600_000;

    private const int SaltSizeBytes = 16;
    private const int HashSizeBytes = 32;
    private const string FormatPrefix = "PBKDF2.V1";
    private const char Delimiter = '$';

    private readonly int _iterations;
    private readonly IConstantTimeComparer _comparer;
    private readonly ICryptographicRandomNumberGenerator _random;

    /// <summary>
    /// Initializes a new instance of the <see cref="Pbkdf2PasswordHasher"/> class with default iterations (600,000).
    /// </summary>
    /// <param name="comparer">The comparer for constant-time hash verification.</param>
    /// <param name="random">The cryptographic random number generator for generating cryptographic salts.</param>
    /// <exception cref="ArgumentNullException"><paramref name="comparer"/> or <paramref name="random"/> is <see langword="null"/></exception>
    public Pbkdf2PasswordHasher(IConstantTimeComparer comparer, ICryptographicRandomNumberGenerator random)
        : this(comparer, random, DefaultIterations)
    {
    }

    internal Pbkdf2PasswordHasher(IConstantTimeComparer comparer, ICryptographicRandomNumberGenerator random, int iterations)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(iterations, 1000);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(iterations, MaxStoredIterations);

        _comparer = comparer ?? throw new ArgumentNullException(nameof(comparer));
        _random = random ?? throw new ArgumentNullException(nameof(random));
        _iterations = iterations;
    }

    /// <summary>
    /// Gets the password hashing algorithm implemented by this hasher (<see cref="PasswordHashAlgorithm.Pbkdf2HmacSha512"/>).
    /// </summary>
    public PasswordHashAlgorithm Algorithm => PasswordHashAlgorithm.Pbkdf2HmacSha512;

    /// <inheritdoc/>
    public string HashPassword(ReadOnlySpan<char> password)
    {
        if (password.Length > 256)
        {
            throw new ArgumentOutOfRangeException(nameof(password), "Password length cannot exceed 256 characters.");
        }

        var salt = new byte[SaltSizeBytes];
        _random.Fill(salt);

        var hash = Rfc2898DeriveBytes.Pbkdf2(password, salt, _iterations, HashAlgorithmName.SHA512, HashSizeBytes);

        return $"{FormatPrefix}{Delimiter}{_iterations}{Delimiter}{Convert.ToBase64String(salt)}{Delimiter}{Convert.ToBase64String(hash)}";
    }


    /// <inheritdoc/>
    public PasswordVerificationResult VerifyPassword(ReadOnlySpan<char> password, string hashedPassword)
    {
        if (string.IsNullOrWhiteSpace(hashedPassword) || hashedPassword.Length > 512 || password.Length > 256)
            return PasswordVerificationResult.Failed;

        if (hashedPassword.StartsWith("$pbkdf2-sha512$", StringComparison.Ordinal))
        {
            return VerifyTier2Pbkdf2Format(password, hashedPassword);
        }

        var parts = hashedPassword.Split(Delimiter);
        if (parts.Length != 4 || parts[0] != FormatPrefix)
            return PasswordVerificationResult.Failed;

        if (!int.TryParse(parts[1], out var iterations))
            return PasswordVerificationResult.Failed;

        // DOS-001 / FINDING-NEW-01: Reject hashes with unreasonable iteration counts immediately.
        if (iterations <= 0 || iterations > MaxStoredIterations)
            return PasswordVerificationResult.Failed;

        // FINDING-NEW-02 / SEC-MEM-1: Pre-allocation validation.
        // Reject strings that cannot be valid base64 representation of 8-64 byte buffers before allocating.
        if (parts[2].Length < 11 || parts[2].Length > 128 || parts[3].Length < 22 || parts[3].Length > 128)
            return PasswordVerificationResult.Failed;

        Span<byte> salt = stackalloc byte[64];
        Span<byte> expectedHash = stackalloc byte[64];

        if (!Convert.TryFromBase64Chars(parts[2].AsSpan(), salt, out int saltBytesWritten) ||
            !Convert.TryFromBase64Chars(parts[3].AsSpan(), expectedHash, out int hashBytesWritten))
        {
            return PasswordVerificationResult.Failed;
        }

        // Reject invalid salt length (must be at least 8 bytes and at most 64 bytes)
        // Reject invalid hash length (must be between 16 and 64 bytes, preventing empty-hash bypass and excessive allocations)
        if (saltBytesWritten < 8 || saltBytesWritten > 64 || hashBytesWritten < 16 || hashBytesWritten > 64)
        {
            return PasswordVerificationResult.Failed;
        }

        var actualSalt = salt[..saltBytesWritten];
        var actualExpectedHash = expectedHash[..hashBytesWritten];

        Span<byte> actualHash = stackalloc byte[hashBytesWritten];
        try
        {
            Rfc2898DeriveBytes.Pbkdf2(password, actualSalt, actualHash, iterations, HashAlgorithmName.SHA512);

            if (!_comparer.FixedTimeEquals(actualHash, actualExpectedHash))
            {
                return PasswordVerificationResult.Failed;
            }

            return NeedsRehash(hashedPassword)
                ? PasswordVerificationResult.SuccessRehashNeeded
                : PasswordVerificationResult.Success;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(actualHash);
            CryptographicOperations.ZeroMemory(salt);
            CryptographicOperations.ZeroMemory(expectedHash);
        }
    }

    private PasswordVerificationResult VerifyTier2Pbkdf2Format(ReadOnlySpan<char> password, string hashedPassword)
    {
        var parts = hashedPassword.Split('$', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length != 4 || !parts[1].StartsWith("i=", StringComparison.Ordinal) || !parts[2].StartsWith("s=", StringComparison.Ordinal))
        {
            return PasswordVerificationResult.Failed;
        }

        if (!int.TryParse(parts[1].AsSpan(2), out int iterations) || iterations <= 0 || iterations > MaxStoredIterations)
        {
            return PasswordVerificationResult.Failed;
        }

        // FINDING-NEW-02 / SEC-MEM-1: Pre-allocation validation
        if (parts[2].Length < 13 || parts[2].Length > 130 || parts[3].Length < 22 || parts[3].Length > 128)
        {
            return PasswordVerificationResult.Failed;
        }

        Span<byte> salt = stackalloc byte[64];
        Span<byte> expectedHash = stackalloc byte[64];

        if (!Convert.TryFromBase64Chars(parts[2].AsSpan(2), salt, out int saltBytesWritten) ||
            !Convert.TryFromBase64Chars(parts[3].AsSpan(), expectedHash, out int hashBytesWritten))
        {
            return PasswordVerificationResult.Failed;
        }

        // Reject invalid salt length (must be at least 8 bytes and at most 64 bytes)
        // Reject invalid hash length (must be between 16 and 64 bytes, preventing empty-hash bypass and excessive allocations)
        if (saltBytesWritten < 8 || saltBytesWritten > 64 || hashBytesWritten < 16 || hashBytesWritten > 64)
        {
            return PasswordVerificationResult.Failed;
        }

        Span<byte> actualHash = stackalloc byte[hashBytesWritten];
        try
        {
            Rfc2898DeriveBytes.Pbkdf2(password, salt[..saltBytesWritten], actualHash, iterations, HashAlgorithmName.SHA512);

            if (!_comparer.FixedTimeEquals(actualHash, expectedHash[..hashBytesWritten]))
            {
                return PasswordVerificationResult.Failed;
            }

            return PasswordVerificationResult.SuccessRehashNeeded;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(actualHash);
            CryptographicOperations.ZeroMemory(salt);
            CryptographicOperations.ZeroMemory(expectedHash);
        }
    }

    /// <inheritdoc/>
    /// <remarks>
    /// Returns <see langword="true"/> if <paramref name="hashedPassword"/> is null, empty, or whitespace
    /// (indicating an invalid hash that must be regenerated); returns <see langword="true"/> also if
    /// the format is invalid, matches Tier 2 format, or stored iterations are less than <c>600,000</c>.
    /// Returns <see langword="false"/> only when the hash is well-formed and meets current iteration requirements.
    /// </remarks>
    public bool NeedsRehash(string hashedPassword)
    {
        if (string.IsNullOrWhiteSpace(hashedPassword))
            return true;

        if (hashedPassword.StartsWith("$pbkdf2-sha512$", StringComparison.Ordinal))
            return true;

        var parts = hashedPassword.Split(Delimiter);
        if (parts.Length != 4 || parts[0] != FormatPrefix)
            return true;

        if (int.TryParse(parts[1], out var iterations))
        {
            return iterations < _iterations;
        }

        return true;
    }
}
