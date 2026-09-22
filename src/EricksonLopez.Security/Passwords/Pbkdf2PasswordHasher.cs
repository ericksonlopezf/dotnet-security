// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Passwords;

using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using EricksonLopez.Security.Abstractions.Passwords;
using EricksonLopez.Security.Diagnostics;

/// <summary>
/// Provides a Password-Based Key Derivation Function 2 (PBKDF2) password hasher using HMAC-SHA512 per RFC 8018
/// and NIST SP 800-63B / OWASP recommendations.
/// Formats hashes using the modular crypt format: <c>$pbkdf2-sha512$i=210000$s=&lt;salt&gt;$&lt;hash&gt;</c>.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Architectural Tier (ADR-023)</strong>: Belongs to the <em>Tier 2 — Application
/// Password Layer</em> within the dual PBKDF2 architecture. It uses the modular crypt format
/// <c>$pbkdf2-sha512$i={iterations}$s={salt}${hash}</c> with a default of <strong>210,000 iterations</strong>
/// (OWASP-recommended minimum for SHA-512).
/// </para>
/// <para>
/// <strong>Format incompatibility warning</strong>: The hash format produced by this implementation
/// (<c>$pbkdf2-sha512$</c> prefix) is <em>not interoperable</em> with the standalone
/// <c>EricksonLopez.Security.Cryptography.Pbkdf2PasswordHasher</c>, which uses the
/// <c>PBKDF2.V1$</c> prefix with 600,000 iterations and a different salt encoding.
/// Mixing hashes from both tiers in the same storage table and routing them through the wrong
/// hasher will cause all verifications to return <c>Failed</c>. See ADR-023 for the complete
/// tier segregation rationale and migration guidance.
/// </para>
/// <para>
/// <strong>Registration</strong>: When using <c>AddEricksonLopezSecurity()</c> or
/// <c>AddPasswordSecurity()</c>, this hasher is registered as the primary hasher inside
/// <see cref="CompositePasswordHasher"/>. New passwords are hashed with the
/// <c>$pbkdf2-sha512$</c> format. Existing <c>$argon2id$</c> hashes are verified transparently
/// and flagged for rehash on next successful login.
/// </para>
/// </remarks>
public sealed class Pbkdf2PasswordHasher : IPasswordHasher
{
    private const string ModularCryptPrefix = "$pbkdf2-sha512$";
    private const int DefaultSaltSizeBytes = 16;   // 128 bits
    private const int DefaultDerivedSizeBytes = 32; // 256 bits
    private readonly int _iterations;
    private readonly int _saltSizeBytes;
    private readonly int _derivedKeySizeBytes;

    /// <summary>
    /// Gets the default recommended iterations for PBKDF2-HMAC-SHA512 (210,000 per OWASP guidance).
    /// </summary>
    public const int DefaultIterations = 210_000;

    // Maximum iteration count accepted from a stored hash string during verification.
    // Hashes claiming more than this value are rejected immediately (DoS prevention, FINDING-NEW-01).
    private const int MaxStoredIterations = 600_000;

    /// <summary>
    /// Gets the default singleton instance configured with 210,000 iterations, 16-byte salt, and 32-byte derived key.
    /// </summary>
    public static readonly Pbkdf2PasswordHasher Default = new();

    /// <inheritdoc />
    public PasswordHashAlgorithm Algorithm => PasswordHashAlgorithm.Pbkdf2HmacSha512;

    /// <summary>
    /// Initializes a new instance of the <see cref="Pbkdf2PasswordHasher"/> class.
    /// </summary>
    /// <param name="iterations">The number of PBKDF2 iterations (defaults to 210,000).</param>
    /// <param name="saltSizeBytes">The salt size in bytes (defaults to 16).</param>
    /// <param name="derivedKeySizeBytes">The derived key size in bytes (defaults to 32).</param>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="iterations"/> is less than 10,000 or greater than 600,000</exception>
    public Pbkdf2PasswordHasher(
        int iterations = DefaultIterations,
        int saltSizeBytes = DefaultSaltSizeBytes,
        int derivedKeySizeBytes = DefaultDerivedSizeBytes)
    {
        if (iterations < 10_000 || iterations > 600_000)
        {
            throw new ArgumentOutOfRangeException(nameof(iterations), iterations, "Iterations must be between 10,000 and 600,000 to prevent DoS.");
        }

        ArgumentOutOfRangeException.ThrowIfLessThan(saltSizeBytes, 8);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(saltSizeBytes, 64);
        ArgumentOutOfRangeException.ThrowIfLessThan(derivedKeySizeBytes, 16);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(derivedKeySizeBytes, 64);

        _iterations = iterations;
        _saltSizeBytes = saltSizeBytes;
        _derivedKeySizeBytes = derivedKeySizeBytes;
    }

    /// <inheritdoc />
    public string HashPassword(ReadOnlySpan<char> password)
    {
        if (password.Length > 256)
        {
            throw new ArgumentOutOfRangeException(nameof(password), "Password length cannot exceed 256 characters.");
        }

        using var activity = SecurityActivitySource.Instance
            .StartActivity(SecurityActivitySource.HashPasswordOperation, ActivityKind.Internal);
        activity?.SetTag(SecurityActivitySource.TagHashAlgorithm, "pbkdf2-sha512");

        var sw = Stopwatch.StartNew();

        // Normalize Unicode representation to Form C per NIST SP 800-63B recommendations
        string normalizedPassword = password.ToString().Normalize(NormalizationForm.FormC);

        Span<byte> salt = stackalloc byte[_saltSizeBytes];
        RandomNumberGenerator.Fill(salt);

        Span<byte> derivedKey = stackalloc byte[_derivedKeySizeBytes];
        Rfc2898DeriveBytes.Pbkdf2(
            password: normalizedPassword.AsSpan(),
            salt: salt,
            destination: derivedKey,
            iterations: _iterations,
            hashAlgorithm: HashAlgorithmName.SHA512);

        string saltBase64 = Convert.ToBase64String(salt);
        string hashBase64 = Convert.ToBase64String(derivedKey);

        ScrubEphemeralMemory(derivedKey);

        sw.Stop();
        SecurityMeter.Pbkdf2HashingDurationMs.Record(sw.Elapsed.TotalMilliseconds);
        activity?.SetTag(SecurityActivitySource.TagResult, "success");

        return $"{ModularCryptPrefix}i={_iterations}$s={saltBase64}${hashBase64}";
    }

    /// <inheritdoc />
    public PasswordVerificationResult VerifyPassword(ReadOnlySpan<char> password, string hashedPassword)
    {
        using var activity = SecurityActivitySource.Instance
            .StartActivity(SecurityActivitySource.VerifyPasswordOperation, ActivityKind.Internal);
        activity?.SetTag(SecurityActivitySource.TagHashAlgorithm, "pbkdf2-sha512");

        var result = VerifyPasswordCore(password, hashedPassword);

        var resultTag = result switch
        {
            PasswordVerificationResult.Success => "success",
            PasswordVerificationResult.SuccessRehashNeeded => "rehash_needed",
            _ => "failure"
        };

        SecurityMeter.PasswordVerificationsTotal.Add(1,
            new KeyValuePair<string, object?>(SecurityActivitySource.TagResult, resultTag),
            new KeyValuePair<string, object?>(SecurityActivitySource.TagHashAlgorithm, "pbkdf2-sha512"));

        activity?.SetTag(SecurityActivitySource.TagResult, resultTag);

        return result;
    }

    private PasswordVerificationResult VerifyPasswordCore(ReadOnlySpan<char> password, string hashedPassword)
    {
        if (string.IsNullOrWhiteSpace(hashedPassword) || hashedPassword.Length > 512 || password.Length > 256)
        {
            return PasswordVerificationResult.Failed;
        }

        // Normalize Unicode representation to Form C per NIST SP 800-63B recommendations
        string normalizedPassword = password.ToString().Normalize(NormalizationForm.FormC);
        ReadOnlySpan<char> passwordSpan = normalizedPassword.AsSpan();

        if (hashedPassword.StartsWith("PBKDF2.V1$", StringComparison.Ordinal))
        {
            return VerifyTier1Pbkdf2Format(passwordSpan, hashedPassword);
        }

        if (!hashedPassword.StartsWith(ModularCryptPrefix, StringComparison.Ordinal))
        {
            return PasswordVerificationResult.Failed;
        }

        // Format: $pbkdf2-sha512$i=210000$s=<salt>$<hash>
        var parts = hashedPassword.Split('$', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length != 4)
        {
            return PasswordVerificationResult.Failed;
        }

        // parts[0]: "pbkdf2-sha512"
        // parts[1]: "i=210000"
        // parts[2]: "s=<salt>"
        // parts[3]: "<hash>"
        if (!parts[1].StartsWith("i=", StringComparison.Ordinal) || !int.TryParse(parts[1].AsSpan(2), out int storedIterations))
        {
            return PasswordVerificationResult.Failed;
        }

        // DOS-001 / FINDING-NEW-01: Reject hashes with unreasonable iteration counts fast, without computing.
        if (storedIterations <= 0 || storedIterations > MaxStoredIterations)
        {
            return PasswordVerificationResult.Failed;
        }

        if (!parts[2].StartsWith("s=", StringComparison.Ordinal))
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
        // Reject invalid hash length (must be between 16 and 64 bytes, preventing empty-hash bypass and stack overflow)
        if (saltBytesWritten < 8 || saltBytesWritten > 64 || hashBytesWritten < 16 || hashBytesWritten > 64)
        {
            return PasswordVerificationResult.Failed;
        }

        Span<byte> computedHash = stackalloc byte[hashBytesWritten];
        try
        {
            Rfc2898DeriveBytes.Pbkdf2(
                password: passwordSpan,
                salt: salt[..saltBytesWritten],
                destination: computedHash,
                iterations: storedIterations,
                hashAlgorithm: HashAlgorithmName.SHA512);

            bool matches = CryptographicOperations.FixedTimeEquals(computedHash, expectedHash[..hashBytesWritten]);
            if (!matches)
            {
                return PasswordVerificationResult.Failed;
            }

            return storedIterations < _iterations ? PasswordVerificationResult.SuccessRehashNeeded : PasswordVerificationResult.Success;
        }
        finally
        {
            ScrubEphemeralMemory(computedHash);
            ScrubEphemeralMemory(expectedHash);
            ScrubEphemeralMemory(salt);
        }
    }

    private PasswordVerificationResult VerifyTier1Pbkdf2Format(ReadOnlySpan<char> password, string hashedPassword)
    {
        // Format: PBKDF2.V1$<iterations>$<salt_base64>$<hash_base64>
        var parts = hashedPassword.Split('$');
        if (parts.Length != 4 || parts[0] != "PBKDF2.V1" || !int.TryParse(parts[1], out int storedIterations))
        {
            return PasswordVerificationResult.Failed;
        }

        // DOS-001 / FINDING-NEW-01: Reject cross-tier hashes with unreasonable iteration counts fast.
        if (storedIterations <= 0 || storedIterations > MaxStoredIterations)
        {
            return PasswordVerificationResult.Failed;
        }

        // FINDING-NEW-02 / SEC-MEM-1: Pre-allocation validation
        if (parts[2].Length < 11 || parts[2].Length > 128 || parts[3].Length < 22 || parts[3].Length > 128)
        {
            return PasswordVerificationResult.Failed;
        }

        Span<byte> salt = stackalloc byte[64];
        Span<byte> expectedHash = stackalloc byte[64];

        if (!Convert.TryFromBase64Chars(parts[2].AsSpan(), salt, out int saltBytesWritten) ||
            !Convert.TryFromBase64Chars(parts[3].AsSpan(), expectedHash, out int hashBytesWritten))
        {
            return PasswordVerificationResult.Failed;
        }

        // Reject invalid salt length (must be at least 8 bytes and at most 64 bytes)
        // Reject invalid hash length (must be between 16 and 64 bytes, preventing empty-hash bypass and stack overflow)
        if (saltBytesWritten < 8 || saltBytesWritten > 64 || hashBytesWritten < 16 || hashBytesWritten > 64)
        {
            return PasswordVerificationResult.Failed;
        }

        Span<byte> computedHash = stackalloc byte[hashBytesWritten];
        try
        {
            Rfc2898DeriveBytes.Pbkdf2(
                password: password,
                salt: salt[..saltBytesWritten],
                destination: computedHash,
                iterations: storedIterations,
                hashAlgorithm: HashAlgorithmName.SHA512);

            bool matches = CryptographicOperations.FixedTimeEquals(computedHash, expectedHash[..hashBytesWritten]);
            if (!matches)
            {
                return PasswordVerificationResult.Failed;
            }

            return storedIterations < _iterations ? PasswordVerificationResult.SuccessRehashNeeded : PasswordVerificationResult.Success;
        }
        finally
        {
            ScrubEphemeralMemory(computedHash);
            ScrubEphemeralMemory(expectedHash);
            ScrubEphemeralMemory(salt);
        }
    }

    /// <inheritdoc />
    public bool NeedsRehash(string hashedPassword)
    {
        if (string.IsNullOrWhiteSpace(hashedPassword))
        {
            return true;
        }

        if (hashedPassword.StartsWith("PBKDF2.V1$", StringComparison.Ordinal))
        {
            var tier1Parts = hashedPassword.Split('$');
            if (tier1Parts.Length == 4 && int.TryParse(tier1Parts[1], out int tier1Iterations))
            {
                return tier1Iterations < _iterations;
            }
            return true;
        }

        if (!hashedPassword.StartsWith(ModularCryptPrefix, StringComparison.Ordinal))
        {
            return true;
        }

        var parts = hashedPassword.Split('$', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length != 4 ||
            !parts[1].StartsWith("i=", StringComparison.Ordinal) ||
            !parts[2].StartsWith("s=", StringComparison.Ordinal) ||
            !int.TryParse(parts[1].AsSpan(2), out int storedIterations))
        {
            return true;
        }

        return storedIterations < _iterations;
    }

    [System.Runtime.CompilerServices.MethodImpl(System.Runtime.CompilerServices.MethodImplOptions.AggressiveInlining)]
    private static void ScrubEphemeralMemory(Span<byte> buffer) => CryptographicOperations.ZeroMemory(buffer);
}
