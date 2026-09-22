// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Passwords;

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Security.Cryptography;
using EricksonLopez.Security.Abstractions.Passwords;
using EricksonLopez.Security.Diagnostics;

/// <summary>
/// Provides a PBKDF2-HMAC-SHA512 password hasher that emits hashes using the
/// <c>$legacy-pbkdf2$</c> modular crypt prefix (native) and can also verify
/// hashes in the legacy <c>$argon2id$</c> format produced by earlier versions
/// of this hasher (see ADR-024).
/// </summary>
/// <remarks>
/// <para>
/// <strong>Cryptographic Substrate</strong>: The underlying key derivation function is
/// <strong>PBKDF2-HMAC-SHA512</strong> (via <c>Rfc2898DeriveBytes.Pbkdf2</c>), not the Argon2id
/// memory-hard algorithm described in RFC 9106. The actual iteration count applied to PBKDF2 is
/// <c>iterations × 70,000</c> (default: <c>3 × 70,000 = 210,000</c>). The <c>m=</c> (memory) and
/// <c>p=</c> (parallelism) cost parameters are stored as format metadata and participate in
/// <see cref="NeedsRehash"/> comparison, but are not consumed by the derivation function.
/// </para>
/// <para>
/// <strong>Format compatibility</strong>: New hashes produced by this hasher use the <c>$legacy-pbkdf2$</c>
/// prefix. Hashes with the old <c>$argon2id$</c> prefix (produced by earlier versions) are verified
/// transparently and flagged for rehash via <see cref="NeedsRehash"/>. Both formats are routed
/// through <see cref="CompositePasswordHasher"/> alongside PBKDF2 hashes.
/// </para>
/// <para>
/// <strong>Security posture</strong>: PBKDF2-HMAC-SHA512 at 210,000+ iterations meets OWASP and
/// NIST SP 800-63B recommendations and provides GPU resistance via SHA-512's compute cost.
/// It is not memory-hard; consider this when evaluating against hardware accelerated offline attacks.
/// </para>
/// </remarks>
public sealed class LegacyPbkdf2PasswordHasher : IPasswordHasher
{
    private const string ModularCryptPrefix = "$legacy-pbkdf2$";
    private const string LegacySpoofedArgon2idPrefix = "$argon2id$";

    /// <summary>
    /// Minimum allowed time cost parameter (<c>t</c>) accepted by this hasher.
    /// </summary>
    public const int MinAllowedTimeCost = 1;

    /// <summary>
    /// Maximum time-cost multiplier accepted from a stored hash during verification.
    /// Effective PBKDF2 iterations = storedTimeCost × 70,000; a cap of 10 limits
    /// computation to 700,000 PBKDF2 iterations — preventing DoS (DOS-001 / SEC-002).
    /// </summary>
    public const int MaxAllowedTimeCost = 10;
    private readonly int _memorySizeKb;
    private readonly int _iterations;
    private readonly int _parallelism;
    private readonly int _saltSizeBytes;

    /// <summary>
    /// Gets the default singleton instance configured with 64 MB memory, 3 time-cost iterations
    /// (effective PBKDF2 iterations: 210,000), and 4 parallelism lanes.
    /// </summary>
    public static readonly LegacyPbkdf2PasswordHasher Default = new();

    /// <inheritdoc />
    /// <remarks>
    /// SEC-005 fix: Returns <see cref="PasswordHashAlgorithm.Pbkdf2HmacSha512"/> — the actual cryptographic
    /// substrate is PBKDF2-HMAC-SHA512, <em>not</em> the memory-hard Argon2id algorithm described in RFC 9106.
    /// The hash format prefix (<c>$legacy-pbkdf2$</c> or legacy <c>$argon2id$</c>) is a format identifier
    /// separate from the cryptographic algorithm actually applied during key derivation. See ADR-024 and
    /// <see cref="SubstrateDescription"/> for more details.
    /// </remarks>
    public PasswordHashAlgorithm Algorithm => PasswordHashAlgorithm.Pbkdf2HmacSha512;

    /// <summary>
    /// Gets a value indicating whether the underlying key derivation function is memory-hard.
    /// </summary>
    /// <remarks>
    /// Evaluates to <see langword="false"/> per ADR-024 because the v1.x substrate is PBKDF2-HMAC-SHA512.
    /// </remarks>
    public static bool IsMemoryHard => false;

    /// <summary>
    /// Gets the cryptographic substrate name backing this hasher.
    /// </summary>
    public static string SubstrateDescription => "PBKDF2-HMAC-SHA512 (ADR-024)";

    /// <summary>
    /// Initializes a new instance of the <see cref="LegacyPbkdf2PasswordHasher"/> class.
    /// </summary>
    /// <param name="memorySizeKb">
    /// Memory cost in kibibytes stored in the hash format header (e.g. <c>m=65536</c>).
    /// Participates in format-level rehash detection via <see cref="NeedsRehash"/> without being consumed
    /// by the underlying PBKDF2 derivation function.
    /// </param>
    /// <param name="iterations">
    /// Time-cost iteration multiplier where effective PBKDF2 iterations equal <c>iterations × 70,000</c>.
    /// Default is <c>3</c> (210,000 PBKDF2 rounds), stored as <c>t=</c> in the hash header.
    /// </param>
    /// <param name="parallelism">
    /// Degree of parallelism stored in the hash format header (e.g. <c>p=4</c>).
    /// Participates in format-level rehash detection via <see cref="NeedsRehash"/> without being consumed
    /// by the underlying PBKDF2 derivation function.
    /// </param>
    /// <param name="saltSizeBytes">The length of the generated cryptographic salt in bytes, defaulting to 16.</param>
    /// <exception cref="ArgumentOutOfRangeException">Any parameter is outside its permitted range</exception>
    public LegacyPbkdf2PasswordHasher(
        int memorySizeKb = 65536,
        int iterations = 3,
        int parallelism = 4,
        int saltSizeBytes = 16)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(iterations, MinAllowedTimeCost);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(iterations, MaxAllowedTimeCost);
        ArgumentOutOfRangeException.ThrowIfLessThan(memorySizeKb, 1024);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(memorySizeKb, 65536);
        ArgumentOutOfRangeException.ThrowIfLessThan(parallelism, 1);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(parallelism, 16);
        ArgumentOutOfRangeException.ThrowIfLessThan(saltSizeBytes, 8);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(saltSizeBytes, 64);

        _memorySizeKb = memorySizeKb;
        _iterations = iterations;
        _parallelism = parallelism;
        _saltSizeBytes = saltSizeBytes;
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
        activity?.SetTag(SecurityActivitySource.TagHashAlgorithm, "pbkdf2-sha512"); // CRYPT-006 fix: actual KDF is PBKDF2-HMAC-SHA512, not Argon2id

        var sw = Stopwatch.StartNew();

        // Generate random salt
        Span<byte> salt = stackalloc byte[_saltSizeBytes];
        RandomNumberGenerator.Fill(salt);

        // Derive 32-byte key via PBKDF2-HMAC-SHA512 (effective iterations = _iterations × 70,000)
        Span<byte> derivedKey = stackalloc byte[32];
        Rfc2898DeriveBytes.Pbkdf2(
            password: password,
            salt: salt,
            destination: derivedKey,
            iterations: _iterations * 70_000,
            hashAlgorithm: HashAlgorithmName.SHA512);

        string saltBase64 = Convert.ToBase64String(salt);
        string hashBase64 = Convert.ToBase64String(derivedKey);

        CryptographicOperations.ZeroMemory(derivedKey);

        sw.Stop();
        SecurityMeter.LegacyPbkdf2HashingDurationMs.Record(sw.Elapsed.TotalMilliseconds);
        activity?.SetTag(SecurityActivitySource.TagResult, "success");

        return $"{ModularCryptPrefix}v=19$m={_memorySizeKb},t={_iterations},p={_parallelism}${saltBase64}${hashBase64}";
    }

    /// <inheritdoc />
    public PasswordVerificationResult VerifyPassword(ReadOnlySpan<char> password, string hashedPassword)
    {
        using var activity = SecurityActivitySource.Instance
            .StartActivity(SecurityActivitySource.VerifyPasswordOperation, ActivityKind.Internal);
        var result = VerifyPasswordCore(password, hashedPassword);

        // Extract algorithm tag based on actual prefix for metrics
        string algoTag = hashedPassword?.StartsWith(LegacySpoofedArgon2idPrefix, StringComparison.Ordinal) == true ? "argon2id" : "legacy-pbkdf2";

        string resultTag = result switch
        {
            PasswordVerificationResult.Success => "success",
            PasswordVerificationResult.SuccessRehashNeeded => "rehash_needed",
            _ => "failure"
        };

        SecurityMeter.PasswordVerificationsTotal.Add(1,
            new KeyValuePair<string, object?>(SecurityActivitySource.TagResult, resultTag),
            new KeyValuePair<string, object?>(SecurityActivitySource.TagHashAlgorithm, algoTag));
        activity?.SetTag(SecurityActivitySource.TagResult, resultTag);

        return result;
    }

    private PasswordVerificationResult VerifyPasswordCore(ReadOnlySpan<char> password, string hashedPassword)
    {
        if (string.IsNullOrWhiteSpace(hashedPassword) || password.Length > 256 || hashedPassword.Length > 512)
        {
            return PasswordVerificationResult.Failed;
        }

        bool isNativeFormat = hashedPassword.StartsWith(ModularCryptPrefix, StringComparison.Ordinal);
        bool isSpoofedFormat = hashedPassword.StartsWith(LegacySpoofedArgon2idPrefix, StringComparison.Ordinal);

        if (!isNativeFormat && !isSpoofedFormat)
        {
            return PasswordVerificationResult.Failed;
        }

        var parts = hashedPassword.Split('$', StringSplitOptions.RemoveEmptyEntries);
        // parts[0]: "legacy-pbkdf2" or "argon2id", parts[1]: "v=19", parts[2]: "m=65536,t=3,p=4", parts[3]: "<salt>", parts[4]: "<hash>"
        if (parts.Length != 5)
        {
            return PasswordVerificationResult.Failed;
        }

        // Validate parameter segment BEFORE allocating/decoding buffers
        int storedIterations = -1;
        var paramPairs = parts[2].Split(',', StringSplitOptions.RemoveEmptyEntries);
        foreach (var pair in paramPairs)
        {
            if (pair.StartsWith("t=", StringComparison.Ordinal))
            {
                if (!int.TryParse(pair.AsSpan(2), out int parsedT) || parsedT < MinAllowedTimeCost || parsedT > MaxAllowedTimeCost)
                {
                    // DOS-001 / SEC-002: Reject out-of-bounds time-cost multiplier fast
                    return PasswordVerificationResult.Failed;
                }

                storedIterations = parsedT;
            }
        }

        // Enforce that a valid t= parameter was present within allowable bounds
        if (storedIterations < MinAllowedTimeCost || storedIterations > MaxAllowedTimeCost)
        {
            return PasswordVerificationResult.Failed;
        }

        if (parts[3].Length < 8 || parts[3].Length > 128 || parts[4].Length < 16 || parts[4].Length > 128)
        {
            return PasswordVerificationResult.Failed;
        }

        Span<byte> salt = stackalloc byte[64];
        if (!Convert.TryFromBase64Chars(parts[3], salt, out int saltBytesWritten) || saltBytesWritten < 8 || saltBytesWritten > 64)
        {
            return PasswordVerificationResult.Failed;
        }

        Span<byte> expectedHash = stackalloc byte[64];
        if (!Convert.TryFromBase64Chars(parts[4], expectedHash, out int hashBytesWritten) || hashBytesWritten < 16 || hashBytesWritten > 64)
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
                iterations: storedIterations * 70_000,
                hashAlgorithm: HashAlgorithmName.SHA512);

            bool matches = CryptographicOperations.FixedTimeEquals(computedHash, expectedHash[..hashBytesWritten]);
            if (!matches)
            {
                return PasswordVerificationResult.Failed;
            }

            return NeedsRehash(hashedPassword)
                ? PasswordVerificationResult.SuccessRehashNeeded
                : PasswordVerificationResult.Success;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(computedHash);
            CryptographicOperations.ZeroMemory(expectedHash);
            CryptographicOperations.ZeroMemory(salt);
        }
    }

    /// <inheritdoc />
    public bool NeedsRehash(string hashedPassword)
    {
        if (string.IsNullOrWhiteSpace(hashedPassword))
        {
            return true;
        }

        if (!hashedPassword.StartsWith(ModularCryptPrefix, StringComparison.Ordinal))
        {
            return true;
        }

        var parts = hashedPassword.Split('$', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length != 5)
        {
            return true;
        }

        var paramPairs = parts[2].Split(',', StringSplitOptions.RemoveEmptyEntries);
        int storedMemory = 0, storedIterations = 0, storedParallelism = 0;

        foreach (var pair in paramPairs)
        {
            if (pair.StartsWith("m=", StringComparison.Ordinal) && int.TryParse(pair.AsSpan(2), out int m))
            {
                storedMemory = m;
            }
            else if (pair.StartsWith("t=", StringComparison.Ordinal) && int.TryParse(pair.AsSpan(2), out int t))
            {
                storedIterations = t;
            }
            else if (pair.StartsWith("p=", StringComparison.Ordinal) && int.TryParse(pair.AsSpan(2), out int p))
            {
                storedParallelism = p;
            }
        }

        if (storedMemory != _memorySizeKb || storedIterations != _iterations || storedParallelism != _parallelism)
        {
            return true;
        }

        return false;
    }

}
