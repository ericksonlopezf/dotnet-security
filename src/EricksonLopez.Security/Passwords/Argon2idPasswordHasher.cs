// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Passwords;

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Security.Cryptography;
using EricksonLopez.Security.Abstractions.Passwords;
using EricksonLopez.Security.Diagnostics;
using Konscious.Security.Cryptography;
using System.Text;

/// <summary>
/// Provides password hashing that produces and verifies hashes encoded in the Argon2id modular crypt format
/// (<c>$argon2id$v=19$m=&lt;mem&gt;,t=&lt;iters&gt;,p=&lt;parallelism&gt;$&lt;salt&gt;$&lt;hash&gt;</c>).
/// </summary>
public sealed class Argon2idPasswordHasher : IPasswordHasher
{
    private const string ModularCryptPrefix = "$argon2id$";
    private readonly int _memorySizeKb;
    private readonly int _iterations;
    private readonly int _parallelism;
    private readonly int _saltSizeBytes;

    /// <summary>
    /// Gets the default singleton instance configured with 64 MB memory, 3 time-cost iterations, and 4 parallelism lanes.
    /// </summary>
    public static readonly Argon2idPasswordHasher Default = new();

    /// <inheritdoc />
    public PasswordHashAlgorithm Algorithm => PasswordHashAlgorithm.Argon2id;

    /// <summary>
    /// Gets a value indicating whether the underlying key derivation function is memory-hard.
    /// </summary>
    public static bool IsMemoryHard => true;

    /// <summary>
    /// Gets the cryptographic substrate name backing this hasher.
    /// </summary>
    public static string SubstrateDescription => "Argon2id (RFC 9106)";

    /// <summary>Minimum time-cost iterations parameter accepted in verification.</summary>
    public const int MinAllowedTimeCost = 1;

    /// <summary>Maximum time-cost iterations parameter accepted in verification.</summary>
    public const int MaxAllowedTimeCost = 10;

    /// <summary>Minimum memory-cost parameter (in KiB) accepted in verification (1 MiB).</summary>
    public const int MinAllowedMemoryCost = 1024;

    /// <summary>Maximum memory-cost parameter (in KiB) accepted in verification (64 MiB) to prevent memory exhaustion DoS.</summary>
    public const int MaxAllowedMemoryCost = 65536;

    /// <summary>Minimum degree of parallelism accepted in verification.</summary>
    public const int MinAllowedParallelism = 1;

    /// <summary>Maximum degree of parallelism accepted in verification.</summary>
    public const int MaxAllowedParallelism = 16;

    /// <summary>
    /// Initializes a new instance of the <see cref="Argon2idPasswordHasher"/> class with the specified cost parameters.
    /// </summary>
    /// <param name="memorySizeKb">The memory cost in kibibytes (KiB). Must be between 1024 and 65536.</param>
    /// <param name="iterations">The time cost in iterations. Must be between 1 and 10.</param>
    /// <param name="parallelism">The degree of parallelism. Must be between 1 and 16.</param>
    /// <param name="saltSizeBytes">The size of the random salt in bytes. Must be between 8 and 64.</param>
    /// <exception cref="ArgumentOutOfRangeException">Any parameter is outside its permitted range</exception>
    public Argon2idPasswordHasher(
        int memorySizeKb = 65536,
        int iterations = 3,
        int parallelism = 4,
        int saltSizeBytes = 16)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(iterations, MinAllowedTimeCost);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(iterations, MaxAllowedTimeCost);
        ArgumentOutOfRangeException.ThrowIfLessThan(memorySizeKb, MinAllowedMemoryCost);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(memorySizeKb, MaxAllowedMemoryCost);
        ArgumentOutOfRangeException.ThrowIfLessThan(parallelism, MinAllowedParallelism);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(parallelism, MaxAllowedParallelism);
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
        activity?.SetTag(SecurityActivitySource.TagHashAlgorithm, "argon2id");

        var sw = Stopwatch.StartNew();

        // Generate random salt
        byte[] salt = new byte[_saltSizeBytes];
        RandomNumberGenerator.Fill(salt);

        // Normalize Unicode representation to Form C per NIST SP 800-63B recommendations
        string normalizedPassword = password.ToString().Normalize(NormalizationForm.FormC);
        int byteCount = Encoding.UTF8.GetByteCount(normalizedPassword);
        byte[] passwordBytes = new byte[byteCount];
        Encoding.UTF8.GetBytes(normalizedPassword, passwordBytes);

        try
        {
            using var argon2 = new Argon2id(passwordBytes)
            {
                Salt = salt,
                DegreeOfParallelism = _parallelism,
                Iterations = _iterations,
                MemorySize = _memorySizeKb
            };

            byte[] derivedKey = argon2.GetBytes(32);
            string hashBase64;
            try
            {
                hashBase64 = Convert.ToBase64String(derivedKey);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(derivedKey);
            }

            string saltBase64 = Convert.ToBase64String(salt);

            sw.Stop();
            // Assuming we still record metrics
            SecurityMeter.Pbkdf2HashingDurationMs.Record(sw.Elapsed.TotalMilliseconds);
            activity?.SetTag(SecurityActivitySource.TagResult, "success");

            return $"{ModularCryptPrefix}v=19$m={_memorySizeKb},t={_iterations},p={_parallelism}${saltBase64}${hashBase64}";
        }
        finally
        {
            CryptographicOperations.ZeroMemory(passwordBytes);
        }
    }

    /// <inheritdoc />
    public PasswordVerificationResult VerifyPassword(ReadOnlySpan<char> password, string hashedPassword)
    {
        using var activity = SecurityActivitySource.Instance
            .StartActivity(SecurityActivitySource.VerifyPasswordOperation, ActivityKind.Internal);
        activity?.SetTag(SecurityActivitySource.TagHashAlgorithm, "argon2id");

        var result = VerifyPasswordCore(password, hashedPassword);
        string resultTag = result switch
        {
            PasswordVerificationResult.Success => "success",
            PasswordVerificationResult.SuccessRehashNeeded => "rehash_needed",
            _ => "failure"
        };

        SecurityMeter.PasswordVerificationsTotal.Add(1,
            new KeyValuePair<string, object?>(SecurityActivitySource.TagResult, resultTag),
            new KeyValuePair<string, object?>(SecurityActivitySource.TagHashAlgorithm, "argon2id"));
        activity?.SetTag(SecurityActivitySource.TagResult, resultTag);

        return result;
    }

    private PasswordVerificationResult VerifyPasswordCore(ReadOnlySpan<char> password, string hashedPassword)
    {
        if (string.IsNullOrWhiteSpace(hashedPassword) || password.Length > 256 || hashedPassword.Length > 512 || !hashedPassword.StartsWith(ModularCryptPrefix, StringComparison.Ordinal))
        {
            return PasswordVerificationResult.Failed;
        }

        var parts = hashedPassword.Split('$', StringSplitOptions.RemoveEmptyEntries);
        // parts[0]: "argon2id", parts[1]: "v=19", parts[2]: "m=65536,t=3,p=4", parts[3]: "<salt>", parts[4]: "<hash>"
        if (parts.Length != 5)
        {
            return PasswordVerificationResult.Failed;
        }

        int storedIterations = -1;
        int storedMemory = -1;
        int storedParallelism = -1;
        var paramPairs = parts[2].Split(',', StringSplitOptions.RemoveEmptyEntries);
        foreach (var pair in paramPairs)
        {
            if (pair.StartsWith("t=", StringComparison.Ordinal))
            {
                if (int.TryParse(pair.AsSpan(2), out int parsedT)) storedIterations = parsedT;
            }
            else if (pair.StartsWith("m=", StringComparison.Ordinal))
            {
                if (int.TryParse(pair.AsSpan(2), out int parsedM)) storedMemory = parsedM;
            }
            else if (pair.StartsWith("p=", StringComparison.Ordinal))
            {
                if (int.TryParse(pair.AsSpan(2), out int parsedP)) storedParallelism = parsedP;
            }
        }

        if (storedIterations < MinAllowedTimeCost || storedIterations > MaxAllowedTimeCost ||
            storedMemory < MinAllowedMemoryCost || storedMemory > MaxAllowedMemoryCost ||
            storedParallelism < MinAllowedParallelism || storedParallelism > MaxAllowedParallelism)
        {
            return PasswordVerificationResult.Failed;
        }

        if (parts[3].Length < 8 || parts[3].Length > 128 || parts[4].Length < 16 || parts[4].Length > 128)
        {
            return PasswordVerificationResult.Failed;
        }

        byte[] salt;
        byte[] expectedHash;
        try
        {
            salt = Convert.FromBase64String(parts[3]);
            expectedHash = Convert.FromBase64String(parts[4]);
        }
        catch (FormatException)
        {
            return PasswordVerificationResult.Failed;
        }

        // Normalize Unicode representation to Form C per NIST SP 800-63B recommendations
        string normalizedPassword = password.ToString().Normalize(NormalizationForm.FormC);
        int byteCount = Encoding.UTF8.GetByteCount(normalizedPassword);
        byte[] passwordBytes = new byte[byteCount];
        Encoding.UTF8.GetBytes(normalizedPassword, passwordBytes);
        try
        {
            using var argon2 = new Argon2id(passwordBytes)
            {
                Salt = salt,
                DegreeOfParallelism = storedParallelism,
                Iterations = storedIterations,
                MemorySize = storedMemory
            };

            byte[] computedHash = argon2.GetBytes(expectedHash.Length);
            try
            {
                bool matches = CryptographicOperations.FixedTimeEquals(computedHash, expectedHash);
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
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(passwordBytes);
        }
    }

    /// <inheritdoc />
    public bool NeedsRehash(string hashedPassword)
    {
        var parts = hashedPassword.Split('$', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length != 5) return true;

        int storedIterations = -1;
        int storedMemory = -1;
        int storedParallelism = -1;
        var paramPairs = parts[2].Split(',', StringSplitOptions.RemoveEmptyEntries);
        foreach (var pair in paramPairs)
        {
            if (pair.StartsWith("t=", StringComparison.Ordinal))
            {
                if (int.TryParse(pair.AsSpan(2), out int parsedT)) storedIterations = parsedT;
            }
            else if (pair.StartsWith("m=", StringComparison.Ordinal))
            {
                if (int.TryParse(pair.AsSpan(2), out int parsedM)) storedMemory = parsedM;
            }
            else if (pair.StartsWith("p=", StringComparison.Ordinal))
            {
                if (int.TryParse(pair.AsSpan(2), out int parsedP)) storedParallelism = parsedP;
            }
        }

        if (storedIterations != _iterations || storedMemory != _memorySizeKb || storedParallelism != _parallelism)
        {
            return true;
        }
        return false;
    }
}
