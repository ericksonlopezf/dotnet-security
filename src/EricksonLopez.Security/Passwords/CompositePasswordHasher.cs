// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Passwords;

using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using EricksonLopez.Security.Abstractions.Passwords;

/// <summary>
/// Provides a composite password hasher and verifier that transparently inspects modular crypt hash prefixes,
/// delegates verification to the matching algorithm engine, and signals when a legacy hash requires
/// transparent rehashing to the active primary policy upon successful authentication.
/// </summary>
public sealed class CompositePasswordHasher : IPasswordHasher, ISimplePasswordHasher
{
    private readonly IPasswordHasher _primaryHasher;
    private readonly Dictionary<string, IPasswordHasher> _registeredHashers = new(StringComparer.OrdinalIgnoreCase);

    /// <inheritdoc />
    public PasswordHashAlgorithm Algorithm => _primaryHasher.Algorithm;

    /// <summary>
    /// Initializes a new instance of the <see cref="CompositePasswordHasher"/> class.
    /// </summary>
    /// <param name="primaryHasher">The primary password hasher for new hash generation.</param>
    /// <param name="additionalHashers">The optional collection of legacy or additional password hashers.</param>
    public CompositePasswordHasher(
        IPasswordHasher? primaryHasher = null,
        IEnumerable<IPasswordHasher>? additionalHashers = null)
    {
        _primaryHasher = primaryHasher ?? Pbkdf2PasswordHasher.Default;
        RegisterHasher(_primaryHasher);

        if (additionalHashers is not null)
        {
            foreach (var hasher in additionalHashers)
            {
                RegisterHasher(hasher);
            }
        }

        // Ensure default fallbacks are registered
        if (!_registeredHashers.ContainsKey("$pbkdf2-sha512$"))
        {
            RegisterHasher(Pbkdf2PasswordHasher.Default);
        }

        if (!_registeredHashers.ContainsKey("$argon2id$"))
        {
            RegisterHasher(Argon2idPasswordHasher.Default);
        }

        // Stryker disable once String : Hasher registration key
        if (!_registeredHashers.ContainsKey("$legacy-pbkdf2$"))
        {
            RegisterHasher(LegacyPbkdf2PasswordHasher.Default);
        }
    }

    private void RegisterHasher(IPasswordHasher hasher)
    {
        if (hasher.Algorithm == PasswordHashAlgorithm.BCrypt)
        {
            _registeredHashers["$2a$"] = hasher;
            _registeredHashers["$2b$"] = hasher;
            _registeredHashers["$2y$"] = hasher;
        }
        else if (hasher is LegacyPbkdf2PasswordHasher)
        {
            _registeredHashers["$legacy-pbkdf2$"] = hasher;
        }
        else if (hasher is Argon2idPasswordHasher)
        {
            _registeredHashers["$argon2id$"] = hasher;
        }
        else
        {
            var prefix = hasher.Algorithm switch
            {
                PasswordHashAlgorithm.Pbkdf2HmacSha512 => "$pbkdf2-sha512$",
                _ => $"${hasher.Algorithm.ToString().ToLowerInvariant()}$"
            };

            _registeredHashers[prefix] = hasher;
        }
    }

    /// <inheritdoc />
    public string HashPassword(ReadOnlySpan<char> password) => _primaryHasher.HashPassword(password);

    /// <inheritdoc />
    public PasswordVerificationResult VerifyPassword(ReadOnlySpan<char> password, string hashedPassword)
    {
        // Stryker disable once Equality,Logical : DoS defense-in-depth length bounds prior to format parsing
        if (string.IsNullOrWhiteSpace(hashedPassword) || password.Length > 256 || hashedPassword.Length > 512)
        {
            return PasswordVerificationResult.Failed;
        }

        // Normalize PHP / BSD BCrypt prefixes ($2y$, $2b$) to $2a$ for standardized verification
        string lookupHash = hashedPassword;
        if (hashedPassword.StartsWith("$2y$", StringComparison.OrdinalIgnoreCase) ||
            hashedPassword.StartsWith("$2b$", StringComparison.OrdinalIgnoreCase))
        {
            lookupHash = string.Concat("$2a$", hashedPassword.AsSpan(4));
        }

        // Cross-tier support for PBKDF2.V1 format (EricksonLopez.Security.Cryptography)
        if (hashedPassword.StartsWith("PBKDF2.V1$", StringComparison.OrdinalIgnoreCase))
        {
            var parts = hashedPassword.Split('$');
            if (parts.Length == 4 && int.TryParse(parts[1], System.Globalization.CultureInfo.InvariantCulture, out var iters))
            {
                // Stryker disable once Equality,Logical,Block : Cross-tier bounds validation
                if (iters is < 1000 or > 600_000 || parts[2].Length is < 8 or > 128 || parts[3].Length is < 16 or > 128)
                {
                    return PasswordVerificationResult.Failed;
                }

                try
                {
                    var salt = Convert.FromBase64String(parts[2]);
                    var expectedHash = Convert.FromBase64String(parts[3]);
                    // Stryker disable once Equality,Block : Hash length bounds
                    if (expectedHash.Length is < 16 or > 128)
                    {
                        return PasswordVerificationResult.Failed;
                    }

                    Span<byte> derived = stackalloc byte[expectedHash.Length];
                    try
                    {
                        Rfc2898DeriveBytes.Pbkdf2(password, salt, derived, iters, HashAlgorithmName.SHA512);

                        if (CryptographicOperations.FixedTimeEquals(derived, expectedHash))
                        {
                            return PasswordVerificationResult.SuccessRehashNeeded;
                        }
                    }
                    finally
                    // Stryker disable once Block : Ephemeral buffer cleanup in finally
                    {
                        // Stryker disable once Statement : Wiping ephemeral stackalloc buffers in finally block
                        CryptographicOperations.ZeroMemory(derived);
                    }
                }
                // Stryker disable once Block : Equivalent to falling through to failure return on line 154
                catch (Exception ex) when (ex is FormatException or ArgumentException or CryptographicException)
                {
                    return PasswordVerificationResult.Failed;
                }
            }

            return PasswordVerificationResult.Failed;
        }

        // Find matching hasher by prefix
        foreach (var (prefix, hasher) in _registeredHashers)
        {
            if (hashedPassword.StartsWith(prefix, StringComparison.OrdinalIgnoreCase) ||
                lookupHash.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            {
                var targetHash = lookupHash;
                var result = hasher.VerifyPassword(password, targetHash);
                // Stryker disable once Logical : Fallback check condition
                if (result == PasswordVerificationResult.Failed && string.Equals(prefix, "$argon2id$", StringComparison.OrdinalIgnoreCase))
                {
                    // If real Argon2id verification failed, check if this is an old v1 legacy-spoofed hash
                    var legacyResult = LegacyPbkdf2PasswordHasher.Default.VerifyPassword(password, targetHash);
                    if (legacyResult != PasswordVerificationResult.Failed)
                    {
                        return PasswordVerificationResult.SuccessRehashNeeded;
                    }
                }

                if (result == PasswordVerificationResult.Failed)
                {
                    return PasswordVerificationResult.Failed;
                }

                // If verified by a non-primary hasher or primary indicates rehash is needed
                if (!ReferenceEquals(hasher, _primaryHasher) || result == PasswordVerificationResult.SuccessRehashNeeded)
                {
                    return PasswordVerificationResult.SuccessRehashNeeded;
                }

                return PasswordVerificationResult.Success;
            }
        }

        // Fallback to primary hasher
        return _primaryHasher.VerifyPassword(password, hashedPassword);
    }

    /// <inheritdoc />
    /// <remarks>
    /// <para>
    /// <strong>Migration promotion</strong>: Delegates directly to the primary hasher's
    /// <c>NeedsRehash</c> implementation. If the stored hash was produced by a different algorithm
    /// than the primary (e.g., the hash has an <c>$argon2id$</c> prefix but the primary hasher is
    /// <c>Pbkdf2PasswordHasher</c>), the primary hasher will not recognise the prefix and will
    /// return <see langword="true"/>. This means <strong>all non-primary-algorithm hashes always
    /// report <c>NeedsRehash = true</c></strong>, intentionally promoting rehash to the current
    /// primary algorithm on the next successful authentication.
    /// </para>
    /// <para>
    /// If you need to check rehash eligibility for the algorithm that <em>produced</em> the hash,
    /// use <see cref="VerifyPassword"/> instead — <c>SuccessRehashNeeded</c> is returned whenever
    /// the matched hasher is not the primary or indicates its own cost parameters are outdated.
    /// </para>
    /// </remarks>
    public bool NeedsRehash(string hashedPassword)
    {
        if (string.IsNullOrWhiteSpace(hashedPassword))
        {
            return true;
        }

        return _primaryHasher.NeedsRehash(hashedPassword);
    }

    /// <inheritdoc />
    string ISimplePasswordHasher.Hash(string password) => HashPassword(password.AsSpan());

    /// <inheritdoc />
    bool ISimplePasswordHasher.Verify(string password, string hash)
    {
        var result = VerifyPassword(password.AsSpan(), hash);
        return result == PasswordVerificationResult.Success || result == PasswordVerificationResult.SuccessRehashNeeded;
    }

    /// <inheritdoc />
    bool ISimplePasswordHasher.NeedsRehash(string hash) => NeedsRehash(hash);
}
