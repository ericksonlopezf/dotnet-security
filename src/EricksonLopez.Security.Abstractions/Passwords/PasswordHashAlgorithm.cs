// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Abstractions.Passwords;

/// <summary>
/// Specifies the password hashing algorithm for storing authentication credentials securely.
/// </summary>
public enum PasswordHashAlgorithm : byte
{
    /// <summary>
    /// Specifies Password-Based Key Derivation Function 2 (PBKDF2) using HMAC-SHA512 per RFC 8018 and OWASP recommendations.
    /// Recommended minimum iterations: 600,000+ (or 210,000 for SHA512).
    /// </summary>
    Pbkdf2HmacSha512 = 1,

    /// <summary>
    /// Specifies the modular crypt format identifier for the <c>$argon2id$</c> hash prefix (RFC 9106 MCF).
    /// </summary>
    /// <remarks>
    /// <para>
    /// <strong>Cryptographic Substrate</strong>: Hashes carrying this prefix are derived via genuine
    /// memory-hard <strong>Argon2id (RFC 9106)</strong> using <c>Konscious.Security.Cryptography.Argon2id</c>.
    /// The default parameters enforce 64 MiB memory cost, 3 time-cost iterations, and 4 parallelism lanes,
    /// providing robust resistance against GPU and ASIC offline brute-force attacks (see ADR-031).
    /// </para>
    /// </remarks>
    Argon2id = 2,

    /// <summary>
    /// Specifies the Openwall or standard BCrypt adaptive password hashing algorithm.
    /// </summary>
    BCrypt = 3
}
