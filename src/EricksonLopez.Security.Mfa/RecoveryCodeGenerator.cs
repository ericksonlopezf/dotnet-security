// Copyright © Erickson Lopez. MIT License.
using System;
using System.Security.Cryptography;
using System.Text;

namespace EricksonLopez.Security.Mfa;

/// <summary>
/// Generates cryptographically secure, alphanumeric emergency recovery backup codes.
/// </summary>
/// <remarks>
/// <para>
/// Recovery codes returned by <see cref="GenerateCodes"/> are in <em>plaintext</em> and must
/// be hashed before storage. Use <see cref="HashCode(string)"/> to obtain the hash for persistence
/// and <see cref="VerifyCode(string, string)"/> to verify a user-supplied recovery code against
/// the stored hash in constant time, preventing timing oracles.
/// </para>
/// <para>
/// <strong>Recommended flow</strong>:
/// <list type="number">
///   <item>Call <see cref="GenerateCodes"/> and display all codes to the user once.</item>
///   <item>For each code, call <see cref="HashCode"/> and store the resulting hash.</item>
///   <item>When a user presents a recovery code, call <see cref="VerifyCode"/> against each stored hash.</item>
///   <item>Delete (mark as used) the matched hash immediately after successful verification.</item>
/// </list>
/// </para>
/// </remarks>
public sealed class RecoveryCodeGenerator : IRecoveryCodeGenerator
{
    private const string CodeChars = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"; // Base32 unambiguous set

    /// <summary>
    /// Generates a collection of unique, formatted recovery codes.
    /// </summary>
    /// <param name="count">The number of recovery codes to generate (default is 10).</param>
    /// <param name="codeLength">The length of each code before formatting (default is 10).</param>
    /// <returns>An array of formatted recovery codes (e.g. <c>XXXX-XXXX-XX</c>).</returns>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="count"/> is less than or equal to zero, or <paramref name="codeLength"/> is less than 8</exception>
    public string[] GenerateCodes(int count = 10, int codeLength = 10)
    {
        if (count <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(count), "Count must be greater than zero.");
        }

        if (codeLength < 8)
        {
            throw new ArgumentOutOfRangeException(nameof(codeLength), "Code length must be at least 8 characters.");
        }

        var codes = new string[count];
        var bytes = new byte[codeLength];

        for (var i = 0; i < count; i++)
        {
            RandomNumberGenerator.Fill(bytes);
            var sb = new StringBuilder();

            for (var j = 0; j < codeLength; j++)
            {
                if (j > 0 && j % 4 == 0)
                {
                    sb.Append('-');
                }

                var charIndex = bytes[j] % CodeChars.Length;
                sb.Append(CodeChars[charIndex]);
            }

            codes[i] = sb.ToString();
        }

        return codes;
    }

    /// <summary>
    /// Computes a SHA-256 hash of the recovery code for secure storage.
    /// Store this hash instead of the plaintext code.
    /// </summary>
    /// <param name="plaintextCode">The plaintext recovery code to hash.</param>
    /// <returns>A lowercase hex string of the SHA-256 hash (64 characters).</returns>
    /// <exception cref="ArgumentException"><paramref name="plaintextCode"/> is <see langword="null"/> or whitespace</exception>
    /// <remarks>
    /// AUTH-010 fix: recovery codes must be stored as hashes, not plaintext.
    /// SHA-256 is appropriate here because recovery codes are high-entropy random values
    /// (not passwords), so a fast hash without salt is sufficient — the entropy of the code
    /// itself provides the necessary brute-force resistance.
    /// </remarks>
    public static string HashCode(string plaintextCode)
    {
        if (string.IsNullOrWhiteSpace(plaintextCode))
        {
            throw new ArgumentException("Recovery code cannot be null or whitespace.", nameof(plaintextCode));
        }

        // Strip formatting dashes and normalize to uppercase for consistent hashing
        var normalizedCode = plaintextCode.Replace("-", string.Empty, StringComparison.Ordinal)
                                          .ToUpperInvariant();

        var codeBytes = Encoding.UTF8.GetBytes(normalizedCode);
        Span<byte> hash = stackalloc byte[32];
        SHA256.HashData(codeBytes, hash);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    /// <summary>
    /// Verifies a user-supplied recovery code against a stored hash in constant time,
    /// preventing timing oracle attacks.
    /// </summary>
    /// <param name="plaintextCode">The recovery code entered by the user.</param>
    /// <param name="storedHash">The SHA-256 hash previously stored via <see cref="HashCode"/>.</param>
    /// <returns><see langword="true"/> if the code matches the stored hash; <see langword="false"/> otherwise.</returns>
    /// <remarks>
    /// AUTH-010 fix: uses <see cref="CryptographicOperations.FixedTimeEquals"/> to prevent
    /// timing-based enumeration of which recovery codes are valid.
    /// </remarks>
    public static bool VerifyCode(string plaintextCode, string storedHash)
    {
        if (string.IsNullOrWhiteSpace(plaintextCode) || string.IsNullOrWhiteSpace(storedHash))
        {
            return false;
        }

        var actualHash = HashCode(plaintextCode);

        // Constant-time comparison to prevent timing oracle attacks
        return CryptographicOperations.FixedTimeEquals(
            Encoding.UTF8.GetBytes(actualHash),
            Encoding.UTF8.GetBytes(storedHash));
    }
}
