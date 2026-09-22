// Copyright © Erickson Lopez. MIT License.
using System;

namespace EricksonLopez.Security.Mfa;

/// <summary>
/// Defines RFC 6238 Time-Based One-Time Password (TOTP) generation and verification operations.
/// </summary>
public interface ITotpService
{
    /// <summary>
    /// Generates a new cryptographically random Base32 encoded secret key.
    /// </summary>
    /// <param name="byteLength">The key length in bytes (default is 20 bytes = 160 bits, recommended by RFC 4226).</param>
    /// <returns>A raw cryptographically random byte array. Consumers should format this securely or store it in an encrypted buffer.</returns>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="byteLength"/> is less than 16 (128 bits minimum)</exception>
    byte[] GenerateSecretKey(int byteLength = 20);

    /// <summary>
    /// Generates the setup information (including <c>otpauth://</c> URI) for enrolling a user in an authenticator app.
    /// </summary>
    /// <param name="issuer">The company or application name (e.g. "EricksonLopez").</param>
    /// <param name="accountName">The user's email or username.</param>
    /// <param name="secretKey">Optional existing secret key. If null, a new key is generated.</param>
    /// <param name="options">Optional TOTP options.</param>
    /// <returns>A setup info record containing the key and URI.</returns>
    TotpSetupInfo GenerateSetupInfo(
        string issuer,
        string accountName,
        string? secretKey = null,
        TotpOptions? options = null);

    /// <summary>
    /// Computes the active TOTP code for a specific timestamp.
    /// </summary>
    /// <param name="secretKey">The Base32 encoded secret key.</param>
    /// <param name="timestamp">The timestamp for which to compute the code.</param>
    /// <param name="options">Optional TOTP options.</param>
    /// <returns>The calculated numeric code string (e.g. "123456").</returns>
    string ComputeCode(string secretKey, DateTimeOffset timestamp, TotpOptions? options = null);

    /// <summary>
    /// Determines whether the provided code matches the secret key within the allowable time drift window.
    /// </summary>
    /// <param name="secretKey">The Base32 encoded secret key.</param>
    /// <param name="code">The code entered by the user.</param>
    /// <param name="timestamp">Optional timestamp to verify against (default is current time).</param>
    /// <param name="options">Optional TOTP options.</param>
    /// <returns><see langword="true"/> if the code is valid; otherwise, <see langword="false"/>.</returns>
    bool VerifyCode(
        string secretKey,
        string code,
        DateTimeOffset? timestamp = null,
        TotpOptions? options = null);
}
