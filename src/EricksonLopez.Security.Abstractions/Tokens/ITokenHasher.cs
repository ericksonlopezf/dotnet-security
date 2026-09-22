// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Abstractions.Tokens;

using System;

/// <summary>
/// Defines contracts for deterministic and salted cryptographic hashing of security tokens.
/// </summary>
public interface ITokenHasher
{
    /// <summary>
    /// Computes a deterministic cryptographic hash of the token suitable for indexed database lookups.
    /// </summary>
    /// <param name="token">The token character span to hash</param>
    /// <returns>A hex-encoded or base64-encoded hash digest of the token.</returns>
    string HashToken(ReadOnlySpan<char> token);

    /// <summary>
    /// Verifies a candidate token against an expected hash using constant-time evaluation.
    /// </summary>
    /// <param name="token">The candidate token character span to verify</param>
    /// <param name="expectedHash">The expected token hash to compare against</param>
    /// <returns><see langword="true"/> if the candidate token matches the expected hash; otherwise, <see langword="false"/>.</returns>
    bool VerifyToken(ReadOnlySpan<char> token, string expectedHash);
}
