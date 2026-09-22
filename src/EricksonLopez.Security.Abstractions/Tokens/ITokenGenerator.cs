// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Abstractions.Tokens;

using EricksonLopez.Security.Abstractions.Primitives;

/// <summary>
/// Defines contracts for generating high-entropy, cryptographically random opaque tokens.
/// </summary>
public interface ITokenGenerator
{
    /// <summary>
    /// Generates a cryptographically secure opaque token with the specified entropy byte length.
    /// </summary>
    /// <param name="byteLength">The number of random bytes to generate, defaulting to 32 bytes</param>
    /// <returns>A new <see cref="OpaqueToken"/> containing the generated random bytes.</returns>
    OpaqueToken GenerateToken(int byteLength = 32);

    /// <summary>
    /// Generates a cryptographically secure URL-safe base64-encoded token string.
    /// </summary>
    /// <param name="byteLength">The number of random bytes to generate, defaulting to 32 bytes</param>
    /// <returns>A URL-safe token string.</returns>
    string GenerateUrlSafeToken(int byteLength = 32);

    /// <summary>
    /// Generates a cryptographically secure hex-encoded token string.
    /// </summary>
    /// <param name="byteLength">The number of random bytes to generate, defaulting to 32 bytes</param>
    /// <returns>A lowercase hex-encoded token string.</returns>
    string GenerateHexToken(int byteLength = 32);

    /// <summary>
    /// Generates a cryptographically secure numeric code of the specified digit length.
    /// </summary>
    /// <param name="digits">The number of digits in the generated code, defaulting to 6</param>
    /// <returns>A numeric code string of the specified length.</returns>
    string GenerateNumericCode(int digits = 6);

    /// <summary>
    /// Attempts to generate a cryptographically secure URL-safe token into the specified destination span.
    /// </summary>
    /// <param name="destination">The destination span for the generated token characters.</param>
    /// <param name="byteLength">The number of random bytes to generate, defaulting to 32 bytes.</param>
    /// <param name="charsWritten">The number of characters written to the destination span.</param>
    /// <returns><see langword="true"/> if the token was successfully generated; otherwise, <see langword="false"/>.</returns>
    bool TryGenerateUrlSafeToken(Span<char> destination, int byteLength, out int charsWritten)
    {
        var token = GenerateUrlSafeToken(byteLength);
        if (destination.Length < token.Length)
        {
            charsWritten = 0;
            return false;
        }
        token.AsSpan().CopyTo(destination);
        charsWritten = token.Length;
        return true;
    }
}
