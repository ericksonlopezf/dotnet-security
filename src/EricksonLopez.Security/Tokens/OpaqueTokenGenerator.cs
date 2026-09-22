// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Tokens;

using System;
using System.Security.Cryptography;
using EricksonLopez.Security.Abstractions.Primitives;
using EricksonLopez.Security.Abstractions.Tokens;
using EricksonLopez.Security.Randomness;

/// <summary>
/// Provides an implementation of <see cref="ITokenGenerator"/> generating cryptographically
/// strong opaque security tokens, session identifiers, and verification codes.
/// </summary>
public sealed class OpaqueTokenGenerator : ITokenGenerator
{
    private const string NumericDigits = "0123456789";

    /// <summary>
    /// Initializes a new instance of the <see cref="OpaqueTokenGenerator"/> class.
    /// </summary>
    public OpaqueTokenGenerator()
    {
    }

    /// <summary>Gets the shared singleton instance of <see cref="OpaqueTokenGenerator"/>.</summary>
    public static readonly OpaqueTokenGenerator Shared = new();

    /// <inheritdoc />
    public OpaqueToken GenerateToken(int byteLength = 32)
    {
        var tokenString = GenerateUrlSafeToken(byteLength);
        return new OpaqueToken(tokenString);
    }

    /// <inheritdoc />
    public string GenerateUrlSafeToken(int byteLength = 32) => CryptographicRandom.Shared.GetUrlSafeString(byteLength);

    /// <inheritdoc />
    public bool TryGenerateUrlSafeToken(Span<char> destination, int byteLength, out int charsWritten) =>
        CryptographicRandom.Shared.TryGetUrlSafeString(destination, byteLength, out charsWritten);

    /// <inheritdoc />
    public string GenerateHexToken(int byteLength = 32) => CryptographicRandom.Shared.GetHexString(byteLength);

    /// <inheritdoc />
    public string GenerateNumericCode(int digits = 6)
    {
        if (digits <= 0 || digits > 16)
        {
            throw new ArgumentOutOfRangeException(nameof(digits), digits, "Digits must be between 1 and 16.");
        }

        Span<char> code = stackalloc char[digits];
        for (int i = 0; i < digits; i++)
        {
            code[i] = NumericDigits[RandomNumberGenerator.GetInt32(0, NumericDigits.Length)];
        }

        return new string(code);
    }
}
