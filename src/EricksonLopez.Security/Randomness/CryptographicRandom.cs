// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Randomness;

using System;
using System.Security.Cryptography;
using EricksonLopez.Security.Abstractions.Randomness;

/// <summary>
/// Provides a thread-safe implementation of <see cref="ICryptographicRandomNumberGenerator"/>
/// utilizing the underlying operating system Cryptographically Secure Pseudo-Random Number Generator (CSPRNG).
/// </summary>
public sealed class CryptographicRandom : ICryptographicRandomNumberGenerator
{
    /// <summary>
    /// Initializes a new instance of the <see cref="CryptographicRandom"/> class.
    /// </summary>
    public CryptographicRandom()
    {
    }

    /// <summary>
    /// Gets the shared singleton instance of <see cref="CryptographicRandom"/>.
    /// </summary>
    public static readonly CryptographicRandom Shared = new();

    /// <inheritdoc />
    public void Fill(Span<byte> destination) => RandomNumberGenerator.Fill(destination);

    /// <inheritdoc />
    public int GetInt32(int fromInclusive, int toExclusive) => RandomNumberGenerator.GetInt32(fromInclusive, toExclusive);

    /// <inheritdoc />
    public byte[] GetBytes(int count)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(count);
        return RandomNumberGenerator.GetBytes(count);
    }

    /// <summary>
    /// Generates a cryptographically random URL-safe base64 string with the specified byte entropy.
    /// </summary>
    /// <param name="byteLength">The entropy byte count.</param>
    /// <returns>A URL-safe random string.</returns>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="byteLength"/> is less than or equal to zero</exception>
    /// <remarks>
    /// <strong>Memory Note (RNG-04):</strong> The returned <see langword="string"/> is a managed heap allocation.
    /// .NET strings are immutable and cannot be explicitly zeroed — the token material may remain in memory
    /// until the next garbage collection cycle. For callers where minimizing the secret exposure window is
    /// critical (e.g., session tokens, API secrets), prefer <see cref="TryGetUrlSafeString(Span{char}, int, out int)"/>,
    /// which writes directly into a caller-controlled <see cref="Span{T}"/> that can be zeroed after use.
    /// </remarks>
    public string GetUrlSafeString(int byteLength = 32)
    {
        if (byteLength <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(byteLength), byteLength, "Byte length must be greater than zero.");
        }

        // FINDING-CRIT-06 (resolved): zero the intermediate byte[] in a finally block so that raw
        // token entropy is not left in the heap after the string is created from it.
        var randomBytes = GetBytes(byteLength);
        try
        {
            return Convert.ToBase64String(randomBytes)
                .Replace('+', '-')
                .Replace('/', '_')
                .TrimEnd('=');
        }
        finally
        // Stryker disable once Block : Ephemeral buffer cleanup in finally
        {
            // Stryker disable once Statement : Defense-in-depth wiping of ephemeral entropy bytes in memory
            CryptographicOperations.ZeroMemory(randomBytes);
        }
    }

    /// <summary>
    /// Attempts to generate a cryptographically random URL-safe base64 string into the specified destination span.
    /// </summary>
    /// <param name="destination">The destination character span to receive the encoded string.</param>
    /// <param name="byteLength">The number of random entropy bytes to generate. Must be greater than zero.</param>
    /// <param name="charsWritten">When this method returns, contains the number of characters written to <paramref name="destination"/>.</param>
    /// <returns><see langword="true"/> if the characters were successfully written; otherwise, <see langword="false"/>.</returns>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="byteLength"/> is less than or equal to zero</exception>
    public bool TryGetUrlSafeString(Span<char> destination, int byteLength, out int charsWritten)
    {
        if (byteLength <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(byteLength), byteLength, "Byte length must be greater than zero.");
        }

        // Stryker disable once Conditional,Equality : Stack allocation threshold vs heap allocation for large buffers
        Span<byte> randomBytes = byteLength <= 256 ? stackalloc byte[byteLength] : new byte[byteLength];
        RandomNumberGenerator.Fill(randomBytes);

        try
        {
#if NET9_0_OR_GREATER
            if (!System.Buffers.Text.Base64Url.TryEncodeToChars(randomBytes, destination, out charsWritten))
            {
                charsWritten = 0;
                return false;
            }
            return true;
#else
            int base64Len = ((byteLength + 2) / 3) * 4;
            Span<char> base64Chars = base64Len <= 512 ? stackalloc char[base64Len] : new char[base64Len];
            if (!Convert.TryToBase64Chars(randomBytes, base64Chars, out int written))
            {
                charsWritten = 0;
                return false;
            }

            int actualLen = written;
            while (actualLen > 0 && base64Chars[actualLen - 1] == '=')
            {
                actualLen--;
            }

            if (destination.Length < actualLen)
            {
                charsWritten = 0;
                return false;
            }

            for (int i = 0; i < actualLen; i++)
            {
                char c = base64Chars[i];
                destination[i] = c switch
                {
                    '+' => '-',
                    '/' => '_',
                    _ => c
                };
            }

            charsWritten = actualLen;
            return true;
#endif
        }
        finally
        // Stryker disable once Block : Ephemeral buffer cleanup in finally
        {
            // Stryker disable once Statement : Defense-in-depth wiping of ephemeral entropy bytes in memory
            CryptographicOperations.ZeroMemory(randomBytes);
        }
    }

    /// <summary>
    /// Generates a cryptographically random lowercase hex string with the specified byte entropy.
    /// </summary>
    /// <param name="byteLength">The entropy byte count.</param>
    /// <returns>A hex-encoded random string.</returns>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="byteLength"/> is less than or equal to zero</exception>
    public string GetHexString(int byteLength = 32)
    {
        if (byteLength <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(byteLength), byteLength, "Byte length must be greater than zero.");
        }

        byte[] randomBytes = GetBytes(byteLength);
        try
        {
            return Convert.ToHexString(randomBytes).ToLowerInvariant();
        }
        finally
        // Stryker disable once Block : Ephemeral buffer cleanup in finally
        {
            // Stryker disable once Statement : Defense-in-depth wiping of ephemeral entropy bytes in memory
            CryptographicOperations.ZeroMemory(randomBytes);
        }
    }
}
