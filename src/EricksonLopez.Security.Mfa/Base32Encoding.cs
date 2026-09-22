// Copyright © Erickson Lopez. MIT License.
using System;
using System.Text;

namespace EricksonLopez.Security.Mfa;

/// <summary>
/// Provides RFC 4648 Base32 encoding and decoding methods without padding for TOTP secret keys.
/// </summary>
public static class Base32Encoding
{
    private const string Base32Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    /// <summary>
    /// Encodes a byte array into a Base32 string.
    /// </summary>
    /// <param name="data">The raw bytes to encode.</param>
    /// <returns>The Base32 string representation.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="data"/> is <see langword="null"/></exception>
    public static string ToBase32String(byte[] data)
    {
        ArgumentNullException.ThrowIfNull(data);
        return ToBase32StringCore(data);
    }

    private static string ToBase32StringCore(byte[] data)
    {
        var sb = new StringBuilder();
        uint buffer = 0;
        int bitsLeft = 0;

        foreach (var b in data)
        {
            buffer = (buffer << 8) | b;
            bitsLeft += 8;
            while (bitsLeft > 4)
            {
                bitsLeft -= 5;
                sb.Append(Base32Chars[(int)((buffer / (1u << bitsLeft)) & 31)]);
            }
        }

        if (bitsLeft > 0)
        {
            sb.Append(Base32Chars[(int)((buffer << (5 - bitsLeft)) & 31)]);
        }

        return sb.ToString();
    }

    /// <summary>
    /// Decodes a Base32 string back into its original raw bytes.
    /// </summary>
    /// <param name="base32">The Base32 encoded string.</param>
    /// <returns>The decoded byte array.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="base32"/> is <see langword="null"/></exception>
    /// <exception cref="ArgumentException"><paramref name="base32"/> exceeds the maximum allowed length of 2048 characters</exception>
    /// <exception cref="FormatException"><paramref name="base32"/> contains an invalid Base32 character</exception>
    public static byte[] FromBase32String(string base32)
    {
        ArgumentNullException.ThrowIfNull(base32);
        // P3.3 (resolved): explicit length guard prevents DoS via oversized input.
        // 2048 Base32 chars encode 1280 bytes — sufficient for any TOTP secret or recovery code.
        if (base32.Length > 2048)
        {
            throw new ArgumentException(
                "Input exceeds the maximum allowed length of 2048 characters.",
                nameof(base32));
        }

        return FromBase32StringCore(base32);
    }

    private static byte[] FromBase32StringCore(string base32)
    {
        var cleanInput = base32.Trim().TrimEnd('=').ToUpperInvariant();
        if (cleanInput.Length == 0)
        {
            return Array.Empty<byte>();
        }

        var byteCount = cleanInput.Length * 5 / 8;
        var result = new byte[byteCount];
        uint buffer = 0;
        int bitsLeft = 0, index = 0;

        foreach (var c in cleanInput)
        {
            var charIndex = Base32Chars.IndexOf(c);
            if (charIndex < 0)
            {
                throw new FormatException($"Invalid Base32 character '{c}'.");
            }

            buffer = (buffer << 5) | (uint)charIndex;
            bitsLeft += 5;
            if (bitsLeft >= 8)
            {
                bitsLeft -= 8;
                result[index++] = (byte)(buffer / (1u << bitsLeft));
            }
        }

        int remainder = cleanInput.Length % 8;
        if (remainder is 1 or 3 or 6)
        {
            throw new FormatException($"Invalid Base32 string length '{cleanInput.Length}' (RFC 4648 prohibits unpadded quantum lengths mod 8 of 1, 3, or 6).");
        }

        if (bitsLeft > 0 && (buffer & ((1u << bitsLeft) - 1)) != 0)
        {
            throw new FormatException("Non-zero padding bits detected in Base32 string (RFC 4648 Section 3.5 violation).");
        }

        return result;
    }
}
