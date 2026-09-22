// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Cryptography;

using System;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using EricksonLopez.Result;
using EricksonLopez.Security.Abstractions.Cryptography;
using EricksonLopez.Security.Abstractions.Errors;

/// <summary>
/// Provides an authenticated encryption engine implementing ChaCha20-Poly1305 (<see cref="AeadAlgorithm.ChaCha20Poly1305"/>).
/// Utilizes a 256-bit key, 96-bit nonce, and 128-bit authentication tag.
/// </summary>
public sealed class ChaCha20Poly1305EncryptionEngine : IAuthenticatedEncryptionEngine
{
    private const int ExpectedKeyBytes = 32;   // 256 bits
    private const int ExpectedNonceBytes = 12; // 96 bits
    private const int ExpectedTagBytes = 16;   // 128 bits

    /// <summary>
    /// Gets the maximum allowed payload size in bytes (256 MiB) enforced by the engine
    /// on Encrypt and Decrypt operations to prevent asymmetric memory exhaustion DoS attacks (GAP-01 / REM-001).
    /// </summary>
    public const int MaxRecommendedPayloadBytes = 256 * 1024 * 1024; // 256 MiB

    /// <summary>
    /// Gets the shared singleton instance of <see cref="ChaCha20Poly1305EncryptionEngine"/>.
    /// </summary>
    public static readonly ChaCha20Poly1305EncryptionEngine Shared = new();

    /// <inheritdoc />
    public AeadAlgorithm Algorithm => AeadAlgorithm.ChaCha20Poly1305;

    /// <inheritdoc />
    public int KeySizeBytes => ExpectedKeyBytes;

    /// <inheritdoc />
    public int NonceSizeBytes => ExpectedNonceBytes;

    /// <inheritdoc />
    public int TagSizeBytes => ExpectedTagBytes;

    /// <summary>
    /// Gets a value indicating whether ChaCha20-Poly1305 is supported on the current platform.
    /// </summary>
    public static bool IsSupported => ChaCha20Poly1305.IsSupported;

    /// <inheritdoc />
    public Result<EncryptedData> Encrypt(
        ReadOnlySpan<byte> plaintext,
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> associatedData = default)
    {
        if (!IsSupported)
        {
            return SecurityError.UnsupportedAlgorithm("ChaCha20Poly1305", "ChaCha20-Poly1305 is not supported on the current platform.");
        }

        if (key.Length != ExpectedKeyBytes)
        {
            return SecurityError.InvalidKey($"ChaCha20-Poly1305 requires a 32-byte key. Received {key.Length} bytes.");
        }

        if (plaintext.Length > MaxRecommendedPayloadBytes)
        {
            return SecurityError.PayloadTooLarge($"Plaintext payload size ({plaintext.Length} bytes) exceeds the maximum allowed payload size of {MaxRecommendedPayloadBytes} bytes.");
        }

        var nonceBytes = new byte[ExpectedNonceBytes];
        RandomNumberGenerator.Fill(nonceBytes);

        return EncryptCore(plaintext, key, nonceBytes, associatedData);
    }

    /// <inheritdoc />
    public Result Encrypt(
        ReadOnlySpan<byte> plaintext,
        ReadOnlySpan<byte> key,
        Span<byte> nonceDestination,
        Span<byte> ciphertextDestination,
        Span<byte> tagDestination,
        ReadOnlySpan<byte> associatedData = default)
    {
        if (!IsSupported)
        {
            return SecurityError.UnsupportedAlgorithm("ChaCha20Poly1305", "ChaCha20-Poly1305 is not supported on the current platform.");
        }

        if (key.Length != ExpectedKeyBytes)
        {
            return SecurityError.InvalidKey($"ChaCha20-Poly1305 requires a 32-byte key. Received {key.Length} bytes.");
        }

        if (plaintext.Length > MaxRecommendedPayloadBytes)
        {
            return SecurityError.PayloadTooLarge($"Plaintext payload size ({plaintext.Length} bytes) exceeds the maximum allowed payload size of {MaxRecommendedPayloadBytes} bytes.");
        }

        if (nonceDestination.Length < ExpectedNonceBytes)
        {
            return SecurityError.InvalidNonce($"ChaCha20-Poly1305 requires a 12-byte nonce buffer. Received {nonceDestination.Length} bytes.");
        }

        if (tagDestination.Length < ExpectedTagBytes)
        {
            return SecurityError.BufferTooSmall($"Tag destination buffer must be at least 16 bytes. Received {tagDestination.Length} bytes.");
        }

        if (ciphertextDestination.Length < plaintext.Length)
        {
            return SecurityError.BufferTooSmall($"Ciphertext destination buffer must be at least {plaintext.Length} bytes. Received {ciphertextDestination.Length} bytes.");
        }

        RandomNumberGenerator.Fill(nonceDestination[..ExpectedNonceBytes]);
        var nonce = nonceDestination[..ExpectedNonceBytes];

        return EncryptSpanCore(plaintext, key, nonce, ciphertextDestination, tagDestination, associatedData);
    }

    /// <inheritdoc />
    public Result Decrypt(
        ReadOnlySpan<byte> ciphertext,
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> tag,
        ReadOnlySpan<byte> associatedData,
        Span<byte> plaintextDestination,
        out int bytesWritten)
    {
        bytesWritten = 0;

        if (!IsSupported)
        {
            return SecurityError.UnsupportedAlgorithm("ChaCha20Poly1305", "ChaCha20-Poly1305 is not supported on the current platform.");
        }

        if (key.Length != ExpectedKeyBytes)
        {
            return SecurityError.InvalidKey($"ChaCha20-Poly1305 requires a 32-byte key. Received {key.Length} bytes.");
        }

        if (ciphertext.Length > MaxRecommendedPayloadBytes)
        {
            return SecurityError.PayloadTooLarge($"Ciphertext payload size ({ciphertext.Length} bytes) exceeds the maximum allowed payload size of {MaxRecommendedPayloadBytes} bytes.");
        }

        if (nonce.Length != ExpectedNonceBytes)
        {
            return SecurityError.InvalidNonce($"ChaCha20-Poly1305 requires a 12-byte nonce. Received {nonce.Length} bytes.");
        }


        if (tag.Length != ExpectedTagBytes)
        {
            return SecurityError.AuthenticationTagMismatch($"Authentication tag must be 16 bytes. Received {tag.Length} bytes.");
        }

        if (plaintextDestination.Length < ciphertext.Length)
        {
            return SecurityError.BufferTooSmall($"Destination buffer ({plaintextDestination.Length} bytes) is smaller than ciphertext ({ciphertext.Length} bytes).");
        }

        return DecryptCore(ciphertext, key, nonce, tag, associatedData, plaintextDestination, out bytesWritten);
    }

    private static Result<EncryptedData> EncryptCore(
        ReadOnlySpan<byte> plaintext,
        ReadOnlySpan<byte> key,
        byte[] nonceBytes,
        ReadOnlySpan<byte> associatedData)
    {
        var ciphertextBytes = new byte[plaintext.Length];
        var tagBytes = new byte[ExpectedTagBytes];

        using var cipher = new ChaCha20Poly1305(key);
        cipher.Encrypt(
            nonce: nonceBytes,
            plaintext: plaintext,
            ciphertext: ciphertextBytes,
            tag: tagBytes,
            associatedData: associatedData);

        return new EncryptedData(ciphertextBytes, tagBytes, nonceBytes);
    }

    private static Result EncryptSpanCore(
        ReadOnlySpan<byte> plaintext,
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> nonce,
        Span<byte> ciphertextDestination,
        Span<byte> tagDestination,
        ReadOnlySpan<byte> associatedData)
    {
        using var cipher = new ChaCha20Poly1305(key);
        cipher.Encrypt(
            nonce: nonce,
            plaintext: plaintext,
            ciphertext: ciphertextDestination[..plaintext.Length],
            tag: tagDestination[..ExpectedTagBytes],
            associatedData: associatedData);

        return Result.Success();
    }

    private static Result DecryptCore(
        ReadOnlySpan<byte> ciphertext,
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> tag,
        ReadOnlySpan<byte> associatedData,
        Span<byte> plaintextDestination,
        out int bytesWritten)
    {
        bytesWritten = 0;

        try
        {
            using var cipher = new ChaCha20Poly1305(key);
            cipher.Decrypt(
                nonce: nonce,
                ciphertext: ciphertext,
                tag: tag,
                plaintext: plaintextDestination[..ciphertext.Length],
                associatedData: associatedData);

            bytesWritten = ciphertext.Length;
            return Result.Success();
        }
        catch (CryptographicException)
        {
            // SEC-MEM: Zero out destination buffer to prevent leaking unauthenticated plaintext residue
            CryptographicOperations.ZeroMemory(plaintextDestination[..ciphertext.Length]);

            // OBS-002 fix: use fixed controlled message; internal details not exposed to caller.
            return SecurityError.AuthenticationTagMismatch("Authentication tag verification failed. The ciphertext may have been tampered with.");
        }
    }
}
