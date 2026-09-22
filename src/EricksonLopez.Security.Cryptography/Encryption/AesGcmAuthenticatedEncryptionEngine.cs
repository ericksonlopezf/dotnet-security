// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Cryptography.Encryption;

using System;
using System.Security.Cryptography;
using EricksonLopez.Result;
using EricksonLopez.Security.Abstractions.Cryptography;
using EricksonLopez.Security.Abstractions.Randomness;
using EricksonLopez.Security.Abstractions.Errors;

/// <summary>
/// Provides high-performance, low-allocation AES-GCM (256-bit) authenticated encryption.
/// </summary>
/// <param name="random">The cryptographic random number generator that generates nonces.</param>
public sealed class AesGcmAuthenticatedEncryptionEngine(ICryptographicRandomNumberGenerator random) : IAuthenticatedEncryptionEngine
{
    private const int KeySize = 32; // AES-256
    private const int NonceSize = 12; // AesGcm.NonceByteSizes.MaxSize
    private const int TagSize = 16; // AesGcm.TagByteSizes.MaxSize

    /// <summary>
    /// Gets the AEAD algorithm implemented by this engine (<see cref="AeadAlgorithm.Aes256Gcm"/>).
    /// </summary>
    public AeadAlgorithm Algorithm => AeadAlgorithm.Aes256Gcm;

    /// <summary>
    /// Gets the required key size in bytes (32 bytes / 256 bits).
    /// </summary>
    public int KeySizeBytes => KeySize;

    /// <summary>
    /// Gets the required nonce (initialization vector) size in bytes (12 bytes / 96 bits).
    /// </summary>
    public int NonceSizeBytes => NonceSize;

    /// <summary>
    /// Gets the authentication tag size in bytes (16 bytes / 128 bits).
    /// </summary>
    public int TagSizeBytes => TagSize;

    /// <inheritdoc/>
    public Result<EncryptedData> Encrypt(
        ReadOnlySpan<byte> plaintext,
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> associatedData = default)
    {
        if (key.Length != KeySize)
        {
            return Result<EncryptedData>.Failure(SecurityError.InvalidKey($"AES-GCM requires a {KeySize}-byte key."));
        }

        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[TagSize];
        var nonce = new byte[NonceSize];

        random.Fill(nonce);

        return EncryptCore(plaintext, key, nonce, ciphertext, tag, associatedData);
    }

    /// <inheritdoc/>
    public Result Encrypt(
        ReadOnlySpan<byte> plaintext,
        ReadOnlySpan<byte> key,
        Span<byte> nonceDestination,
        Span<byte> ciphertextDestination,
        Span<byte> tagDestination,
        ReadOnlySpan<byte> associatedData = default)
    {
        if (key.Length != KeySize)
        {
            return Result.Failure(SecurityError.InvalidKey($"AES-GCM requires a {KeySize}-byte key."));
        }

        if (nonceDestination.Length < NonceSize)
        {
            return Result.Failure(SecurityError.EncryptionFailed($"AES-GCM requires a {NonceSize}-byte nonce destination."));
        }

        if (tagDestination.Length != TagSize)
        {
            return Result.Failure(SecurityError.EncryptionFailed($"AES-GCM requires a {TagSize}-byte tag destination."));
        }

        if (ciphertextDestination.Length < plaintext.Length)
        {
            return Result.Failure(SecurityError.EncryptionFailed("Ciphertext destination span is too small."));
        }

        random.Fill(nonceDestination[..NonceSize]);
        var nonce = nonceDestination[..NonceSize];

        return EncryptSpanCore(plaintext, key, nonce, ciphertextDestination, tagDestination, associatedData);
    }

    /// <inheritdoc/>
    public Result Decrypt(
        ReadOnlySpan<byte> ciphertext,
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> tag,
        ReadOnlySpan<byte> associatedData,
        Span<byte> plaintextDestination,
        out int bytesWritten)
    {
        if (key.Length != KeySize)
        {
            bytesWritten = 0;
            return Result.Failure(SecurityError.InvalidKey($"AES-GCM requires a {KeySize}-byte key."));
        }

        if (nonce.Length != NonceSize)
        {
            bytesWritten = 0;
            return Result.Failure(SecurityError.DecryptionFailed($"AES-GCM requires a {NonceSize}-byte nonce."));
        }

        if (tag.Length != TagSize)
        {
            bytesWritten = 0;
            return Result.Failure(SecurityError.DecryptionFailed($"AES-GCM requires a {TagSize}-byte authentication tag."));
        }

        if (plaintextDestination.Length < ciphertext.Length)
        {
            bytesWritten = 0;
            return Result.Failure(SecurityError.DecryptionFailed("Plaintext destination span is too small."));
        }

        return DecryptCore(ciphertext, key, nonce, tag, associatedData, plaintextDestination, out bytesWritten);
    }

    private static Result<EncryptedData> EncryptCore(
        ReadOnlySpan<byte> plaintext,
        ReadOnlySpan<byte> key,
        byte[] nonce,
        byte[] ciphertext,
        byte[] tag,
        ReadOnlySpan<byte> associatedData)
    {
        using var aes = new AesGcm(key, TagSize);
        aes.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);
        return Result<EncryptedData>.Success(new EncryptedData(ciphertext, tag, nonce));
    }

    private static Result EncryptSpanCore(
        ReadOnlySpan<byte> plaintext,
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> nonce,
        Span<byte> ciphertextDestination,
        Span<byte> tagDestination,
        ReadOnlySpan<byte> associatedData)
    {
        using var aes = new AesGcm(key, TagSize);
        aes.Encrypt(nonce, plaintext, ciphertextDestination.Slice(0, plaintext.Length), tagDestination, associatedData);
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
        try
        {
            using var aes = new AesGcm(key, TagSize);
            aes.Decrypt(nonce, ciphertext, tag, plaintextDestination.Slice(0, ciphertext.Length), associatedData);
            bytesWritten = ciphertext.Length;
            return Result.Success();
        }
        catch (CryptographicException)
        {
            CryptographicOperations.ZeroMemory(plaintextDestination.Slice(0, ciphertext.Length));
            bytesWritten = 0;
            return Result.Failure(SecurityError.AuthenticationTagMismatch("Data tampering detected or invalid key."));
        }
    }
}
