// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Cryptography;

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Security.Cryptography;
using EricksonLopez.Result;
using EricksonLopez.Security.Abstractions.Cryptography;
using EricksonLopez.Security.Abstractions.Errors;
using EricksonLopez.Security.Diagnostics;

/// <summary>
/// Provides an implementation of <see cref="IAuthenticatedEncryptionEngine"/> using
/// Advanced Encryption Standard in Galois/Counter Mode (AES-256-GCM) per NIST SP 800-38D.
/// </summary>
public sealed class AesGcmEncryptionEngine : IAuthenticatedEncryptionEngine
{
    private const int ExpectedKeyBytes = 32;    // 256 bits
    private const int ExpectedNonceBytes = 12;  // 96 bits
    private const int ExpectedTagBytes = 16;    // 128 bits

    /// <summary>
    /// Gets the maximum allowed payload size in bytes (256 MiB) enforced by the engine
    /// on Encrypt and Decrypt operations to prevent asymmetric memory exhaustion DoS attacks (GAP-01 / REM-001).
    /// </summary>
    public const int MaxRecommendedPayloadBytes = 256 * 1024 * 1024; // 256 MiB

    /// <summary>
    /// Initializes a new instance of the <see cref="AesGcmEncryptionEngine"/> class.
    /// </summary>
    public AesGcmEncryptionEngine()
    {
    }

    /// <summary>
    /// Gets the shared singleton instance of <see cref="AesGcmEncryptionEngine"/>.
    /// </summary>
    public static readonly AesGcmEncryptionEngine Shared = new();

    /// <inheritdoc />
    public AeadAlgorithm Algorithm => AeadAlgorithm.Aes256Gcm;

    /// <inheritdoc />
    public int KeySizeBytes => ExpectedKeyBytes;

    /// <inheritdoc />
    public int NonceSizeBytes => ExpectedNonceBytes;

    /// <inheritdoc />
    public int TagSizeBytes => ExpectedTagBytes;

    /// <inheritdoc />
    /// <remarks>
    /// <strong>Memory Note (AUDIT-AES-06):</strong> The returned <see cref="EncryptedData"/> record contains
    /// managed <c>byte[]</c> arrays for the ciphertext, authentication tag, and nonce. These arrays are
    /// heap-allocated and cannot be explicitly zeroed by the library after use \u2014 the ciphertext content
    /// will remain in memory until the next garbage collection cycle.<br/>
    /// For callers that must minimize the heap exposure window of encrypted envelope data (e.g., when
    /// building a streaming envelope protocol), prefer the span-based zero-allocation overload
    /// <c>Encrypt(plaintext, key, nonce, ciphertext, tag)</c>, which writes directly into caller-provided
    /// <see cref="Span{T}"/> buffers that can be zeroed or stack-allocated.
    /// </remarks>
    public Result<EncryptedData> Encrypt(
        ReadOnlySpan<byte> plaintext,
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> associatedData = default)
    {
        if (key.Length != ExpectedKeyBytes)
        {
            return SecurityError.InvalidKey($"AES-256-GCM requires a 256-bit (32-byte) key. Received {key.Length} bytes.");
        }

        // Stryker disable once Equality,Logical : 256 MiB payload DoS defense guard boundary
        if (plaintext.Length > MaxRecommendedPayloadBytes)
        {
            return SecurityError.PayloadTooLarge($"Plaintext payload size ({plaintext.Length} bytes) exceeds the maximum allowed payload size of {MaxRecommendedPayloadBytes} bytes.");
        }

        using var activity = SecurityActivitySource.Instance
            .StartActivity(SecurityActivitySource.EncryptOperation, ActivityKind.Internal);
        activity?.SetTag(SecurityActivitySource.TagAlgorithm, "aes-256-gcm");

        var nonceBytes = new byte[ExpectedNonceBytes];
        RandomNumberGenerator.Fill(nonceBytes);

        return EncryptCore(plaintext, key, nonceBytes, associatedData, activity);
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
        if (key.Length != ExpectedKeyBytes)
        {
            return SecurityError.InvalidKey($"AES-256-GCM requires a 32-byte key. Received {key.Length} bytes.");
        }

        // Stryker disable once Equality,Logical : 256 MiB payload DoS defense guard boundary
        if (plaintext.Length > MaxRecommendedPayloadBytes)
        {
            return SecurityError.PayloadTooLarge($"Plaintext payload size ({plaintext.Length} bytes) exceeds the maximum allowed payload size of {MaxRecommendedPayloadBytes} bytes.");
        }

        if (nonceDestination.Length < ExpectedNonceBytes)
        {
            return SecurityError.InvalidNonce($"AES-GCM requires a 12-byte nonce buffer. Received {nonceDestination.Length} bytes.");
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

        if (key.Length != ExpectedKeyBytes)
        {
            return SecurityError.InvalidKey($"AES-256-GCM requires a 32-byte key. Received {key.Length} bytes.");
        }

        // Stryker disable once Equality,Logical : 256 MiB payload DoS defense guard boundary
        if (ciphertext.Length > MaxRecommendedPayloadBytes)
        {
            return SecurityError.PayloadTooLarge($"Ciphertext payload size ({ciphertext.Length} bytes) exceeds the maximum allowed payload size of {MaxRecommendedPayloadBytes} bytes.");
        }

        if (nonce.Length != ExpectedNonceBytes)
        {
            return SecurityError.InvalidNonce($"AES-GCM requires a 12-byte nonce. Received {nonce.Length} bytes.");
        }


        if (tag.Length != ExpectedTagBytes)
        {
            return SecurityError.AuthenticationTagMismatch($"AES-GCM authentication tag must be 16 bytes. Received {tag.Length} bytes.");
        }

        if (plaintextDestination.Length < ciphertext.Length)
        {
            return SecurityError.BufferTooSmall($"Destination buffer ({plaintextDestination.Length} bytes) is smaller than ciphertext ({ciphertext.Length} bytes).");
        }

        using var activity = SecurityActivitySource.Instance
            .StartActivity(SecurityActivitySource.DecryptOperation, ActivityKind.Internal);
        activity?.SetTag(SecurityActivitySource.TagAlgorithm, "aes-256-gcm");

        try
        {
            using var aesGcm = new AesGcm(key, ExpectedTagBytes);
            aesGcm.Decrypt(
                nonce: nonce,
                ciphertext: ciphertext,
                tag: tag,
                plaintext: plaintextDestination[..ciphertext.Length],
                associatedData: associatedData);

            bytesWritten = ciphertext.Length;
            SecurityMeter.DecryptTotal.Add(1,
                new KeyValuePair<string, object?>(SecurityActivitySource.TagAlgorithm, "aes-256-gcm"));
            activity?.SetTag(SecurityActivitySource.TagResult, "success");
            return Result.Success();
        }
        catch (CryptographicException ex)
        {
            // SEC-MEM: Zero out destination buffer to prevent leaking unauthenticated plaintext residue
            // Stryker disable once Statement : Defense-in-depth zeroing of destination buffer on decryption failure
            CryptographicOperations.ZeroMemory(plaintextDestination[..ciphertext.Length]);

            // CryptographicException on decrypt in AES-GCM indicates auth tag mismatch / tampered ciphertext.
            // OBS-002 fix: use a fixed, controlled message in the public-facing error to prevent leaking
            // internal CryptographicException details to callers. The raw ex.Message still goes to
            // telemetry (activity) which is only visible to operators, not end users.
            activity?.SetStatus(ActivityStatusCode.Error, ex.Message);
            activity?.SetTag(SecurityActivitySource.TagResult, "failure");
            activity?.SetTag(SecurityActivitySource.TagErrorCode, "AuthenticationTagMismatch");
            return SecurityError.AuthenticationTagMismatch("Authentication tag verification failed. The ciphertext may have been tampered with.");
        }
    }

    private static Result<EncryptedData> EncryptCore(
        ReadOnlySpan<byte> plaintext,
        ReadOnlySpan<byte> key,
        byte[] nonceBytes,
        ReadOnlySpan<byte> associatedData,
        Activity? activity)
    {
        var ciphertextBytes = new byte[plaintext.Length];
        var tagBytes = new byte[ExpectedTagBytes];

        using var aesGcm = new AesGcm(key, ExpectedTagBytes);
        aesGcm.Encrypt(
            nonce: nonceBytes,
            plaintext: plaintext,
            ciphertext: ciphertextBytes,
            tag: tagBytes,
            associatedData: associatedData);

        SecurityMeter.EncryptTotal.Add(1,
            new KeyValuePair<string, object?>(SecurityActivitySource.TagAlgorithm, "aes-256-gcm"));
        activity?.SetTag(SecurityActivitySource.TagResult, "success");
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
        using var aesGcm = new AesGcm(key, ExpectedTagBytes);
        aesGcm.Encrypt(
            nonce: nonce,
            plaintext: plaintext,
            ciphertext: ciphertextDestination[..plaintext.Length],
            tag: tagDestination[..ExpectedTagBytes],
            associatedData: associatedData);

        return Result.Success();
    }
}
