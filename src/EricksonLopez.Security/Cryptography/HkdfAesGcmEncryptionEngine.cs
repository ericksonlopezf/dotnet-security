// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Cryptography;

using System;
using System.Security.Cryptography;
using EricksonLopez.Result;
using EricksonLopez.Security.Abstractions.Cryptography;
using EricksonLopez.Security.Abstractions.Errors;

/// <summary>
/// Provides HKDF-enhanced AES-256-GCM authenticated encryption that derives a unique ephemeral
/// 256-bit key for every encryption operation via HKDF-SHA512, ensuring forward-secrecy-like
/// key isolation and replay resistance through per-operation key derivation.
/// </summary>
/// <remarks>
/// <strong>HKDF Parameter Semantics (HKDF-03):</strong>
/// <para>
/// This engine uses <see cref="HKDF"/> (RFC 5869) with SHA-512 to derive a fresh ephemeral key for
/// each encrypt/decrypt call from the root key material:
/// </para>
/// <list type="bullet">
///   <item><description>
///     <strong>IKM (Input Key Material):</strong> The caller-provided root key (256 bits / 32 bytes).
///     This is the secret managed by <see cref="EricksonLopez.Security.KeyManagement.KeyRing"/>.
///   </description></item>
///   <item><description>
///     <strong>Salt:</strong> The per-operation nonce (96 bits / 12 bytes, generated freshly by
///     <see cref="System.Security.Cryptography.RandomNumberGenerator.Fill"/>). Using the nonce as salt
///     means each encryption derives a unique ephemeral key, achieving per-operation key isolation
///     without requiring callers to manage separate derived key material.
///   </description></item>
///   <item><description>
///     <strong>Info (Context Separation):</strong> The constant label <c>"EricksonLopez.Security.HKDF.AES-256-GCM.v1"</c>
///     (UTF-8 encoded). This info label provides domain separation \u2014 the same root key used with a different
///     <c>info</c> label (e.g., for a different algorithm or application context) will produce a
///     completely independent derived key. This prevents cross-context key confusion.
///   </description></item>
///   <item><description>
///     <strong>Output:</strong> 256-bit ephemeral AES-256 key, used for a single AES-256-GCM operation
///     and then zeroed via <see cref="System.Security.Cryptography.CryptographicOperations.ZeroMemory"/>.
///   </description></item>
/// </list>
/// <para>
/// Forward-secrecy property: compromise of the ephemeral key does not compromise the root key or
/// other ephemeral keys because HKDF is a one-way function.
/// </para>
/// </remarks>
public sealed class HkdfAesGcmEncryptionEngine : IAuthenticatedEncryptionEngine
{
    private const int ExpectedKeyBytes = 32;   // 256 bits
    private const int ExpectedNonceBytes = 12; // 96 bits
    private const int ExpectedTagBytes = 16;   // 128 bits
    private const string KdfInfoLabel = "EricksonLopez.Security.HKDF.AES-256-GCM.v1";

    /// <summary>
    /// Gets the maximum allowed payload size in bytes (256 MiB) enforced by the engine
    /// on Encrypt and Decrypt operations to prevent asymmetric memory exhaustion DoS attacks (GAP-01 / REM-001).
    /// </summary>
    public const int MaxRecommendedPayloadBytes = 256 * 1024 * 1024; // 256 MiB

    /// <summary>
    /// Gets the shared singleton instance of <see cref="HkdfAesGcmEncryptionEngine"/>.
    /// </summary>
    public static readonly HkdfAesGcmEncryptionEngine Shared = new();

    /// <inheritdoc />
    public AeadAlgorithm Algorithm => AeadAlgorithm.HkdfAes256Gcm;

    /// <summary>
    /// Gets a value indicating whether this engine provides true quantum resistance.
    /// </summary>
    /// <remarks>
    /// Evaluates to <see langword="false"/> as this is a classical HKDF-SHA512 + AES-256-GCM scheme.
    /// True ML-KEM-768 key encapsulation will be introduced in a future release upon FIPS 140-3 validation.
    /// </remarks>
    public static bool IsQuantumResistant => false;

    /// <summary>
    /// Gets the cryptographic substrate name backing this engine.
    /// </summary>
    public static string SubstrateDescription => "HKDF-SHA512 + AES-256-GCM Ephemeral Key Isolation (ADR-025)";

    /// <inheritdoc />
    public int KeySizeBytes => ExpectedKeyBytes;

    /// <inheritdoc />
    public int NonceSizeBytes => ExpectedNonceBytes;

    /// <inheritdoc />
    public int TagSizeBytes => ExpectedTagBytes;

    private static void DeriveHybridKey(ReadOnlySpan<byte> rootKey, ReadOnlySpan<byte> nonce, Span<byte> destination)
    {
        Span<byte> info = stackalloc byte[System.Text.Encoding.UTF8.GetByteCount(KdfInfoLabel)];
        System.Text.Encoding.UTF8.GetBytes(KdfInfoLabel, info);

        HKDF.DeriveKey(
            hashAlgorithmName: HashAlgorithmName.SHA512,
            ikm: rootKey,
            output: destination,
            salt: nonce,
            info: info);
    }

    /// <inheritdoc />
    public Result<EncryptedData> Encrypt(
        ReadOnlySpan<byte> plaintext,
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> associatedData = default)
    {
        if (key.Length != ExpectedKeyBytes)
        {
            return SecurityError.InvalidKey($"HKDF AES-256-GCM requires a 256-bit (32-byte) key. Received {key.Length} bytes.");
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
        if (key.Length != ExpectedKeyBytes)
        {
            return SecurityError.InvalidKey($"HKDF AES-256-GCM requires a 32-byte key. Received {key.Length} bytes.");
        }

        if (plaintext.Length > MaxRecommendedPayloadBytes)
        {
            return SecurityError.PayloadTooLarge($"Plaintext payload size ({plaintext.Length} bytes) exceeds the maximum allowed payload size of {MaxRecommendedPayloadBytes} bytes.");
        }

        if (nonceDestination.Length < ExpectedNonceBytes)
        {
            return SecurityError.InvalidNonce($"HKDF AES-256-GCM requires a 12-byte nonce buffer. Received {nonceDestination.Length} bytes.");
        }

        if (tagDestination.Length < ExpectedTagBytes)
        {
            return SecurityError.BufferTooSmall($"Tag destination buffer must be at least 16 bytes. Received {tagDestination.Length} bytes.");
        }

        if (ciphertextDestination.Length < plaintext.Length)
        {
            return SecurityError.BufferTooSmall($"Ciphertext destination buffer must be at least {plaintext.Length} bytes.");
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
            return SecurityError.InvalidKey($"HKDF AES-256-GCM requires a 32-byte key. Received {key.Length} bytes.");
        }

        if (ciphertext.Length > MaxRecommendedPayloadBytes)
        {
            return SecurityError.PayloadTooLarge($"Ciphertext payload size ({ciphertext.Length} bytes) exceeds the maximum allowed payload size of {MaxRecommendedPayloadBytes} bytes.");
        }

        if (nonce.Length != ExpectedNonceBytes)
        {
            return SecurityError.InvalidNonce($"HKDF AES-256-GCM requires a 12-byte nonce. Received {nonce.Length} bytes.");
        }

        if (tag.Length != ExpectedTagBytes)
        {
            return SecurityError.AuthenticationTagMismatch($"Authentication tag must be 16 bytes. Received {tag.Length} bytes.");
        }

        if (plaintextDestination.Length < ciphertext.Length)
        {
            return SecurityError.BufferTooSmall($"Destination buffer ({plaintextDestination.Length} bytes) is smaller than ciphertext ({ciphertext.Length} bytes).");
        }

        Span<byte> hybridKey = stackalloc byte[ExpectedKeyBytes];
        DeriveHybridKey(key, nonce, hybridKey);

        try
        {
            using var aesGcm = new AesGcm(hybridKey, ExpectedTagBytes);
            aesGcm.Decrypt(
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
            CryptographicOperations.ZeroMemory(plaintextDestination[..ciphertext.Length]);
            return SecurityError.AuthenticationTagMismatch("Authentication tag verification failed. The ciphertext may have been tampered with.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(hybridKey);
        }
    }

    private static Result<EncryptedData> EncryptCore(
        ReadOnlySpan<byte> plaintext,
        ReadOnlySpan<byte> key,
        byte[] nonceBytes,
        ReadOnlySpan<byte> associatedData)
    {
        Span<byte> hybridKey = stackalloc byte[ExpectedKeyBytes];
        DeriveHybridKey(key, nonceBytes, hybridKey);
        var ciphertextBytes = new byte[plaintext.Length];
        var tagBytes = new byte[ExpectedTagBytes];

        try
        {
            using var aesGcm = new AesGcm(hybridKey, ExpectedTagBytes);
            aesGcm.Encrypt(
                nonce: nonceBytes,
                plaintext: plaintext,
                ciphertext: ciphertextBytes,
                tag: tagBytes,
                associatedData: associatedData);

            return new EncryptedData(ciphertextBytes, tagBytes, nonceBytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(hybridKey);
        }
    }

    private static Result EncryptSpanCore(
        ReadOnlySpan<byte> plaintext,
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> nonce,
        Span<byte> ciphertextDestination,
        Span<byte> tagDestination,
        ReadOnlySpan<byte> associatedData)
    {
        Span<byte> hybridKey = stackalloc byte[ExpectedKeyBytes];
        DeriveHybridKey(key, nonce, hybridKey);

        try
        {
            using var aesGcm = new AesGcm(hybridKey, ExpectedTagBytes);
            aesGcm.Encrypt(
                nonce: nonce,
                plaintext: plaintext,
                ciphertext: ciphertextDestination[..plaintext.Length],
                tag: tagDestination[..ExpectedTagBytes],
                associatedData: associatedData);

            return Result.Success();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(hybridKey);
        }
    }
}
