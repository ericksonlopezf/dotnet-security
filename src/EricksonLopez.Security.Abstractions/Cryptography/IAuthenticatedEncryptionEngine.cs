// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Abstractions.Cryptography;

using System;
using EricksonLopez.Result;

/// <summary>
/// Defines the contract for high-performance, low-allocation Authenticated Encryption with Associated Data (AEAD) engines.
/// </summary>
public interface IAuthenticatedEncryptionEngine
{
    /// <summary>
    /// Gets the AEAD algorithm implemented by this engine.
    /// </summary>
    AeadAlgorithm Algorithm { get; }

    /// <summary>
    /// Gets the required key size in bytes (e.g., 32 bytes for AES-256).
    /// </summary>
    int KeySizeBytes { get; }

    /// <summary>
    /// Gets the required nonce size in bytes (e.g., 12 bytes).
    /// </summary>
    int NonceSizeBytes { get; }

    /// <summary>
    /// Gets the required authentication tag size in bytes (e.g., 16 bytes).
    /// </summary>
    int TagSizeBytes { get; }

    /// <summary>
    /// Encrypts the provided plaintext using authenticated encryption with the specified key, generating a fresh random nonce.
    /// </summary>
    /// <param name="plaintext">The unencrypted data span.</param>
    /// <param name="key">The 256-bit cryptographic key span.</param>
    /// <param name="associatedData">Optional authenticated associated data.</param>
    /// <returns>A <see cref="Result{T}"/> containing the <see cref="EncryptedData"/> on success, or a failure error.</returns>
    Result<EncryptedData> Encrypt(
        ReadOnlySpan<byte> plaintext,
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> associatedData = default);

    /// <summary>
    /// Encrypts the provided plaintext into caller-provided output spans for zero heap allocations,
    /// automatically generating a fresh cryptographically secure random nonce into <paramref name="nonceDestination"/>
    /// to guarantee nonce-misuse resistance and prevent catastrophic nonce reuse.
    /// </summary>
    /// <param name="plaintext">The unencrypted data span.</param>
    /// <param name="key">The cryptographic key span.</param>
    /// <param name="nonceDestination">The destination span where the freshly generated nonce is written (at least 12 bytes).</param>
    /// <param name="ciphertextDestination">The destination span for encrypted bytes (must be at least plaintext.Length).</param>
    /// <param name="tagDestination">The destination span for the 16-byte authentication tag.</param>
    /// <param name="associatedData">Optional authenticated associated data.</param>
    /// <returns>A <see cref="Result"/> indicating success or a cryptographic failure error.</returns>
    Result Encrypt(
        ReadOnlySpan<byte> plaintext,
        ReadOnlySpan<byte> key,
        Span<byte> nonceDestination,
        Span<byte> ciphertextDestination,
        Span<byte> tagDestination,
        ReadOnlySpan<byte> associatedData = default);

    /// <summary>
    /// Decrypts and authenticates the ciphertext using the specified key, nonce, tag, and associated data into a caller-supplied destination span.
    /// </summary>
    /// <param name="ciphertext">The encrypted payload span.</param>
    /// <param name="key">The cryptographic key span.</param>
    /// <param name="nonce">The initialization nonce span.</param>
    /// <param name="tag">The authentication tag span.</param>
    /// <param name="associatedData">The associated data span to authenticate.</param>
    /// <param name="plaintextDestination">The destination buffer for decrypted bytes.</param>
    /// <param name="bytesWritten">The number of decrypted bytes written to the destination.</param>
    /// <returns>A <see cref="Result"/> indicating success or failure (e.g. tag mismatch, tampered data).</returns>
    /// <remarks>
    /// <para>
    /// <strong>Security — Payload Size (GAP-01):</strong> This method does not enforce an upper bound on
    /// <paramref name="ciphertext"/> length. When the caller allocates <paramref name="plaintextDestination"/>
    /// based on untrusted input (e.g. network-received ciphertext), an attacker who controls the payload
    /// length can trigger large heap allocations before the authentication tag is verified, potentially
    /// causing out-of-memory conditions in constrained environments.
    /// </para>
    /// <para>
    /// <strong>Required mitigation:</strong> The caller MUST validate <c>ciphertext.Length</c> against an
    /// application-defined maximum before calling this method. A recommended limit is
    /// <c>256 * 1024 * 1024</c> bytes (256 MiB) for most workloads. See individual engine implementations
    /// (e.g. <c>AesGcmEncryptionEngine.MaxRecommendedPayloadBytes</c>) for suggested defaults.
    /// </para>
    /// </remarks>
    Result Decrypt(
        ReadOnlySpan<byte> ciphertext,
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> tag,
        ReadOnlySpan<byte> associatedData,
        Span<byte> plaintextDestination,
        out int bytesWritten);
}
