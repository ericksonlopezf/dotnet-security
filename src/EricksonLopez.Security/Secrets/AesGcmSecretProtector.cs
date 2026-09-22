// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Secrets;

using System;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using EricksonLopez.Result;
using EricksonLopez.Security.Abstractions.Cryptography;
using EricksonLopez.Security.Abstractions.Errors;
using EricksonLopez.Security.Abstractions.KeyManagement;
using EricksonLopez.Security.Abstractions.Primitives;
using EricksonLopez.Security.Abstractions.Secrets;
using EricksonLopez.Security.Cryptography;
using EricksonLopez.Security.Memory;

/// <summary>
/// Provides an envelope-based secret protector that encrypts sensitive payloads with AES-256-GCM using active keys
/// from <see cref="IEncryptionKeyProvider"/> and produces tamper-resistant binary <see cref="SecurityEnvelope"/> payloads.
/// </summary>
public sealed class AesGcmSecretProtector : ISecretProtector
{
    private readonly IEncryptionKeyProvider _keyProvider;
    private readonly IAuthenticatedEncryptionEngine _engine;
    private readonly ISecurityEnvelopeSerializer _serializer;

    /// <summary>
    /// Initializes a new instance of the <see cref="AesGcmSecretProtector"/> class.
    /// </summary>
    /// <param name="keyProvider">The encryption key provider.</param>
    /// <param name="engine">The optional authenticated encryption engine (defaults to AES-GCM).</param>
    /// <param name="serializer">The optional binary envelope serializer.</param>
    /// <exception cref="ArgumentNullException"><paramref name="keyProvider"/> is <see langword="null"/></exception>
    public AesGcmSecretProtector(
        IEncryptionKeyProvider keyProvider,
        IAuthenticatedEncryptionEngine? engine = null,
        ISecurityEnvelopeSerializer? serializer = null)
    {
        _keyProvider = keyProvider ?? throw new ArgumentNullException(nameof(keyProvider));
        _engine = engine ?? AesGcmEncryptionEngine.Shared;
        _serializer = serializer ?? BinarySecurityEnvelopeSerializer.Shared;
    }

    /// <inheritdoc />
    public async ValueTask<Result<byte[]>> ProtectAsync(
        ReadOnlyMemory<byte> secret,
        KeyPurpose purpose = KeyPurpose.SecretProtection,
        AuthenticatedContext expectedAssociatedData = default,
        CancellationToken cancellationToken = default)
    {
        var keyResult = await _keyProvider.GetActiveEncryptionKeyAsync(purpose, cancellationToken);
        if (keyResult.IsFailure)
        {
            return keyResult.Error;
        }

        // MEM-007 fix: dispose the key immediately after use so the underlying SecretBuffer
        // calls CryptographicOperations.ZeroMemory, preventing key material from persisting
        // in the heap until the next GC collection.
        using var key = keyResult.Value;
        var encryptResult = _engine.Encrypt(secret.Span, key.GetKeyBytes(), expectedAssociatedData.Span);
        if (encryptResult.IsFailure)
        {
            return encryptResult.Error;
        }

        var encryptedData = encryptResult.Value;
        var envelope = new SecurityEnvelope(
            FormatVersion: SecurityEnvelope.CurrentFormatVersion,
            Algorithm: _engine.Algorithm,
            KeyId: key.Metadata.KeyId,
            KeyVersion: key.Metadata.Version,
            Nonce: encryptedData.Nonce,
            Tag: encryptedData.Tag,
            Ciphertext: encryptedData.Ciphertext,
            AssociatedData: expectedAssociatedData.Span.ToArray());

        var serialized = _serializer.Serialize(envelope);
        return serialized;
    }

    /// <inheritdoc />
    /// <remarks>
    /// <strong>Memory Note (SP-04):</strong> The returned <c>byte[]</c> contains the decrypted plaintext
    /// as a managed heap allocation. Unlike <see cref="Memory.SecretBuffer"/>, a raw <c>byte[]</c> cannot
    /// be explicitly zeroed by the library because the caller holds the only reference after return.
    /// To minimize the plaintext exposure window, callers should:
    /// <list type="bullet">
    ///   <item><description>Process the plaintext and discard the reference as quickly as possible.</description></item>
    ///   <item><description>Call <c>CryptographicOperations.ZeroMemory(result);</c> when finished to scrub
    ///   the content before the array is collected (best-effort — JIT may optimize away without
    ///   <c>[MethodImpl(NoOptimization)]</c>).</description></item>
    /// </list>
    /// A future version (v1.2) will introduce a <c>UnprotectToSecretBufferAsync</c> overload returning
    /// a <see cref="Memory.SecretBuffer"/> with deterministic zeroing on disposal.
    /// </remarks>
    public async ValueTask<Result<byte[]>> UnprotectAsync(
        ReadOnlyMemory<byte> protectedData,
        AuthenticatedContext expectedAssociatedData = default,
        CancellationToken cancellationToken = default)
    {
        var deserializeResult = _serializer.Deserialize(protectedData.Span);
        if (deserializeResult.IsFailure)
        {
            return deserializeResult.Error;
        }

        var envelope = deserializeResult.Value;

        var keyResult = await _keyProvider.GetDecryptionKeyAsync(envelope.KeyId, envelope.KeyVersion, cancellationToken);
        if (keyResult.IsFailure)
        {
            return keyResult.Error;
        }

        // MEM-007 fix: dispose key immediately so SecretBuffer zeroes key material via CryptographicOperations.ZeroMemory.
        using var key = keyResult.Value;
        var destination = new byte[envelope.Ciphertext.Length];

        // SEC-CRIT-01 & SEC-002 fix: If the envelope contains authenticated associated data,
        // the caller must supply matching AAD to prevent cross-tenant confused deputy attacks.
        ReadOnlySpan<byte> effectiveAad;
        if (envelope.HasAssociatedData)
        {
            if (expectedAssociatedData.IsEmpty || !expectedAssociatedData.Equals(AuthenticatedContext.FromBytes(envelope.AssociatedData.Span)))
            {
                return SecurityError.AssociatedDataMismatch(
                    "The authenticated associated data (AAD) provided does not match the authenticated context in the secret envelope.");
            }
            effectiveAad = envelope.AssociatedData.Span;
        }
        else
        {
            if (!expectedAssociatedData.IsEmpty)
            {
                return SecurityError.AssociatedDataMismatch(
                    "The secret envelope does not contain authenticated associated data (AAD), but associated data was expected.");
            }
            effectiveAad = ReadOnlySpan<byte>.Empty;
        }

        var decryptResult = _engine.Decrypt(
            ciphertext: envelope.Ciphertext.Span,
            key: key.GetKeyBytes(),
            nonce: envelope.Nonce.Span,
            tag: envelope.Tag.Span,
            associatedData: effectiveAad,
            plaintextDestination: destination,
            out int bytesWritten);

        if (decryptResult.IsFailure)
        {
            CryptographicOperations.ZeroMemory(destination);
            return decryptResult.Error;
        }

        return destination;
    }

    /// <inheritdoc />
    public async ValueTask<Result<ISecretBuffer>> UnprotectToSecretBufferAsync(
        ReadOnlyMemory<byte> protectedData,
        AuthenticatedContext expectedAssociatedData = default,
        CancellationToken cancellationToken = default)
    {
        var deserializeResult = _serializer.Deserialize(protectedData.Span);
        if (deserializeResult.IsFailure)
        {
            return deserializeResult.Error;
        }

        var envelope = deserializeResult.Value;

        var keyResult = await _keyProvider.GetDecryptionKeyAsync(envelope.KeyId, envelope.KeyVersion, cancellationToken);
        if (keyResult.IsFailure)
        {
            return keyResult.Error;
        }

        using var key = keyResult.Value;
        var destination = new SecretBuffer(envelope.Ciphertext.Length);

        ReadOnlySpan<byte> effectiveAad;
        if (envelope.HasAssociatedData)
        {
            if (expectedAssociatedData.IsEmpty || !expectedAssociatedData.Equals(AuthenticatedContext.FromBytes(envelope.AssociatedData.Span)))
            {
                destination.Dispose();
                return SecurityError.AssociatedDataMismatch(
                    "The authenticated associated data (AAD) provided does not match the authenticated context in the secret envelope.");
            }
            effectiveAad = envelope.AssociatedData.Span;
        }
        else
        {
            if (!expectedAssociatedData.IsEmpty)
            {
                destination.Dispose();
                return SecurityError.AssociatedDataMismatch(
                    "The secret envelope does not contain authenticated associated data (AAD), but associated data was expected.");
            }
            effectiveAad = ReadOnlySpan<byte>.Empty;
        }

        var decryptResult = _engine.Decrypt(
            ciphertext: envelope.Ciphertext.Span,
            key: key.GetKeyBytes(),
            nonce: envelope.Nonce.Span,
            tag: envelope.Tag.Span,
            associatedData: effectiveAad,
            plaintextDestination: destination.GetWritableSpan(),
            out int bytesWritten);

        if (decryptResult.IsFailure)
        {
            destination.Dispose();
            return decryptResult.Error;
        }

        return Result<ISecretBuffer>.Success(destination);
    }

    /// <inheritdoc />
    public Result<byte[]> Protect(
        ReadOnlySpan<byte> secret,
        KeyPurpose purpose = KeyPurpose.SecretProtection,
        AuthenticatedContext expectedAssociatedData = default)
    {
        Result<CryptographicKey> keyResult;
        if (_keyProvider is IKeyRing keyRing)
        {
            keyResult = keyRing.GetActiveKey(purpose);
        }
        else
        {
            keyResult = _keyProvider.GetActiveEncryptionKeyAsync(purpose).AsTask().GetAwaiter().GetResult();
        }

        if (keyResult.IsFailure)
        {
            return keyResult.Error;
        }

        // MEM-007 fix: dispose key immediately after use to zero key bytes in memory.
        using var key = keyResult.Value;
        var encryptResult = _engine.Encrypt(secret, key.GetKeyBytes(), expectedAssociatedData.Span);
        if (encryptResult.IsFailure)
        {
            return encryptResult.Error;
        }

        var encryptedData = encryptResult.Value;
        var envelope = new SecurityEnvelope(
            FormatVersion: SecurityEnvelope.CurrentFormatVersion,
            Algorithm: _engine.Algorithm,
            KeyId: key.Metadata.KeyId,
            KeyVersion: key.Metadata.Version,
            Nonce: encryptedData.Nonce,
            Tag: encryptedData.Tag,
            Ciphertext: encryptedData.Ciphertext,
            AssociatedData: expectedAssociatedData.Span.ToArray());

        var serialized = _serializer.Serialize(envelope);
        return serialized;
    }

    /// <inheritdoc />
    public Result<byte[]> Unprotect(ReadOnlySpan<byte> protectedData, AuthenticatedContext expectedAssociatedData = default)
    {
        var deserializeResult = _serializer.Deserialize(protectedData);
        if (deserializeResult.IsFailure)
        {
            return deserializeResult.Error;
        }

        var envelope = deserializeResult.Value;

        Result<CryptographicKey> keyResult;
        if (_keyProvider is IKeyRing keyRing)
        {
            keyResult = keyRing.GetKey(envelope.KeyId, envelope.KeyVersion);
        }
        else
        {
            keyResult = _keyProvider.GetDecryptionKeyAsync(envelope.KeyId, envelope.KeyVersion).AsTask().GetAwaiter().GetResult();
        }

        if (keyResult.IsFailure)
        {
            return keyResult.Error;
        }

        // MEM-007 fix: dispose key immediately after use to zero key bytes in memory.
        using var key = keyResult.Value;
        var destination = new byte[envelope.Ciphertext.Length];
        // SEC-CRIT-01 & SEC-002 fix: If the envelope contains authenticated associated data,
        // the caller must supply matching AAD to prevent cross-tenant confused deputy attacks.
        ReadOnlySpan<byte> effectiveAad;
        if (envelope.HasAssociatedData)
        {
            if (expectedAssociatedData.IsEmpty || !expectedAssociatedData.Equals(AuthenticatedContext.FromBytes(envelope.AssociatedData.Span)))
            {
                return SecurityError.AssociatedDataMismatch(
                    "The authenticated associated data (AAD) provided does not match the authenticated context in the secret envelope.");
            }
            effectiveAad = envelope.AssociatedData.Span;
        }
        else
        {
            if (!expectedAssociatedData.IsEmpty)
            {
                return SecurityError.AssociatedDataMismatch(
                    "The secret envelope does not contain authenticated associated data (AAD), but associated data was expected.");
            }
            effectiveAad = ReadOnlySpan<byte>.Empty;
        }

        var decryptResult = _engine.Decrypt(
            ciphertext: envelope.Ciphertext.Span,
            key: key.GetKeyBytes(),
            nonce: envelope.Nonce.Span,
            tag: envelope.Tag.Span,
            associatedData: effectiveAad,
            plaintextDestination: destination,
            out int bytesWritten);

        if (decryptResult.IsFailure)
        {
            CryptographicOperations.ZeroMemory(destination);
            return decryptResult.Error;
        }

        return destination;
    }
}
