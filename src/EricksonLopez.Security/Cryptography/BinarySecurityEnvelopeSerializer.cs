// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Cryptography;

using System;
using System.Buffers.Binary;
using System.Text;
using EricksonLopez.Result;
using EricksonLopez.Security.Abstractions.Cryptography;
using EricksonLopez.Security.Abstractions.Errors;
using EricksonLopez.Security.Abstractions.Primitives;

/// <summary>
/// Provides a binary serializer and parser for <see cref="SecurityEnvelope"/> that enforces strict byte-level validation, version matching, and buffer boundaries.
/// </summary>
public sealed class BinarySecurityEnvelopeSerializer : ISecurityEnvelopeSerializer
{
    private const byte SupportedFormatVersion = SecurityEnvelope.CurrentFormatVersion;
    private const int NonceLength = 12;
    private const int TagLength = 16;
    private const int MinHeaderSize = 1 + 1 + 2 + 4 + NonceLength + TagLength + 4 + 4; // 44 bytes minimum

    /// <summary>
    /// Defines the maximum permitted ciphertext payload size in bytes (64 MB) to prevent memory exhaustion DoS attacks.
    /// </summary>
    public const int MaxCiphertextPayloadBytes = 64 * 1024 * 1024;

    /// <summary>
    /// Initializes a new instance of the <see cref="BinarySecurityEnvelopeSerializer"/> class.
    /// </summary>
    public BinarySecurityEnvelopeSerializer()
    {
    }

    /// <summary>
    /// Gets the shared singleton instance of <see cref="BinarySecurityEnvelopeSerializer"/>.
    /// </summary>
    public static readonly BinarySecurityEnvelopeSerializer Shared = new();

    /// <inheritdoc />
    public byte[] Serialize(SecurityEnvelope envelope)
    {
        ArgumentNullException.ThrowIfNull(envelope);

        int keyIdByteCount = Encoding.UTF8.GetByteCount(envelope.KeyId.Value);
        int totalSize = 1 + 1 + 2 + keyIdByteCount + 4 + NonceLength + TagLength + 4 + envelope.AssociatedData.Length + 4 + envelope.Ciphertext.Length;

        var buffer = new byte[totalSize];
        if (!TrySerialize(envelope, buffer, out _))
        {
            throw new InvalidOperationException("Failed to serialize security envelope to calculated buffer size.");
        }

        return buffer;
    }

    /// <inheritdoc />
    public bool TrySerialize(SecurityEnvelope envelope, Span<byte> destination, out int bytesWritten)
    {
        bytesWritten = 0;
        if (envelope is null)
        {
            return false;
        }

        int keyIdByteCount = Encoding.UTF8.GetByteCount(envelope.KeyId.Value);
        if (keyIdByteCount > ushort.MaxValue)
        {
            return false;
        }

        int requiredSize = 1 + 1 + 2 + keyIdByteCount + 4 + NonceLength + TagLength + 4 + envelope.AssociatedData.Length + 4 + envelope.Ciphertext.Length;
        if (destination.Length < requiredSize)
        {
            return false;
        }

        int offset = 0;

        // Byte 0: FormatVersion
        destination[offset++] = envelope.FormatVersion;

        // Byte 1: Algorithm
        destination[offset++] = (byte)envelope.Algorithm;

        // Bytes 2-3: KeyId length
        BinaryPrimitives.WriteUInt16LittleEndian(destination[offset..], (ushort)keyIdByteCount);
        offset += 2;

        // KeyId bytes
        Encoding.UTF8.GetBytes(envelope.KeyId.Value, destination[offset..]);
        offset += keyIdByteCount;

        // KeyVersion (int32)
        BinaryPrimitives.WriteInt32LittleEndian(destination[offset..], envelope.KeyVersion.Value);
        offset += 4;

        // Nonce (12 bytes)
        envelope.Nonce.Span.CopyTo(destination[offset..]);
        offset += NonceLength;

        // Tag (16 bytes)
        envelope.Tag.Span.CopyTo(destination[offset..]);
        offset += TagLength;

        // AssociatedData length (int32) & bytes
        BinaryPrimitives.WriteInt32LittleEndian(destination[offset..], envelope.AssociatedData.Length);
        offset += 4;
        if (!envelope.AssociatedData.IsEmpty)
        {
            envelope.AssociatedData.Span.CopyTo(destination[offset..]);
            offset += envelope.AssociatedData.Length;
        }

        // Ciphertext length (int32) & bytes
        BinaryPrimitives.WriteInt32LittleEndian(destination[offset..], envelope.Ciphertext.Length);
        offset += 4;
        if (!envelope.Ciphertext.IsEmpty)
        {
            envelope.Ciphertext.Span.CopyTo(destination[offset..]);
            offset += envelope.Ciphertext.Length;
        }

        bytesWritten = offset;
        return true;
    }

    /// <inheritdoc />
    public Result<SecurityEnvelope> Deserialize(ReadOnlySpan<byte> payload)
    {
        if (payload.Length < MinHeaderSize)
        {
            return SecurityError.InvalidCiphertext($"Payload length ({payload.Length} bytes) is less than minimum envelope size ({MinHeaderSize} bytes).");
        }

        int offset = 0;

        // Byte 0: FormatVersion
        byte formatVersion = payload[offset++];
        if (formatVersion != SupportedFormatVersion)
        {
            return SecurityError.InvalidCiphertext($"Unsupported envelope format version '{formatVersion}'. Expected '{SupportedFormatVersion}'.");
        }

        // Byte 1: Algorithm
        byte algorithmByte = payload[offset++];
        if (!Enum.IsDefined(typeof(AeadAlgorithm), algorithmByte))
        {
            return SecurityError.UnsupportedAlgorithm($"Unknown AEAD algorithm ID '{algorithmByte}' in envelope header.");
        }
        var algorithm = (AeadAlgorithm)algorithmByte;

        // Bytes 2-3: KeyId length
        ushort keyIdByteCount = BinaryPrimitives.ReadUInt16LittleEndian(payload[offset..]);
        offset += 2;

        if (keyIdByteCount > payload.Length - offset)
        {
            return SecurityError.InvalidCiphertext("Malformed envelope: KeyId truncated.");
        }

        string keyIdString = Encoding.UTF8.GetString(payload.Slice(offset, keyIdByteCount));
        offset += keyIdByteCount;

        if (!KeyIdentifier.TryCreate(keyIdString, out var keyId))
        {
            return SecurityError.InvalidCiphertext("Malformed envelope: Invalid KeyIdentifier.");
        }

        // KeyVersion
        if (payload.Length - offset < 4)
        {
            return SecurityError.InvalidCiphertext("Malformed envelope: KeyVersion truncated.");
        }
        int keyVersionInt = BinaryPrimitives.ReadInt32LittleEndian(payload[offset..]);
        offset += 4;
        if (keyVersionInt < 1)
        {
            return SecurityError.InvalidCiphertext("Malformed envelope: KeyVersion must be positive.");
        }
        var keyVersion = new KeyVersion(keyVersionInt);

        // Nonce (12 bytes)
        if (payload.Length - offset < NonceLength)
        {
            return SecurityError.InvalidCiphertext("Malformed envelope: Nonce truncated.");
        }
        var nonce = payload.Slice(offset, NonceLength).ToArray();
        offset += NonceLength;

        // Tag (16 bytes)
        if (payload.Length - offset < TagLength)
        {
            return SecurityError.InvalidCiphertext("Malformed envelope: Tag truncated.");
        }
        var tag = payload.Slice(offset, TagLength).ToArray();
        offset += TagLength;

        // AssociatedData length & bytes
        if (payload.Length - offset < 4)
        {
            return SecurityError.InvalidCiphertext("Malformed envelope: AssociatedData length truncated.");
        }
        int aadLength = BinaryPrimitives.ReadInt32LittleEndian(payload[offset..]);
        offset += 4;

        if (aadLength < 0 || aadLength > payload.Length - offset)
        {
            return SecurityError.InvalidCiphertext("Malformed envelope: Invalid AssociatedData length.");
        }

        var associatedData = ReadAssociatedData(payload, ref offset, aadLength);

        // Ciphertext length & bytes
        if (payload.Length - offset < 4)
        {
            return SecurityError.InvalidCiphertext("Malformed envelope: Ciphertext length truncated.");
        }
        int ciphertextLength = BinaryPrimitives.ReadInt32LittleEndian(payload[offset..]);
        offset += 4;

        if (ciphertextLength < 0 || ciphertextLength > payload.Length - offset || ciphertextLength > MaxCiphertextPayloadBytes)
        {
            return SecurityError.InvalidCiphertext($"Malformed envelope: Invalid Ciphertext length or exceeds maximum {MaxCiphertextPayloadBytes} bytes.");
        }

        var ciphertext = payload.Slice(offset, ciphertextLength).ToArray();
        offset += ciphertextLength;

        if (offset != payload.Length)
        {
            return SecurityError.InvalidCiphertext($"Malformed envelope: Payload contains {payload.Length - offset} unconsumed trailing bytes.");
        }

        return new SecurityEnvelope(
            FormatVersion: formatVersion,
            Algorithm: algorithm,
            KeyId: keyId,
            KeyVersion: keyVersion,
            Nonce: nonce,
            Tag: tag,
            Ciphertext: ciphertext,
            AssociatedData: associatedData);
    }

    private static ReadOnlyMemory<byte> ReadAssociatedData(ReadOnlySpan<byte> payload, ref int offset, int aadLength)
    {
        var data = payload.Slice(offset, aadLength).ToArray();
        offset += aadLength;
        return data;
    }
}
