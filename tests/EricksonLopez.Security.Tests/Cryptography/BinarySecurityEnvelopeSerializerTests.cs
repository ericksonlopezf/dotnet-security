// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Tests.Cryptography;

using System;
using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Text;
using EricksonLopez.Security.Abstractions.Cryptography;
using EricksonLopez.Security.Abstractions.Primitives;
using EricksonLopez.Security.Cryptography;
using Xunit;

public sealed class BinarySecurityEnvelopeSerializerTests
{
    [Fact]
    public void BinarySerializer_SerializeAndDeserialize_RoundtripsSuccessfully()
    {
        var serializer = BinarySecurityEnvelopeSerializer.Shared;
        var keyId = KeyIdentifier.New();
        var keyVersion = KeyVersion.Initial;
        byte[] nonce = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        byte[] tag = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100, 110, 120, 130, 140, 150, 160];
        byte[] ciphertext = Encoding.UTF8.GetBytes("Encrypted content.");
        byte[] aad = Encoding.UTF8.GetBytes("Associated metadata");

        var envelope = new SecurityEnvelope(
            FormatVersion: 1,
            Algorithm: AeadAlgorithm.Aes256Gcm,
            KeyId: keyId,
            KeyVersion: keyVersion,
            Nonce: nonce,
            Tag: tag,
            Ciphertext: ciphertext,
            AssociatedData: aad);

        byte[] serialized = serializer.Serialize(envelope);
        var deserializeResult = serializer.Deserialize(serialized);

        Assert.True(deserializeResult.IsSuccess);
        var restored = deserializeResult.Value;

        Assert.Equal(envelope.FormatVersion, restored.FormatVersion);
        Assert.Equal(envelope.Algorithm, restored.Algorithm);
        Assert.Equal(envelope.KeyId, restored.KeyId);
        Assert.Equal(envelope.KeyVersion, restored.KeyVersion);
        Assert.True(restored.Nonce.Span.SequenceEqual(nonce));
        Assert.True(restored.Tag.Span.SequenceEqual(tag));
        Assert.True(restored.Ciphertext.Span.SequenceEqual(ciphertext));
        Assert.True(restored.AssociatedData.Span.SequenceEqual(aad));
    }

    [Fact]
    public void BinarySerializer_Serialize_EmptyAssociatedData_RoundtripsSuccessfully()
    {
        var serializer = BinarySecurityEnvelopeSerializer.Shared;
        var keyId = KeyIdentifier.New();
        var keyVersion = KeyVersion.Initial;
        byte[] nonce = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        byte[] tag = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        byte[] ciphertext = [10, 20, 30];

        var envelope = new SecurityEnvelope(
            FormatVersion: 1,
            Algorithm: AeadAlgorithm.ChaCha20Poly1305,
            KeyId: keyId,
            KeyVersion: keyVersion,
            Nonce: nonce,
            Tag: tag,
            Ciphertext: ciphertext,
            AssociatedData: ReadOnlyMemory<byte>.Empty);

        byte[] serialized = serializer.Serialize(envelope);
        var deserializeResult = serializer.Deserialize(serialized);

        Assert.True(deserializeResult.IsSuccess);
        var restored = deserializeResult.Value;
        Assert.False(restored.HasAssociatedData);
        Assert.True(restored.AssociatedData.IsEmpty);
    }

    [Fact]
    public void BinarySerializer_Serialize_NullEnvelope_ThrowsArgumentNullException()
    {
        var serializer = BinarySecurityEnvelopeSerializer.Shared;
        var ex = Assert.Throws<ArgumentNullException>(() => serializer.Serialize(null!));
        Assert.Equal("envelope", ex.ParamName);

        Assert.False(serializer.TrySerialize(null!, new byte[100], out var written));
        Assert.Equal(0, written);
    }

    [Fact]
    public void BinarySerializer_TrySerialize_ExactBoundaryAndMinusOneBuffer_TestsAllArithmetic()
    {
        var serializer = BinarySecurityEnvelopeSerializer.Shared;
        var keyId = KeyIdentifier.New();
        var envelope = new SecurityEnvelope(
            FormatVersion: 1,
            Algorithm: AeadAlgorithm.Aes256Gcm,
            KeyId: keyId,
            KeyVersion: KeyVersion.Initial,
            Nonce: new byte[12],
            Tag: new byte[16],
            Ciphertext: new byte[10],
            AssociatedData: new byte[5]);

        int keyIdByteCount = Encoding.UTF8.GetByteCount(keyId.Value);
        int requiredSize = 1 + 1 + 2 + keyIdByteCount + 4 + 12 + 16 + 4 + 5 + 4 + 10;

        // Buffer of requiredSize - 1 must fail
        byte[] tooSmallExact = new byte[requiredSize - 1];
        Assert.False(serializer.TrySerialize(envelope, tooSmallExact, out var writtenSmall));
        Assert.Equal(0, writtenSmall);

        // Buffer of exact requiredSize must succeed
        byte[] exactBuffer = new byte[requiredSize];
        Assert.True(serializer.TrySerialize(envelope, exactBuffer, out var writtenExact));
        Assert.Equal(requiredSize, writtenExact);
    }

    [Fact]
    public void BinarySerializer_Deserialize_MalformedPayloads_HandledSafely()
    {
        var serializer = BinarySecurityEnvelopeSerializer.Shared;

        // 1. Payload less than MinHeaderSize (44 bytes)
        var shortPayload = new byte[43];
        var resShort = serializer.Deserialize(shortPayload);
        Assert.True(resShort.IsFailure);
        Assert.Equal("Security.InvalidCiphertext", resShort.Error.Code);

        // 2. Unsupported format version (!= 1)
        var invalidVersionPayload = new byte[50];
        invalidVersionPayload[0] = 2; // unknown format version
        var resVer = serializer.Deserialize(invalidVersionPayload);
        Assert.True(resVer.IsFailure);
        Assert.Contains("Unsupported envelope format version", resVer.Error.Description);

        // 3. Unknown algorithm ID
        var invalidAlgoPayload = new byte[50];
        invalidAlgoPayload[0] = 1;
        invalidAlgoPayload[1] = 100; // unknown algo
        var resAlgo = serializer.Deserialize(invalidAlgoPayload);
        Assert.True(resAlgo.IsFailure);
        Assert.Equal("Security.UnsupportedAlgorithm", resAlgo.Error.Code);
        Assert.Contains("Unknown AEAD algorithm ID", resAlgo.Error.Description);

        // Prepare a valid serialized envelope to tamper with specific fields
        var validEnvelope = new SecurityEnvelope(
            FormatVersion: 1,
            Algorithm: AeadAlgorithm.Aes256Gcm,
            KeyId: KeyIdentifier.New(),
            KeyVersion: KeyVersion.Initial,
            Nonce: new byte[12],
            Tag: new byte[16],
            Ciphertext: new byte[4],
            AssociatedData: new byte[4]);
        byte[] validBytes = serializer.Serialize(validEnvelope);

        // 4. Truncated KeyId (keyIdByteCount exceeds payload length)
        byte[] tamperedKeyIdLen = (byte[])validBytes.Clone();
        BinaryPrimitives.WriteUInt16LittleEndian(tamperedKeyIdLen.AsSpan(2), 1000);
        var resTruncKeyId = serializer.Deserialize(tamperedKeyIdLen);
        Assert.True(resTruncKeyId.IsFailure);
        Assert.Contains("KeyId truncated", resTruncKeyId.Error.Description);

        // 5. Invalid KeyIdentifier content (e.g. whitespace)
        byte[] tamperedKeyIdContent = serializer.Serialize(validEnvelope);
        ushort keyIdLen = BinaryPrimitives.ReadUInt16LittleEndian(tamperedKeyIdContent.AsSpan(2));
        tamperedKeyIdContent.AsSpan(4, keyIdLen).Fill((byte)' ');
        var resInvalidKeyId = serializer.Deserialize(tamperedKeyIdContent);
        Assert.True(resInvalidKeyId.IsFailure);
        Assert.Contains("Invalid KeyIdentifier", resInvalidKeyId.Error.Description);

        // 6. Invalid KeyVersion (< 1)
        byte[] tamperedKeyVersion = (byte[])validBytes.Clone();
        int keyVersionOffset = 4 + keyIdLen;
        BinaryPrimitives.WriteInt32LittleEndian(tamperedKeyVersion.AsSpan(keyVersionOffset), 0);
        var resInvalidKeyVer = serializer.Deserialize(tamperedKeyVersion);
        Assert.True(resInvalidKeyVer.IsFailure);
        Assert.Contains("KeyVersion must be positive", resInvalidKeyVer.Error.Description);

        BinaryPrimitives.WriteInt32LittleEndian(tamperedKeyVersion.AsSpan(keyVersionOffset), -5);
        var resNegKeyVer = serializer.Deserialize(tamperedKeyVersion);
        Assert.True(resNegKeyVer.IsFailure);

        // 7. Truncation at KeyVersion offset (< 44 bytes fails with minimum header size check)
        var truncAtKeyVer = validBytes.AsSpan(0, keyVersionOffset + 2).ToArray();
        var resTruncKeyVer = serializer.Deserialize(truncAtKeyVer);
        Assert.True(resTruncKeyVer.IsFailure);
        Assert.Contains("less than minimum envelope size", resTruncKeyVer.Error.Description);

        // Exact boundary at end of KeyId (< 44 bytes fails with minimum header size check)
        var exactKeyIdEnd = validBytes.AsSpan(0, keyVersionOffset).ToArray();
        var resExactKeyId = serializer.Deserialize(exactKeyIdEnd);
        Assert.True(resExactKeyId.IsFailure);
        Assert.Contains("less than minimum envelope size", resExactKeyId.Error.Description);

        // 8. Truncation at Nonce offset (50 bytes > 44, fails at Nonce truncated check)
        int nonceOffset = keyVersionOffset + 4;
        var truncAtNonce = validBytes.AsSpan(0, nonceOffset + 6).ToArray();
        var resTruncNonce = serializer.Deserialize(truncAtNonce);
        Assert.True(resTruncNonce.IsFailure);
        Assert.Contains("Nonce truncated", resTruncNonce.Error.Description);

        // Exact boundary at end of KeyVersion (40 bytes payload < 44 fails at minimum envelope size)
        var exactKeyVerEnd = validBytes.AsSpan(0, nonceOffset).ToArray();
        var resExactKeyVer = serializer.Deserialize(exactKeyVerEnd);
        Assert.True(resExactKeyVer.IsFailure);
        Assert.Contains("less than minimum envelope size", resExactKeyVer.Error.Description);

        // 9. Truncation at Tag offset
        int tagOffset = nonceOffset + 12;
        var truncAtTag = validBytes.AsSpan(0, tagOffset + 8).ToArray();
        var resTruncTag = serializer.Deserialize(truncAtTag);
        Assert.True(resTruncTag.IsFailure);
        Assert.Contains("Tag truncated", resTruncTag.Error.Description);

        // Exact boundary at end of Nonce
        var exactNonceEnd = validBytes.AsSpan(0, tagOffset).ToArray();
        var resExactNonce = serializer.Deserialize(exactNonceEnd);
        Assert.True(resExactNonce.IsFailure);
        Assert.Contains("Tag truncated", resExactNonce.Error.Description);

        // 10. Truncation at AssociatedData length offset
        int aadLenOffset = tagOffset + 16;
        var truncAtAadLen = validBytes.AsSpan(0, aadLenOffset + 2).ToArray();
        var resTruncAadLen = serializer.Deserialize(truncAtAadLen);
        Assert.True(resTruncAadLen.IsFailure);
        Assert.Contains("AssociatedData length truncated", resTruncAadLen.Error.Description);

        // Exact boundary at end of Tag
        var exactTagEnd = validBytes.AsSpan(0, aadLenOffset).ToArray();
        var resExactTag = serializer.Deserialize(exactTagEnd);
        Assert.True(resExactTag.IsFailure);
        Assert.Contains("AssociatedData length truncated", resExactTag.Error.Description);

        // 11. Invalid AssociatedData length (< 0 or exceeds payload)
        byte[] tamperedAadLen = (byte[])validBytes.Clone();
        BinaryPrimitives.WriteInt32LittleEndian(tamperedAadLen.AsSpan(aadLenOffset), 5000);
        var resInvalidAad = serializer.Deserialize(tamperedAadLen);
        Assert.True(resInvalidAad.IsFailure);
        Assert.Contains("Invalid AssociatedData length", resInvalidAad.Error.Description);

        BinaryPrimitives.WriteInt32LittleEndian(tamperedAadLen.AsSpan(aadLenOffset), -1);
        var resNegAad = serializer.Deserialize(tamperedAadLen);
        Assert.True(resNegAad.IsFailure);
        Assert.Contains("Invalid AssociatedData length", resNegAad.Error.Description);

        // 12. Truncation at Ciphertext length offset
        int cipherLenOffset = aadLenOffset + 4 + 4;
        var truncAtCipherLen = validBytes.AsSpan(0, cipherLenOffset + 2).ToArray();
        var resTruncCipherLen = serializer.Deserialize(truncAtCipherLen);
        Assert.True(resTruncCipherLen.IsFailure);
        Assert.Contains("Ciphertext length truncated", resTruncCipherLen.Error.Description);

        // Exact boundary at end of AssociatedData
        var exactAadEnd = validBytes.AsSpan(0, cipherLenOffset).ToArray();
        var resExactAad = serializer.Deserialize(exactAadEnd);
        Assert.True(resExactAad.IsFailure);
        Assert.Contains("Ciphertext length truncated", resExactAad.Error.Description);

        // 13. Invalid Ciphertext length (< 0 or exceeds payload)
        byte[] tamperedCipherLen = (byte[])validBytes.Clone();
        BinaryPrimitives.WriteInt32LittleEndian(tamperedCipherLen.AsSpan(cipherLenOffset), 5000);
        var resInvalidCipher = serializer.Deserialize(tamperedCipherLen);
        Assert.True(resInvalidCipher.IsFailure);
        Assert.Contains("Invalid Ciphertext length", resInvalidCipher.Error.Description);

        BinaryPrimitives.WriteInt32LittleEndian(tamperedCipherLen.AsSpan(cipherLenOffset), -1);
        var resNegCipher = serializer.Deserialize(tamperedCipherLen);
        Assert.True(resNegCipher.IsFailure);
        Assert.Contains("Invalid Ciphertext length", resNegCipher.Error.Description);

        // 14. Exact minimal header size (44 bytes payload without AAD or Ciphertext)
        var minEnvelope = new SecurityEnvelope(
            FormatVersion: 1,
            Algorithm: AeadAlgorithm.Aes256Gcm,
            KeyId: KeyIdentifier.New(),
            KeyVersion: KeyVersion.Initial,
            Nonce: new byte[12],
            Tag: new byte[16],
            Ciphertext: ReadOnlyMemory<byte>.Empty,
            AssociatedData: ReadOnlyMemory<byte>.Empty);

        byte[] minSerialized = serializer.Serialize(minEnvelope);
        var resMin = serializer.Deserialize(minSerialized);
        Assert.True(resMin.IsSuccess);
        Assert.Empty(resMin.Value.Ciphertext.ToArray());
        Assert.Empty(resMin.Value.AssociatedData.ToArray());
    }

    [Fact]
    public void BinarySerializer_ExactBoundaryConditions_KillsEqualityMutants()
    {
        var serializer = BinarySecurityEnvelopeSerializer.Shared;

        // 1. MinHeaderSize boundary (44 bytes):
        // 43 bytes -> fails with "less than minimum envelope size"
        var res43 = serializer.Deserialize(new byte[43]);
        Assert.True(res43.IsFailure);
        Assert.Contains("less than minimum envelope size", res43.Error.Description);

        // 44 bytes -> passes the size check and fails with format version error
        var res44 = serializer.Deserialize(new byte[44]);
        Assert.True(res44.IsFailure);
        Assert.Contains("Unsupported envelope format version", res44.Error.Description);

        // 2. KeyId boundary: offset (4) + keyIdByteCount (42) == payload.Length (46 bytes total)
        byte[] payloadAtKeyIdEnd = new byte[46];
        payloadAtKeyIdEnd[0] = 1; // FormatVersion
        payloadAtKeyIdEnd[1] = (byte)AeadAlgorithm.Aes256Gcm;
        BinaryPrimitives.WriteUInt16LittleEndian(payloadAtKeyIdEnd.AsSpan(2), 42);
        for (int i = 4; i < 46; i++) payloadAtKeyIdEnd[i] = (byte)'a';
        var resKeyIdEnd = serializer.Deserialize(payloadAtKeyIdEnd);
        Assert.True(resKeyIdEnd.IsFailure);
        // If offset + keyIdByteCount > payload.Length, it passes KeyId check and fails at KeyVersion truncated
        Assert.Equal("Malformed envelope: KeyVersion truncated.", resKeyIdEnd.Error.Description);

        // 3. KeyVersion boundary: offset (46) + 4 == payload.Length (50 bytes total)
        byte[] payloadAtKeyVerEnd = new byte[50];
        payloadAtKeyIdEnd.CopyTo(payloadAtKeyVerEnd, 0);
        BinaryPrimitives.WriteInt32LittleEndian(payloadAtKeyVerEnd.AsSpan(46), 1); // KeyVersion = 1
        var resKeyVerEnd = serializer.Deserialize(payloadAtKeyVerEnd);
        Assert.True(resKeyVerEnd.IsFailure);
        // If offset + 4 > payload.Length, it passes KeyVersion check and fails at Nonce truncated
        Assert.Equal("Malformed envelope: Nonce truncated.", resKeyVerEnd.Error.Description);

        // 4. AssociatedData length boundary: offset (50 + 12 + 16 = 78) + 4 == payload.Length (82 bytes total)
        byte[] payloadAtAadLenEnd = new byte[82];
        payloadAtKeyVerEnd.CopyTo(payloadAtAadLenEnd, 0);
        // Nonce is 12 bytes (46..58), Tag is 16 bytes (58..74)
        BinaryPrimitives.WriteInt32LittleEndian(payloadAtAadLenEnd.AsSpan(78), 0); // aadLength = 0
        var resAadLenEnd = serializer.Deserialize(payloadAtAadLenEnd);
        Assert.True(resAadLenEnd.IsFailure);
        // If offset + 4 > payload.Length, it passes AAD length check and fails at Ciphertext length truncated
        Assert.Equal("Malformed envelope: Ciphertext length truncated.", resAadLenEnd.Error.Description);

        // 5. Deserialization of envelope with aadLength = 0 must produce null AssociatedData (kills aadLength >= 0 mutant)
        var envelopeNoAad = new SecurityEnvelope(
            FormatVersion: 1,
            Algorithm: AeadAlgorithm.Aes256Gcm,
            KeyId: KeyIdentifier.New(),
            KeyVersion: KeyVersion.Initial,
            Nonce: new byte[12],
            Tag: new byte[16],
            Ciphertext: new byte[10],
            AssociatedData: null);
        var serializedNoAad = serializer.Serialize(envelopeNoAad);
        var roundtripNoAad = serializer.Deserialize(serializedNoAad);
        Assert.True(roundtripNoAad.IsSuccess);
        Assert.True(roundtripNoAad.Value.AssociatedData.IsEmpty);
    }

    [Fact]
    public void BinarySerializer_LargeKeyId_ValidatesMaxUshortBoundaries()
    {
        var serializer = BinarySecurityEnvelopeSerializer.Shared;

        // KeyId of exactly ushort.MaxValue (65535) characters
        string maxUshortKeyId = new('k', ushort.MaxValue);
        var envelopeMax = new SecurityEnvelope(
            FormatVersion: 1,
            Algorithm: AeadAlgorithm.Aes256Gcm,
            KeyId: new KeyIdentifier(maxUshortKeyId),
            KeyVersion: KeyVersion.Initial,
            Nonce: new byte[12],
            Tag: new byte[16],
            Ciphertext: ReadOnlyMemory<byte>.Empty);

        // Small destination buffer fails cleanly on size check
        Span<byte> smallDest = stackalloc byte[10];
        Assert.False(serializer.TrySerialize(envelopeMax, smallDest, out _));

        // Adequate buffer succeeds when keyIdByteCount == ushort.MaxValue (kills keyIdByteCount >= ushort.MaxValue mutant)
        byte[] largeDest = new byte[65600];
        bool success = serializer.TrySerialize(envelopeMax, largeDest, out int written);
        Assert.True(success);
        Assert.True(written > ushort.MaxValue);

        // KeyId exceeding ushort.MaxValue throws in Serialize
        string oversizedKeyId = new('k', ushort.MaxValue + 1);
        var envelopeOversized = new SecurityEnvelope(
            FormatVersion: 1,
            Algorithm: AeadAlgorithm.Aes256Gcm,
            KeyId: new KeyIdentifier(oversizedKeyId),
            KeyVersion: KeyVersion.Initial,
            Nonce: new byte[12],
            Tag: new byte[16],
            Ciphertext: ReadOnlyMemory<byte>.Empty);

        var ex = Assert.Throws<InvalidOperationException>(() => serializer.Serialize(envelopeOversized));
        Assert.Equal("Failed to serialize security envelope to calculated buffer size.", ex.Message);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(4)]
    [InlineData(10)]
    [InlineData(20)]
    public void BinarySerializer_Deserialize_TruncatedHeaderBuffers_ReturnsFailure(int truncatedLength)
    {
        var serializer = BinarySecurityEnvelopeSerializer.Shared;
        byte[] truncated = new byte[truncatedLength];

        var result = serializer.Deserialize(truncated);
        Assert.True(result.IsFailure);
        Assert.Equal("Security.InvalidCiphertext", result.Error.Code);
    }

    [Fact]
    public void BinarySerializer_Deserialize_CiphertextExceedingMaxCiphertextPayloadBytes_ReturnsFailure()
    {
        var serializer = BinarySecurityEnvelopeSerializer.Shared;
        var keyId = KeyIdentifier.New();
        var keyVersion = KeyVersion.Initial;
        var envelope = new SecurityEnvelope(
            FormatVersion: 1,
            Algorithm: AeadAlgorithm.Aes256Gcm,
            KeyId: keyId,
            KeyVersion: keyVersion,
            Nonce: new byte[12],
            Tag: new byte[16],
            Ciphertext: new byte[4]);

        byte[] serialized = serializer.Serialize(envelope);

        // Corrupt the ciphertext length (last 4 bytes of header before ciphertext) to 65 MB
        int lengthOffset = serialized.Length - 4 - 4; // 4 bytes of ciphertext, 4 bytes of length
        BinaryPrimitives.WriteInt32LittleEndian(serialized.AsSpan(lengthOffset), BinarySecurityEnvelopeSerializer.MaxCiphertextPayloadBytes + 1);

        var result = serializer.Deserialize(serialized);
        Assert.True(result.IsFailure);
        Assert.Equal("Security.InvalidCiphertext", result.Error.Code);
        Assert.Contains("exceeds maximum", result.Error.Description);
    }

    [Fact]
    public void BinarySerializer_Deserialize_SubtleArithmeticTruncations_ReturnsFailureCleanly()
    {
        var serializer = BinarySecurityEnvelopeSerializer.Shared;

        // 1. KeyId truncation with keyIdByteCount = (payload.Length - offset) + 1
        // offset is 4. Let payload length be 45 (>= MinHeaderSize 44). payload.Length - offset = 41. Set keyIdByteCount = 42.
        byte[] keyIdTrunc = new byte[45];
        keyIdTrunc[0] = 1; // version
        keyIdTrunc[1] = (byte)AeadAlgorithm.Aes256Gcm;
        BinaryPrimitives.WriteUInt16LittleEndian(keyIdTrunc.AsSpan(2), 42);
        var resKeyId = serializer.Deserialize(keyIdTrunc);
        Assert.True(resKeyId.IsFailure);
        Assert.Equal("Malformed envelope: KeyId truncated.", resKeyId.Error.Description);

        // 2. AAD truncation with aadLength = (payload.Length - offset) + 1
        // Build valid envelope up to AAD length
        var validKeyId = KeyIdentifier.New();
        var minEnvelope = new SecurityEnvelope(
            FormatVersion: 1,
            Algorithm: AeadAlgorithm.Aes256Gcm,
            KeyId: validKeyId,
            KeyVersion: KeyVersion.Initial,
            Nonce: new byte[12],
            Tag: new byte[16],
            Ciphertext: new byte[4],
            AssociatedData: new byte[4]);
        byte[] serialized = serializer.Serialize(minEnvelope);

        // Find AAD length offset: 4 (header) + keyIdLen + 4 (ver) + 12 (nonce) + 16 (tag)
        int keyIdByteCount = Encoding.UTF8.GetByteCount(validKeyId.Value);
        int aadLenOffset = 4 + keyIdByteCount + 4 + 12 + 16;
        int remainingAtAad = serialized.Length - (aadLenOffset + 4);

        byte[] aadTrunc = (byte[])serialized.Clone();
        BinaryPrimitives.WriteInt32LittleEndian(aadTrunc.AsSpan(aadLenOffset), remainingAtAad + 1);
        var resAad = serializer.Deserialize(aadTrunc);
        Assert.True(resAad.IsFailure);
        Assert.Equal("Malformed envelope: Invalid AssociatedData length.", resAad.Error.Description);

        // 3. Ciphertext truncation with ciphertextLength = (payload.Length - offset) + 1
        int cipherLenOffset = aadLenOffset + 4 + 4; // 4 bytes of AAD
        int remainingAtCipher = serialized.Length - (cipherLenOffset + 4);

        byte[] cipherTrunc = (byte[])serialized.Clone();
        BinaryPrimitives.WriteInt32LittleEndian(cipherTrunc.AsSpan(cipherLenOffset), remainingAtCipher + 1);
        var resCipher = serializer.Deserialize(cipherTrunc);
        Assert.True(resCipher.IsFailure);
        Assert.Contains("Malformed envelope: Invalid Ciphertext length", resCipher.Error.Description);

        // 4. Exact MaxCiphertextPayloadBytes boundary (must succeed when payload has exactly MaxCiphertextPayloadBytes)
        int headerPrefixLen = cipherLenOffset + 4;
        byte[] maxCipherTest = new byte[headerPrefixLen + BinarySecurityEnvelopeSerializer.MaxCiphertextPayloadBytes];
        serialized.AsSpan(0, headerPrefixLen).CopyTo(maxCipherTest);
        BinaryPrimitives.WriteInt32LittleEndian(maxCipherTest.AsSpan(cipherLenOffset), BinarySecurityEnvelopeSerializer.MaxCiphertextPayloadBytes);
        var resMaxCipher = serializer.Deserialize(maxCipherTest);
        Assert.True(resMaxCipher.IsSuccess);
        Assert.Equal(BinarySecurityEnvelopeSerializer.MaxCiphertextPayloadBytes, resMaxCipher.Value.Ciphertext.Length);
    }
}
