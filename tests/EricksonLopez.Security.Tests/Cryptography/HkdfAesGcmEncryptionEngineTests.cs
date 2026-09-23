// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Tests.Cryptography;

using System;
using System.Security.Cryptography;
using System.Text;
using AwesomeAssertions;
using EricksonLopez.Security.Abstractions.Cryptography;
using EricksonLopez.Security.Cryptography;
using Xunit;

public sealed class HkdfAesGcmEncryptionEngineTests
{
    [Fact]
    public void HkdfAesGcmEngine_Properties_MatchExpectedConstants()
    {
        var engine = HkdfAesGcmEncryptionEngine.Shared;
        engine.Algorithm.Should().Be(AeadAlgorithm.HkdfAes256Gcm);
        engine.KeySizeBytes.Should().Be(32);
        engine.NonceSizeBytes.Should().Be(12);
        engine.TagSizeBytes.Should().Be(16);
    }

    [Fact]
    public void HkdfAesGcmEngine_EncryptAndDecrypt_RoundtripsSuccessfully()
    {
        var engine = HkdfAesGcmEncryptionEngine.Shared;
        byte[] rootKey = new byte[32];
        RandomNumberGenerator.Fill(rootKey);

        byte[] plaintext = Encoding.UTF8.GetBytes("HKDF-Enhanced AES-GCM Confidential Payload 2026.");
        byte[] aad = Encoding.UTF8.GetBytes("tenant-hkdf-99");

        var encryptResult = engine.Encrypt(plaintext, rootKey, aad);

        encryptResult.IsSuccess.Should().BeTrue();
        var encrypted = encryptResult.Value;
        encrypted.CiphertextLength.Should().Be(plaintext.Length);
        encrypted.TagLength.Should().Be(16);
        encrypted.NonceLength.Should().Be(12);
        encrypted.Nonce.Span.SequenceEqual(new byte[12]).Should().BeFalse();

        byte[] decrypted = new byte[plaintext.Length];
        var decryptResult = engine.Decrypt(
            ciphertext: encrypted.Ciphertext.Span,
            key: rootKey,
            nonce: encrypted.Nonce.Span,
            tag: encrypted.Tag.Span,
            associatedData: aad,
            plaintextDestination: decrypted,
            out int written);

        decryptResult.IsSuccess.Should().BeTrue();
        written.Should().Be(plaintext.Length);
        Encoding.UTF8.GetString(decrypted).Should().Be("HKDF-Enhanced AES-GCM Confidential Payload 2026.");
    }

    [Fact]
    public void HkdfAesGcmEngine_KdfInfoContext_IsBoundToDomainSeparationLabel()
    {
        var engine = HkdfAesGcmEncryptionEngine.Shared;
        byte[] rootKey = new byte[32];
        RandomNumberGenerator.Fill(rootKey);
        byte[] nonce = new byte[12];
        RandomNumberGenerator.Fill(nonce);
        byte[] plaintext = "KnownPayload"u8.ToArray();
        byte[] cipherDest = new byte[plaintext.Length];
        byte[] tagDest = new byte[16];

        var encRes = engine.Encrypt(plaintext, rootKey, nonce, cipherDest, tagDest);
        encRes.IsSuccess.Should().BeTrue();

        // Manually derive expected key with exact domain label "EricksonLopez.Security.HKDF.AES-256-GCM.v1"
        byte[] expectedDerivedKey = new byte[32];
        HKDF.DeriveKey(
            HashAlgorithmName.SHA512,
            ikm: rootKey,
            output: expectedDerivedKey,
            salt: nonce,
            info: "EricksonLopez.Security.HKDF.AES-256-GCM.v1"u8.ToArray());

        // Decrypt using raw AesGcm with expected derived key
        using var rawAes = new AesGcm(expectedDerivedKey, 16);
        byte[] decrypted = new byte[plaintext.Length];
        rawAes.Decrypt(nonce, cipherDest, tagDest, decrypted);
        decrypted.Should().Equal(plaintext);
    }

    [Fact]
    public void HkdfAesGcmEngine_InvalidKeyLength_ReturnsInvalidKeyError()
    {
        var engine = HkdfAesGcmEncryptionEngine.Shared;
        byte[] shortKey = new byte[16];
        byte[] plaintext = [1, 2, 3];

        var encResult = engine.Encrypt(plaintext, shortKey);
        encResult.IsFailure.Should().BeTrue();
        encResult.Error.Code.Should().Be("Security.InvalidKey");

        Span<byte> cipherDest = stackalloc byte[3];
        Span<byte> tagDest = stackalloc byte[16];
        var encSpanResult = engine.Encrypt(plaintext, shortKey, stackalloc byte[12], cipherDest, tagDest);
        encSpanResult.IsFailure.Should().BeTrue();
        encSpanResult.Error.Code.Should().Be("Security.InvalidKey");

        Span<byte> plainDest = stackalloc byte[3];
        var decResult = engine.Decrypt(cipherDest, shortKey, stackalloc byte[12], tagDest, ReadOnlySpan<byte>.Empty, plainDest, out _);
        decResult.IsFailure.Should().BeTrue();
        decResult.Error.Code.Should().Be("Security.InvalidKey");
    }

    [Fact]
    public void HkdfAesGcmEngine_InvalidNonceAndTagLength_ReturnsError()
    {
        var engine = HkdfAesGcmEncryptionEngine.Shared;
        byte[] key = new byte[32];
        RandomNumberGenerator.Fill(key);
        byte[] plaintext = [1, 2, 3, 4];

        // Invalid nonce in span-based Encrypt
        Span<byte> shortNonce = stackalloc byte[8];
        Span<byte> cipherDest = stackalloc byte[4];
        Span<byte> tagDest = stackalloc byte[16];
        var resNonce = engine.Encrypt(plaintext, key, shortNonce, cipherDest, tagDest);
        resNonce.IsFailure.Should().BeTrue();
        resNonce.Error.Code.Should().Be("Security.InvalidNonce");

        // Invalid tag buffer in span-based Encrypt
        Span<byte> validNonce = stackalloc byte[12];
        Span<byte> shortTag = stackalloc byte[8];
        var resTag = engine.Encrypt(plaintext, key, validNonce, cipherDest, shortTag);
        resTag.IsFailure.Should().BeTrue();
        resTag.Error.Code.Should().Be("Security.BufferTooSmall");

        // Small ciphertext destination
        Span<byte> smallCipher = stackalloc byte[2];
        var resSmallCipher = engine.Encrypt(plaintext, key, validNonce, smallCipher, tagDest);
        resSmallCipher.IsFailure.Should().BeTrue();
        resSmallCipher.Error.Code.Should().Be("Security.BufferTooSmall");

        // Decrypt with invalid nonce length
        Span<byte> plainDest = stackalloc byte[4];
        var decNonce = engine.Decrypt(cipherDest, key, shortNonce, tagDest, ReadOnlySpan<byte>.Empty, plainDest, out _);
        decNonce.IsFailure.Should().BeTrue();
        decNonce.Error.Code.Should().Be("Security.InvalidNonce");

        // Decrypt with invalid tag length
        var decTag = engine.Decrypt(cipherDest, key, validNonce, shortTag, ReadOnlySpan<byte>.Empty, plainDest, out _);
        decTag.IsFailure.Should().BeTrue();
        decTag.Error.Code.Should().Be("Security.AuthenticationTagMismatch");

        // Decrypt with small plaintext destination
        Span<byte> smallPlain = stackalloc byte[2];
        var decSmallDest = engine.Decrypt(cipherDest, key, validNonce, tagDest, ReadOnlySpan<byte>.Empty, smallPlain, out _);
        decSmallDest.IsFailure.Should().BeTrue();
        decSmallDest.Error.Code.Should().Be("Security.BufferTooSmall");
        decSmallDest.Error.Description.Should().Contain("Destination buffer");
    }

    [Fact]
    public void HkdfAesGcmEngine_TamperedCiphertext_FailsAuthentication()
    {
        var engine = HkdfAesGcmEncryptionEngine.Shared;
        byte[] key = new byte[32];
        RandomNumberGenerator.Fill(key);

        byte[] plaintext = Encoding.UTF8.GetBytes("Confidential HKDF Data");
        var encrypted = engine.Encrypt(plaintext, key).Value;

        byte[] tamperedCiphertext = encrypted.Ciphertext.ToArray();
        tamperedCiphertext[0] ^= 0xFF;

        byte[] decrypted = new byte[plaintext.Length];

        var decryptResult = engine.Decrypt(
            ciphertext: tamperedCiphertext,
            key: key,
            nonce: encrypted.Nonce.Span,
            tag: encrypted.Tag.Span,
            associatedData: ReadOnlySpan<byte>.Empty,
            plaintextDestination: decrypted,
            out _);

        decryptResult.IsFailure.Should().BeTrue();
        decryptResult.Error.Code.Should().Be("Security.AuthenticationTagMismatch");
    }

    [Fact]
    public void HkdfAesGcmEngine_TamperedAssociatedData_FailsAuthentication()
    {
        var engine = HkdfAesGcmEncryptionEngine.Shared;
        byte[] key = new byte[32];
        RandomNumberGenerator.Fill(key);

        byte[] plaintext = Encoding.UTF8.GetBytes("Confidential HKDF Data");
        byte[] aad = Encoding.UTF8.GetBytes("origin-hkdf-aad");
        var encrypted = engine.Encrypt(plaintext, key, aad).Value;

        byte[] tamperedAad = Encoding.UTF8.GetBytes("tampered-hkdf-aad");
        byte[] decrypted = new byte[plaintext.Length];

        var decryptResult = engine.Decrypt(
            ciphertext: encrypted.Ciphertext.Span,
            key: key,
            nonce: encrypted.Nonce.Span,
            tag: encrypted.Tag.Span,
            associatedData: tamperedAad,
            plaintextDestination: decrypted,
            out _);

        decryptResult.IsFailure.Should().BeTrue();
        decryptResult.Error.Code.Should().Be("Security.AuthenticationTagMismatch");
    }

    [Fact]
    public void HkdfAesGcmEngine_WrongKey_FailsDecryption()
    {
        var engine = HkdfAesGcmEncryptionEngine.Shared;
        byte[] key1 = new byte[32];
        byte[] key2 = new byte[32];
        RandomNumberGenerator.Fill(key1);
        RandomNumberGenerator.Fill(key2);

        byte[] plaintext = Encoding.UTF8.GetBytes("Confidential HKDF Data");
        var encrypted = engine.Encrypt(plaintext, key1).Value;

        byte[] decrypted = new byte[plaintext.Length];

        var decryptResult = engine.Decrypt(
            ciphertext: encrypted.Ciphertext.Span,
            key: key2,
            nonce: encrypted.Nonce.Span,
            tag: encrypted.Tag.Span,
            associatedData: ReadOnlySpan<byte>.Empty,
            plaintextDestination: decrypted,
            out _);

        decryptResult.IsFailure.Should().BeTrue();
        decryptResult.Error.Code.Should().Be("Security.AuthenticationTagMismatch");
    }

    [Fact]
    public void HkdfAesGcmEngine_ZeroAllocationOverload_OperatesCorrectly()
    {
        var engine = HkdfAesGcmEncryptionEngine.Shared;
        Span<byte> key = stackalloc byte[32];
        Span<byte> nonce = stackalloc byte[12];
        RandomNumberGenerator.Fill(key);
        RandomNumberGenerator.Fill(nonce);

        byte[] plaintext = Encoding.UTF8.GetBytes("HKDF AES-GCM span encryption.");
        Span<byte> ciphertext = stackalloc byte[plaintext.Length];
        Span<byte> tag = stackalloc byte[16];

        var encryptResult = engine.Encrypt(plaintext, key, nonce, ciphertext, tag);

        encryptResult.IsSuccess.Should().BeTrue();

        Span<byte> decrypted = stackalloc byte[plaintext.Length];
        var decryptResult = engine.Decrypt(ciphertext, key, nonce, tag, ReadOnlySpan<byte>.Empty, decrypted, out int written);

        decryptResult.IsSuccess.Should().BeTrue();
        written.Should().Be(plaintext.Length);
        decrypted.SequenceEqual(plaintext).Should().BeTrue();
    }

    [Fact]
    public void HkdfAesGcmEngine_PayloadExceedingMaxRecommendedPayloadBytes_ReturnsPayloadTooLargeError()
    {
        var engine = HkdfAesGcmEncryptionEngine.Shared;
        byte[] key = new byte[32];
        RandomNumberGenerator.Fill(key);

        unsafe
        {
            var oversized = new ReadOnlySpan<byte>((void*)1, HkdfAesGcmEncryptionEngine.MaxRecommendedPayloadBytes + 1);
            var encResult = engine.Encrypt(oversized, key);
            encResult.IsFailure.Should().BeTrue();
            encResult.Error.Code.Should().Be("Security.PayloadTooLarge");
            encResult.Error.Description.Should().Contain((HkdfAesGcmEncryptionEngine.MaxRecommendedPayloadBytes + 1).ToString());

            var encSpanResult = engine.Encrypt(oversized, key, nonceDestination: default, ciphertextDestination: default, tagDestination: default);
            encSpanResult.IsFailure.Should().BeTrue();
            encSpanResult.Error.Code.Should().Be("Security.PayloadTooLarge");
            encSpanResult.Error.Description.Should().Contain((HkdfAesGcmEncryptionEngine.MaxRecommendedPayloadBytes + 1).ToString());

            var decResult = engine.Decrypt(oversized, key, stackalloc byte[12], stackalloc byte[16], ReadOnlySpan<byte>.Empty, Span<byte>.Empty, out _);
            decResult.IsFailure.Should().BeTrue();
            decResult.Error.Code.Should().Be("Security.PayloadTooLarge");
            decResult.Error.Description.Should().Contain((HkdfAesGcmEncryptionEngine.MaxRecommendedPayloadBytes + 1).ToString());
        }
    }

    [Fact]
    public void HkdfAesGcmEngine_SpanEncrypt_GeneratesRandomNonce()
    {
        var engine = HkdfAesGcmEncryptionEngine.Shared;
        byte[] key = new byte[32];
        RandomNumberGenerator.Fill(key);

        byte[] plaintext = [1, 2, 3, 4];
        byte[] nonce1 = new byte[12];
        byte[] nonce2 = new byte[12];
        byte[] ciphertext1 = new byte[plaintext.Length];
        byte[] ciphertext2 = new byte[plaintext.Length];
        byte[] tag1 = new byte[16];
        byte[] tag2 = new byte[16];

        var res1 = engine.Encrypt(plaintext, key, nonce1, ciphertext1, tag1);
        res1.IsSuccess.Should().BeTrue();
        nonce1.Any(b => b != 0).Should().BeTrue();

        var res2 = engine.Encrypt(plaintext, key, nonce2, ciphertext2, tag2);
        res2.IsSuccess.Should().BeTrue();
        nonce2.Any(b => b != 0).Should().BeTrue();
        nonce1.SequenceEqual(nonce2).Should().BeFalse();
    }
}
