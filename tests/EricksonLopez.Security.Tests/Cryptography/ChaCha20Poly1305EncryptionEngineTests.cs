// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Tests.Cryptography;

using System;
using System.Security.Cryptography;
using System.Text;
using EricksonLopez.Security.Abstractions.Cryptography;
using EricksonLopez.Security.Cryptography;
using Xunit;

public sealed class ChaCha20Poly1305EncryptionEngineTests
{
    [Fact]
    public void ChaCha20Poly1305_Engine_Properties_MatchExpectedConstants()
    {
        var engine = ChaCha20Poly1305EncryptionEngine.Shared;
        Assert.Equal(AeadAlgorithm.ChaCha20Poly1305, engine.Algorithm);
        Assert.Equal(32, engine.KeySizeBytes);
        Assert.Equal(12, engine.NonceSizeBytes);
        Assert.Equal(16, engine.TagSizeBytes);
        Assert.Equal(ChaCha20Poly1305.IsSupported, ChaCha20Poly1305EncryptionEngine.IsSupported);
    }

    [Fact]
    public void ChaCha20Poly1305_EncryptAndDecrypt_RoundtripsSuccessfully()
    {
        if (!ChaCha20Poly1305EncryptionEngine.IsSupported)
        {
            return;
        }

        var engine = ChaCha20Poly1305EncryptionEngine.Shared;
        byte[] key = new byte[32];
        RandomNumberGenerator.Fill(key);

        byte[] plaintext = Encoding.UTF8.GetBytes("Confidential ChaCha20-Poly1305 payload 2026.");
        byte[] associatedData = Encoding.UTF8.GetBytes("tenant-id:rfc8439");

        var encryptResult = engine.Encrypt(plaintext, key, associatedData);

        Assert.True(encryptResult.IsSuccess);
        var encrypted = encryptResult.Value;
        Assert.Equal(plaintext.Length, encrypted.CiphertextLength);
        Assert.Equal(16, encrypted.TagLength);
        Assert.Equal(12, encrypted.NonceLength);
        Assert.False(encrypted.Nonce.Span.SequenceEqual(new byte[12]));

        byte[] decrypted = new byte[plaintext.Length];
        var decryptResult = engine.Decrypt(
            ciphertext: encrypted.Ciphertext.Span,
            key: key,
            nonce: encrypted.Nonce.Span,
            tag: encrypted.Tag.Span,
            associatedData: associatedData,
            plaintextDestination: decrypted,
            out int bytesWritten);

        Assert.True(decryptResult.IsSuccess);
        Assert.Equal(plaintext.Length, bytesWritten);
        Assert.Equal("Confidential ChaCha20-Poly1305 payload 2026.", Encoding.UTF8.GetString(decrypted));
    }

    [Fact]
    public void ChaCha20Poly1305_InvalidKeyLength_ReturnsInvalidKeyError()
    {
        if (!ChaCha20Poly1305EncryptionEngine.IsSupported)
        {
            return;
        }

        var engine = ChaCha20Poly1305EncryptionEngine.Shared;
        byte[] shortKey = new byte[16];
        byte[] plaintext = [1, 2, 3];

        var encResult = engine.Encrypt(plaintext, shortKey);
        Assert.True(encResult.IsFailure);
        Assert.Equal("Security.InvalidKey", encResult.Error.Code);

        Span<byte> cipherDest = stackalloc byte[3];
        Span<byte> tagDest = stackalloc byte[16];
        var encSpanResult = engine.Encrypt(plaintext, shortKey, stackalloc byte[12], cipherDest, tagDest);
        Assert.True(encSpanResult.IsFailure);
        Assert.Equal("Security.InvalidKey", encSpanResult.Error.Code);

        Span<byte> plainDest = stackalloc byte[3];
        var decResult = engine.Decrypt(cipherDest, shortKey, stackalloc byte[12], tagDest, ReadOnlySpan<byte>.Empty, plainDest, out _);
        Assert.True(decResult.IsFailure);
        Assert.Equal("Security.InvalidKey", decResult.Error.Code);
    }

    [Fact]
    public void ChaCha20Poly1305_InvalidNonceAndTagLength_ReturnsError()
    {
        if (!ChaCha20Poly1305EncryptionEngine.IsSupported)
        {
            return;
        }

        var engine = ChaCha20Poly1305EncryptionEngine.Shared;
        byte[] key = new byte[32];
        RandomNumberGenerator.Fill(key);
        byte[] plaintext = [1, 2, 3, 4];

        // Invalid nonce in span-based Encrypt
        Span<byte> shortNonce = stackalloc byte[8];
        Span<byte> cipherDest = stackalloc byte[4];
        Span<byte> tagDest = stackalloc byte[16];
        var resNonce = engine.Encrypt(plaintext, key, shortNonce, cipherDest, tagDest);
        Assert.True(resNonce.IsFailure);
        Assert.Equal("Security.InvalidNonce", resNonce.Error.Code);

        // Invalid tag buffer in span-based Encrypt
        Span<byte> validNonce = stackalloc byte[12];
        Span<byte> shortTag = stackalloc byte[8];
        var resTag = engine.Encrypt(plaintext, key, validNonce, cipherDest, shortTag);
        Assert.True(resTag.IsFailure);
        Assert.Equal("Security.BufferTooSmall", resTag.Error.Code);

        // Small ciphertext destination
        Span<byte> smallCipher = stackalloc byte[2];
        var resSmallCipher = engine.Encrypt(plaintext, key, validNonce, smallCipher, tagDest);
        Assert.True(resSmallCipher.IsFailure);
        Assert.Equal("Security.BufferTooSmall", resSmallCipher.Error.Code);

        // Decrypt with invalid nonce length
        Span<byte> plainDest = stackalloc byte[4];
        var decNonce = engine.Decrypt(cipherDest, key, shortNonce, tagDest, ReadOnlySpan<byte>.Empty, plainDest, out _);
        Assert.True(decNonce.IsFailure);
        Assert.Equal("Security.InvalidNonce", decNonce.Error.Code);

        // Decrypt with invalid tag length
        var decTag = engine.Decrypt(cipherDest, key, validNonce, shortTag, ReadOnlySpan<byte>.Empty, plainDest, out _);
        Assert.True(decTag.IsFailure);
        Assert.Equal("Security.AuthenticationTagMismatch", decTag.Error.Code);

        // Decrypt with small plaintext destination
        Span<byte> smallPlain = stackalloc byte[2];
        var decSmallDest = engine.Decrypt(cipherDest, key, validNonce, tagDest, ReadOnlySpan<byte>.Empty, smallPlain, out _);
        Assert.True(decSmallDest.IsFailure);
        Assert.Equal("Security.BufferTooSmall", decSmallDest.Error.Code);
        Assert.Contains("Destination buffer", decSmallDest.Error.Description);
    }

    [Fact]
    public void ChaCha20Poly1305_TamperedCiphertext_FailsAuthentication()
    {
        if (!ChaCha20Poly1305EncryptionEngine.IsSupported)
        {
            return;
        }

        var engine = ChaCha20Poly1305EncryptionEngine.Shared;
        byte[] key = new byte[32];
        RandomNumberGenerator.Fill(key);

        byte[] plaintext = Encoding.UTF8.GetBytes("ChaCha data");
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

        Assert.True(decryptResult.IsFailure);
        Assert.Equal("Security.AuthenticationTagMismatch", decryptResult.Error.Code);
    }

    [Fact]
    public void ChaCha20Poly1305_TamperedAssociatedData_FailsAuthentication()
    {
        if (!ChaCha20Poly1305EncryptionEngine.IsSupported)
        {
            return;
        }

        var engine = ChaCha20Poly1305EncryptionEngine.Shared;
        byte[] key = new byte[32];
        RandomNumberGenerator.Fill(key);

        byte[] plaintext = Encoding.UTF8.GetBytes("ChaCha aad data");
        byte[] aad = Encoding.UTF8.GetBytes("tenant-origin");
        var encrypted = engine.Encrypt(plaintext, key, aad).Value;

        byte[] tamperedAad = Encoding.UTF8.GetBytes("tenant-tampered");
        byte[] decrypted = new byte[plaintext.Length];

        var decryptResult = engine.Decrypt(
            ciphertext: encrypted.Ciphertext.Span,
            key: key,
            nonce: encrypted.Nonce.Span,
            tag: encrypted.Tag.Span,
            associatedData: tamperedAad,
            plaintextDestination: decrypted,
            out _);

        Assert.True(decryptResult.IsFailure);
        Assert.Equal("Security.AuthenticationTagMismatch", decryptResult.Error.Code);
    }

    [Fact]
    public void ChaCha20Poly1305_WrongKey_FailsDecryption()
    {
        if (!ChaCha20Poly1305EncryptionEngine.IsSupported)
        {
            return;
        }

        var engine = ChaCha20Poly1305EncryptionEngine.Shared;
        byte[] key1 = new byte[32];
        byte[] key2 = new byte[32];
        RandomNumberGenerator.Fill(key1);
        RandomNumberGenerator.Fill(key2);

        byte[] plaintext = Encoding.UTF8.GetBytes("ChaCha wrong key data");
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

        Assert.True(decryptResult.IsFailure);
        Assert.Equal("Security.AuthenticationTagMismatch", decryptResult.Error.Code);
    }

    [Fact]
    public void ChaCha20Poly1305_ZeroAllocationOverload_OperatesCorrectly()
    {
        if (!ChaCha20Poly1305EncryptionEngine.IsSupported)
        {
            return;
        }

        var engine = ChaCha20Poly1305EncryptionEngine.Shared;
        Span<byte> key = stackalloc byte[32];
        Span<byte> nonce = stackalloc byte[12];
        RandomNumberGenerator.Fill(key);
        RandomNumberGenerator.Fill(nonce);

        byte[] plaintext = Encoding.UTF8.GetBytes("ChaCha span encryption.");
        Span<byte> ciphertext = stackalloc byte[plaintext.Length];
        Span<byte> tag = stackalloc byte[16];

        var encryptResult = engine.Encrypt(plaintext, key, nonce, ciphertext, tag);

        Assert.True(encryptResult.IsSuccess);

        Span<byte> decrypted = stackalloc byte[plaintext.Length];
        var decryptResult = engine.Decrypt(ciphertext, key, nonce, tag, ReadOnlySpan<byte>.Empty, decrypted, out int written);

        Assert.True(decryptResult.IsSuccess);
        Assert.Equal(plaintext.Length, written);
        Assert.True(decrypted.SequenceEqual(plaintext));
    }

    [Fact]
    public void ChaCha20Poly1305_PayloadExceedingMaxRecommendedPayloadBytes_ReturnsPayloadTooLargeError()
    {
        if (!ChaCha20Poly1305EncryptionEngine.IsSupported)
        {
            return;
        }

        var engine = ChaCha20Poly1305EncryptionEngine.Shared;
        byte[] key = new byte[32];
        RandomNumberGenerator.Fill(key);

        unsafe
        {
            var oversized = new ReadOnlySpan<byte>((void*)1, ChaCha20Poly1305EncryptionEngine.MaxRecommendedPayloadBytes + 1);
            var encResult = engine.Encrypt(oversized, key);
            Assert.True(encResult.IsFailure);
            Assert.Equal("Security.PayloadTooLarge", encResult.Error.Code);
            Assert.Contains((ChaCha20Poly1305EncryptionEngine.MaxRecommendedPayloadBytes + 1).ToString(), encResult.Error.Description);

            var encSpanResult = engine.Encrypt(oversized, key, nonceDestination: default, ciphertextDestination: default, tagDestination: default);
            Assert.True(encSpanResult.IsFailure);
            Assert.Equal("Security.PayloadTooLarge", encSpanResult.Error.Code);
            Assert.Contains((ChaCha20Poly1305EncryptionEngine.MaxRecommendedPayloadBytes + 1).ToString(), encSpanResult.Error.Description);

            var decResult = engine.Decrypt(oversized, key, stackalloc byte[12], stackalloc byte[16], ReadOnlySpan<byte>.Empty, Span<byte>.Empty, out _);
            Assert.True(decResult.IsFailure);
            Assert.Equal("Security.PayloadTooLarge", decResult.Error.Code);
            Assert.Contains((ChaCha20Poly1305EncryptionEngine.MaxRecommendedPayloadBytes + 1).ToString(), decResult.Error.Description);
        }
    }

    [Fact]
    public void ChaCha20Poly1305_WhenPlatformNotSupported_ReturnsUnsupportedAlgorithmError()
    {
        try
        {
            ChaCha20Poly1305EncryptionEngine.s_isSupportedOverride = false;
            var engine = ChaCha20Poly1305EncryptionEngine.Shared;
            byte[] key = new byte[32];
            byte[] nonce = new byte[12];
            byte[] tag = new byte[16];

            var enc1 = engine.Encrypt(ReadOnlySpan<byte>.Empty, key);
            Assert.True(enc1.IsFailure);
            Assert.Equal("Security.UnsupportedAlgorithm", enc1.Error.Code);
            Assert.Equal("ChaCha20-Poly1305 is not supported on the current platform.", enc1.Error.Description);

            var enc2 = engine.Encrypt(ReadOnlySpan<byte>.Empty, key, nonce, Span<byte>.Empty, tag);
            Assert.True(enc2.IsFailure);
            Assert.Equal("Security.UnsupportedAlgorithm", enc2.Error.Code);
            Assert.Equal("ChaCha20-Poly1305 is not supported on the current platform.", enc2.Error.Description);

            var dec = engine.Decrypt(ReadOnlySpan<byte>.Empty, key, nonce, tag, ReadOnlySpan<byte>.Empty, Span<byte>.Empty, out _);
            Assert.True(dec.IsFailure);
            Assert.Equal("Security.UnsupportedAlgorithm", dec.Error.Code);
            Assert.Equal("ChaCha20-Poly1305 is not supported on the current platform.", dec.Error.Description);
        }
        finally
        {
            ChaCha20Poly1305EncryptionEngine.s_isSupportedOverride = null;
        }
    }
}

