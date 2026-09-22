// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Cryptography.Tests.Encryption;

using System;
using EricksonLopez.Security.Abstractions.Cryptography;
using EricksonLopez.Security.Cryptography.Encryption;
using EricksonLopez.Security.Cryptography.Randomness;
using AwesomeAssertions;
using Xunit;

public sealed class AesGcmAuthenticatedEncryptionEngineTests
{
    private readonly AesGcmAuthenticatedEncryptionEngine _sut;
    private readonly CryptographicRandomNumberGenerator _random;

    public AesGcmAuthenticatedEncryptionEngineTests()
    {
        _random = new CryptographicRandomNumberGenerator();
        _sut = new AesGcmAuthenticatedEncryptionEngine(_random);
    }

    [Fact]
    public void Properties_MatchAeadStandard()
    {
        _sut.Algorithm.Should().Be(AeadAlgorithm.Aes256Gcm);
        _sut.KeySizeBytes.Should().Be(32);
        _sut.NonceSizeBytes.Should().Be(12);
        _sut.TagSizeBytes.Should().Be(16);
    }

    [Fact]
    public void Encrypt_WithValidKey_ReturnsEncryptedData_And_UniqueNonce()
    {
        var plaintext = "Secret payload"u8;
        var key = new byte[32];
        _random.Fill(key);

        var result1 = _sut.Encrypt(plaintext, key);
        var result2 = _sut.Encrypt(plaintext, key);

        result1.IsSuccess.Should().BeTrue();
        result2.IsSuccess.Should().BeTrue();

        result1.Value.Ciphertext.ToArray().Should().NotBeEmpty();
        result1.Value.Nonce.ToArray().Should().HaveCount(12);
        result1.Value.Tag.ToArray().Should().HaveCount(16);

        // Random nonce ensures different ciphertexts for same plaintext
        result1.Value.Nonce.ToArray().Should().NotBeEquivalentTo(result2.Value.Nonce.ToArray());
        result1.Value.Ciphertext.ToArray().Should().NotBeEquivalentTo(result2.Value.Ciphertext.ToArray());
    }

    [Fact]
    public void Encrypt_WithInvalidKeyLength_ReturnsInvalidKeyError()
    {
        var plaintext = "Secret payload"u8;
        var invalidKey = new byte[16]; // AES-128 is not accepted, requires 32 bytes

        var result = _sut.Encrypt(plaintext, invalidKey);
        result.IsFailure.Should().BeTrue();
        result.Error.Code.Should().Be("Security.InvalidKey");
    }

    [Fact]
    public void Encrypt_SpanOverload_WithValidParameters_Succeeds()
    {
        var plaintext = "Secret payload"u8;
        var key = new byte[32];
        var nonce = new byte[12];
        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[16];
        var aad = "AuthenticatedContext"u8;

        _random.Fill(key);
        _random.Fill(nonce);

        var result = _sut.Encrypt(plaintext, key, nonce, ciphertext, tag, aad);
        result.IsSuccess.Should().BeTrue();

        // Verify decryption roundtrip
        var decrypted = new byte[plaintext.Length];
        var decResult = _sut.Decrypt(ciphertext, key, nonce, tag, aad, decrypted, out var bytesWritten);

        decResult.IsSuccess.Should().BeTrue();
        bytesWritten.Should().Be(plaintext.Length);
        decrypted.Should().BeEquivalentTo(plaintext.ToArray());
    }

    [Fact]
    public void Encrypt_SpanOverload_ValidatesParameterSizes()
    {
        var plaintext = "Secret payload"u8;
        var validKey = new byte[32];
        var validNonce = new byte[12];
        var validTag = new byte[16];
        var validCiphertext = new byte[plaintext.Length];

        // Invalid key
        var res1 = _sut.Encrypt(plaintext, new byte[16], validNonce, validCiphertext, validTag);
        res1.IsFailure.Should().BeTrue();
        res1.Error.Code.Should().Be("Security.InvalidKey");

        // Invalid nonce
        var res2 = _sut.Encrypt(plaintext, validKey, new byte[8], validCiphertext, validTag);
        res2.IsFailure.Should().BeTrue();
        res2.Error.Code.Should().Be("Security.EncryptionFailed");
        res2.Error.Description.Should().Contain("nonce");

        // Invalid tag destination size
        var res3 = _sut.Encrypt(plaintext, validKey, validNonce, validCiphertext, new byte[8]);
        res3.IsFailure.Should().BeTrue();
        res3.Error.Code.Should().Be("Security.EncryptionFailed");
        res3.Error.Description.Should().Contain("tag destination");

        // Ciphertext destination too small
        var res4 = _sut.Encrypt(plaintext, validKey, validNonce, new byte[plaintext.Length - 1], validTag);
        res4.IsFailure.Should().BeTrue();
        res4.Error.Code.Should().Be("Security.EncryptionFailed");
        res4.Error.Description.Should().Contain("Ciphertext destination span is too small");
    }

    [Fact]
    public void Decrypt_ValidatesParameters()
    {
        var validKey = new byte[32];
        var validNonce = new byte[12];
        var validTag = new byte[16];
        var ciphertext = new byte[10];
        var plaintextDest = new byte[10];

        // Invalid key
        var res1 = _sut.Decrypt(ciphertext, new byte[16], validNonce, validTag, default, plaintextDest, out _);
        res1.IsFailure.Should().BeTrue();
        res1.Error.Code.Should().Be("Security.InvalidKey");

        // Invalid nonce
        var res2 = _sut.Decrypt(ciphertext, validKey, new byte[8], validTag, default, plaintextDest, out _);
        res2.IsFailure.Should().BeTrue();
        res2.Error.Code.Should().Be("Security.DecryptionFailed");
        res2.Error.Description.Should().Contain("nonce");

        // Invalid tag
        var res3 = _sut.Decrypt(ciphertext, validKey, validNonce, new byte[8], default, plaintextDest, out _);
        res3.IsFailure.Should().BeTrue();
        res3.Error.Code.Should().Be("Security.DecryptionFailed");
        res3.Error.Description.Should().Contain("authentication tag");

        // Plaintext destination too small
        var res4 = _sut.Decrypt(ciphertext, validKey, validNonce, validTag, default, new byte[ciphertext.Length - 1], out _);
        res4.IsFailure.Should().BeTrue();
        res4.Error.Code.Should().Be("Security.DecryptionFailed");
        res4.Error.Description.Should().Contain("Plaintext destination span is too small");
    }

    [Fact]
    public void Decrypt_WithTamperedCiphertext_ReturnsTagMismatch()
    {
        var plaintext = "Secret payload"u8;
        var key = new byte[32];
        _random.Fill(key);

        var encrypted = _sut.Encrypt(plaintext, key).Value;
        var decryptedBuffer = new byte[plaintext.Length];

        // Tamper with ciphertext
        var tamperedCiphertext = encrypted.Ciphertext.ToArray();
        tamperedCiphertext[0] ^= 0xFF;

        var result = _sut.Decrypt(tamperedCiphertext, key, encrypted.Nonce.Span, encrypted.Tag.Span, default, decryptedBuffer, out var written);

        result.IsFailure.Should().BeTrue();
        result.Error.Code.Should().Be("Security.AuthenticationTagMismatch");
        written.Should().Be(0);
    }

    [Fact]
    public void Decrypt_WithTamperedAad_ReturnsTagMismatch()
    {
        var plaintext = "Secret payload"u8;
        var aad = "HeaderData"u8;
        var key = new byte[32];
        _random.Fill(key);

        var encrypted = _sut.Encrypt(plaintext, key, aad).Value;
        var decryptedBuffer = new byte[plaintext.Length];

        var tamperedAad = "TamperedHeader"u8;
        var result = _sut.Decrypt(encrypted.Ciphertext.Span, key, encrypted.Nonce.Span, encrypted.Tag.Span, tamperedAad, decryptedBuffer, out _);

        result.IsFailure.Should().BeTrue();
        result.Error.Code.Should().Be("Security.AuthenticationTagMismatch");
    }

    [Fact]
    public void Encrypt_SpanWithNonceDestination_GeneratesRandomNonceAndDecodesSuccessfully()
    {
        var plaintext = "Span overload with nonceDestination"u8;
        var key = new byte[32];
        _random.Fill(key);

        Span<byte> nonce1 = stackalloc byte[12];
        Span<byte> cipher1 = stackalloc byte[plaintext.Length];
        Span<byte> tag1 = stackalloc byte[16];

        Span<byte> nonce2 = stackalloc byte[12];
        Span<byte> cipher2 = stackalloc byte[plaintext.Length];
        Span<byte> tag2 = stackalloc byte[16];

        var res1 = _sut.Encrypt(plaintext, key, nonce1, cipher1, tag1);
        var res2 = _sut.Encrypt(plaintext, key, nonce2, cipher2, tag2);

        res1.IsSuccess.Should().BeTrue();
        res2.IsSuccess.Should().BeTrue();

        // Ensure nonces are not zeroed and are unique
        nonce1.ToArray().Should().NotBeEquivalentTo(new byte[12]);
        nonce1.ToArray().Should().NotBeEquivalentTo(nonce2.ToArray());

        // Verify roundtrip decryption
        var decrypted = new byte[plaintext.Length];
        var decRes = _sut.Decrypt(cipher1, key, nonce1, tag1, default, decrypted, out var written);
        decRes.IsSuccess.Should().BeTrue();
        written.Should().Be(plaintext.Length);
        decrypted.Should().BeEquivalentTo(plaintext.ToArray());

        // Test invalid destination sizes for this overload
        Span<byte> shortNonce = stackalloc byte[11];
        var resShortNonce = _sut.Encrypt(plaintext, key, shortNonce, cipher1, tag1);
        resShortNonce.IsFailure.Should().BeTrue();
        resShortNonce.Error.Code.Should().Be("Security.EncryptionFailed");
        resShortNonce.Error.Description.Should().Contain("12-byte nonce destination");

        Span<byte> shortTag = stackalloc byte[15];
        var resShortTag = _sut.Encrypt(plaintext, key, nonce1, cipher1, shortTag);
        resShortTag.IsFailure.Should().BeTrue();
        resShortTag.Error.Code.Should().Be("Security.EncryptionFailed");
        resShortTag.Error.Description.Should().Contain("16-byte tag destination");

        Span<byte> shortCipher = stackalloc byte[plaintext.Length - 1];
        var resShortCipher = _sut.Encrypt(plaintext, key, nonce1, shortCipher, tag1);
        resShortCipher.IsFailure.Should().BeTrue();
        resShortCipher.Error.Code.Should().Be("Security.EncryptionFailed");

        var resInvalidKey = _sut.Encrypt(plaintext, new byte[16], nonce1, cipher1, tag1);
        resInvalidKey.IsFailure.Should().BeTrue();
        resInvalidKey.Error.Code.Should().Be("Security.InvalidKey");
    }
}
