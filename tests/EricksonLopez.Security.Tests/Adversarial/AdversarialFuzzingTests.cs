// Copyright © Erickson Lopez. MIT License.

using System;
using System.Security.Cryptography;
using AwesomeAssertions;
using EricksonLopez.Security.Cryptography;
using EricksonLopez.Security.Mfa;
using EricksonLopez.Security.Passwords;
using EricksonLopez.Security.Abstractions.Passwords;
using EricksonLopez.Security.Randomness;
using Xunit;

namespace EricksonLopez.Security.Tests.Adversarial;

public class AdversarialFuzzingTests
{
    [Fact]
    public void ConstantTimeComparer_Fuzz_10000_Mutations()
    {
        var comparer = ConstantTimeComparer.Shared;
        for (int i = 0; i < 10_000; i++)
        {
            var len = RandomNumberGenerator.GetInt32(1, 128);
            var b1 = new byte[len];
            RandomNumberGenerator.Fill(b1);
            var b2 = (byte[])b1.Clone();

            // 50% identical, 50% mutated
            if (i % 2 == 0)
            {
                comparer.FixedTimeEquals(b1, b2).Should().BeTrue();
            }
            else
            {
                var mutateIdx = RandomNumberGenerator.GetInt32(0, len);
                b2[mutateIdx] ^= 0xFF; // Flip all bits of random byte
                comparer.FixedTimeEquals(b1, b2).Should().BeFalse();
            }
        }
    }

    [Fact]
    public void Pbkdf2PasswordHasher_Fuzz_10000_Malformed_Hashes()
    {
        var hasher = Pbkdf2PasswordHasher.Default;
        var rng = RandomNumberGenerator.Create();

        for (int i = 0; i < 10_000; i++)
        {
            var randomBytes = new byte[RandomNumberGenerator.GetInt32(1, 64)];
            rng.GetBytes(randomBytes);
            var randomStr = Convert.ToBase64String(randomBytes);

            // Construct mutated, distorted, or truncated hash inputs
            string fuzzedHash = (i % 5) switch
            {
                0 => $"$pbkdf2-sha512$i={RandomNumberGenerator.GetInt32(-1000, 10_000_000)}$s={randomStr}${randomStr}",
                1 => $"$pbkdf2-sha512$i=210000$s=invalid!char${randomStr}",
                2 => $"PBKDF2.V1${RandomNumberGenerator.GetInt32(-5, 999_999)}${randomStr}",
                3 => $"$argon2id$v=19$m=65536,t={i},p=4${randomStr}",
                _ => randomStr
            };

            // Fuzzing invariant: No unhandled exceptions, fails safely
            var result = hasher.VerifyPassword("password123", fuzzedHash);
            // Must either fail or (if valid format coincidence) return result cleanly
            Assert.True(result is PasswordVerificationResult.Failed or PasswordVerificationResult.Success or PasswordVerificationResult.SuccessRehashNeeded);
        }
    }

    [Fact]
    public void Base32Encoding_Fuzz_10000_Arbitrary_Inputs()
    {
        for (int i = 0; i < 10_000; i++)
        {
            var randomLen = RandomNumberGenerator.GetInt32(0, 64);
            var randomBytes = new byte[randomLen];
            RandomNumberGenerator.Fill(randomBytes);

            // Roundtrip must always succeed for valid bytes
            var encoded = Base32Encoding.ToBase32String(randomBytes);
            var decoded = Base32Encoding.FromBase32String(encoded);
            decoded.Should().BeEquivalentTo(randomBytes);

            // Mutating a single character to invalid character must throw FormatException cleanly
            if (encoded.Length > 0)
            {
                var chars = encoded.ToCharArray();
                chars[0] = '1'; // '1' is invalid in Base32
                var act = () => Base32Encoding.FromBase32String(new string(chars));
                act.Should().Throw<FormatException>();
            }
        }
    }

    /// <summary>
    /// TEST-03: Binary Envelope Deserializer Fuzz.
    /// Feeds 10,000 random byte arrays of varying lengths (0 to 512 bytes) into
    /// BinarySecurityEnvelopeSerializer.Deserialize. The serializer must NEVER crash,
    /// throw an unhandled exception, or return a successful result for random input.
    /// All random inputs must produce a Result.Failure.
    /// This closes the deserialization fuzz gap identified in 10_DESERIALIZATION_AUDIT.md.
    /// </summary>
    [Fact]
    public void BinarySecurityEnvelope_Fuzz_10000_RandomBytes_NeverCrash()
    {
        var serializer = BinarySecurityEnvelopeSerializer.Shared;
        var rng = RandomNumberGenerator.Create();

        int successCount = 0;
        int failureCount = 0;

        for (int i = 0; i < 10_000; i++)
        {
            // Random length: 0 to 512 bytes (covers empty, tiny, and moderately large inputs)
            var length = RandomNumberGenerator.GetInt32(0, 513);
            var randomBytes = new byte[length];
            rng.GetBytes(randomBytes);

            try
            {
                var result = serializer.Deserialize(randomBytes);
                if (result.IsSuccess)
                {
                    successCount++;
                }
                else
                {
                    failureCount++;
                }
            }
            catch (Exception ex)
            {
                Assert.Fail($"BinarySecurityEnvelopeSerializer.Deserialize threw an unhandled exception on iteration {i}: {ex.GetType().Name}: {ex.Message}");
            }
        }

        // No random byte sequence should successfully deserialize to a valid SecurityEnvelope
        successCount.Should().Be(0,
            "random byte arrays must never deserialize to a valid SecurityEnvelope");
        failureCount.Should().Be(10_000,
            "all 10,000 random byte arrays must produce a Result.Failure");
    }

    /// <summary>
    /// TEST-04: ChaCha20-Poly1305 Tamper Property Test.
    /// Verifies that any single-bit or single-byte mutation of a ChaCha20-Poly1305 ciphertext    /// always causes decryption to fail. This closes the property test gap identified for
    /// ChaCha20 in 14_PROPERTY_TESTING.md — previously only AES-GCM had this property verified.
    /// </summary>
    [Fact]
    public void ChaCha20Poly1305_Fuzz_5000_MutatedCiphertexts_AlwaysFail()
    {
        if (!ChaCha20Poly1305EncryptionEngine.IsSupported)
        {
            return; // Skip on platforms without ChaCha20-Poly1305 support
        }

        var engine = ChaCha20Poly1305EncryptionEngine.Shared;
        var plaintextBytes = System.Text.Encoding.UTF8.GetBytes("ChaCha20-Poly1305 tamper-resistance property test payload.");
        var key = new byte[32];
        RandomNumberGenerator.Fill(key);

        // Encrypt a valid ciphertext to mutate using the span overload
        const int NonceSize = 12;
        const int TagSize = 16;
        var nonce = new byte[NonceSize];
        var ciphertext = new byte[plaintextBytes.Length];
        var tag = new byte[TagSize];

        var encryptResult = engine.Encrypt(plaintextBytes, key, nonce, ciphertext, tag);
        encryptResult.IsSuccess.Should().BeTrue("Setup: ChaCha20 encryption must succeed");

        int decryptSuccessCount = 0;
        var decryptedBuffer = new byte[plaintextBytes.Length];

        for (int i = 0; i < 5_000; i++)
        {
            // Choose a random mutation target: 0 = ciphertext, 1 = tag, 2 = nonce
            var target = RandomNumberGenerator.GetInt32(0, 3);
            byte[] mutatedNonce = (byte[])nonce.Clone();
            byte[] mutatedTag = (byte[])tag.Clone();
            byte[] mutatedCiphertext = (byte[])ciphertext.Clone();

            switch (target)
            {
                case 0 when mutatedCiphertext.Length > 0:
                    var cpos = RandomNumberGenerator.GetInt32(0, mutatedCiphertext.Length);
                    mutatedCiphertext[cpos] ^= 0xFF;
                    break;
                case 1:
                    var tpos = RandomNumberGenerator.GetInt32(0, mutatedTag.Length);
                    mutatedTag[tpos] ^= 0xFF;
                    break;
                default:
                    var npos = RandomNumberGenerator.GetInt32(0, mutatedNonce.Length);
                    mutatedNonce[npos] ^= 0xFF;
                    break;
            }

            try
            {
                var decryptResult = engine.Decrypt(
                    mutatedCiphertext,
                    key,
                    mutatedNonce,
                    mutatedTag,
                    ReadOnlySpan<byte>.Empty,
                    decryptedBuffer,
                    out _);

                if (decryptResult.IsSuccess)
                {
                    decryptSuccessCount++;
                }
            }
            catch (Exception ex)
            {
                Assert.Fail($"ChaCha20 tamper test iteration {i} threw unhandled exception: {ex.GetType().Name}: {ex.Message}");
            }
        }

        decryptSuccessCount.Should().Be(0,
            "ChaCha20-Poly1305 property: any mutation of ciphertext, tag, or nonce must never decrypt successfully");
    }
}
