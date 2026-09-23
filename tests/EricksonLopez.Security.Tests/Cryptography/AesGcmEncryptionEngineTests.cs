// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Tests.Cryptography;

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using EricksonLopez.Security.Abstractions.Cryptography;
using EricksonLopez.Security.Cryptography;
using EricksonLopez.Security.Diagnostics;
using Xunit;

[Collection("TelemetryTests")]
[Trait("Category", "Unit")]
public sealed class AesGcmEncryptionEngineTests
{
    [Fact]
    public void AesGcm_Engine_Properties_MatchExpectedConstants()
    {
        var engine = AesGcmEncryptionEngine.Shared;
        Assert.Equal(AeadAlgorithm.Aes256Gcm, engine.Algorithm);
        Assert.Equal(32, engine.KeySizeBytes);
        Assert.Equal(12, engine.NonceSizeBytes);
        Assert.Equal(16, engine.TagSizeBytes);
    }

    [Fact]
    public void AesGcm_EncryptAndDecrypt_RoundtripsSuccessfully_And_RecordsTelemetry()
    {
        var startedActivities = new System.Collections.Concurrent.ConcurrentBag<Activity>();
        using var listener = new ActivityListener
        {
            ShouldListenTo = s => s.Name == SecurityActivitySource.SourceName,
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllData,
            ActivityStarted = a => startedActivities.Add(a)
        };
        ActivitySource.AddActivityListener(listener);

        var engine = AesGcmEncryptionEngine.Shared;
        byte[] key = new byte[32];
        RandomNumberGenerator.Fill(key);

        byte[] plaintext = Encoding.UTF8.GetBytes("Confidential enterprise payload 2026.");
        byte[] associatedData = Encoding.UTF8.GetBytes("tenant-id:42");

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
        Assert.Equal("Confidential enterprise payload 2026.", Encoding.UTF8.GetString(decrypted));

        // Verify telemetry recorded
        Assert.Contains(startedActivities, a => a.OperationName == SecurityActivitySource.EncryptOperation && (string?)a.GetTagItem(SecurityActivitySource.TagAlgorithm) == "aes-256-gcm");
        Assert.Contains(startedActivities, a => a.OperationName == SecurityActivitySource.DecryptOperation && (string?)a.GetTagItem(SecurityActivitySource.TagAlgorithm) == "aes-256-gcm");
    }

    [Fact]
    public void AesGcm_InvalidKeyLength_ReturnsInvalidKeyError()
    {
        var engine = AesGcmEncryptionEngine.Shared;
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
    public void AesGcm_InvalidNonceAndTagLength_ReturnsError()
    {
        var engine = AesGcmEncryptionEngine.Shared;
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
    public void AesGcm_TamperedCiphertext_FailsAuthenticationTagVerification_And_RecordsFailureTelemetry()
    {
        var startedActivities = new System.Collections.Concurrent.ConcurrentBag<Activity>();
        using var listener = new ActivityListener
        {
            ShouldListenTo = s => s.Name == SecurityActivitySource.SourceName,
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllData,
            ActivityStarted = a => startedActivities.Add(a)
        };
        ActivitySource.AddActivityListener(listener);

        var engine = AesGcmEncryptionEngine.Shared;
        byte[] key = new byte[32];
        RandomNumberGenerator.Fill(key);

        byte[] plaintext = Encoding.UTF8.GetBytes("Sensitive data");
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

        // Verify failure telemetry
        Assert.Contains(startedActivities, a => a.OperationName == SecurityActivitySource.DecryptOperation && (string?)a.GetTagItem(SecurityActivitySource.TagResult) == "failure");
    }

    [Fact]
    public void AesGcm_TamperedAssociatedData_FailsAuthentication()
    {
        var engine = AesGcmEncryptionEngine.Shared;
        byte[] key = new byte[32];
        RandomNumberGenerator.Fill(key);

        byte[] plaintext = Encoding.UTF8.GetBytes("Sensitive data");
        byte[] aad = Encoding.UTF8.GetBytes("tenant-a");
        var encrypted = engine.Encrypt(plaintext, key, aad).Value;

        byte[] tamperedAad = Encoding.UTF8.GetBytes("tenant-b");
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
    public void AesGcm_WrongKey_FailsDecryption()
    {
        var engine = AesGcmEncryptionEngine.Shared;
        byte[] key1 = new byte[32];
        byte[] key2 = new byte[32];
        RandomNumberGenerator.Fill(key1);
        RandomNumberGenerator.Fill(key2);

        byte[] plaintext = Encoding.UTF8.GetBytes("Sensitive data");
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
    public void AesGcm_ZeroAllocationOverload_OperatesCorrectly()
    {
        var engine = AesGcmEncryptionEngine.Shared;
        Span<byte> key = stackalloc byte[32];
        Span<byte> nonce = stackalloc byte[12];
        RandomNumberGenerator.Fill(key);
        RandomNumberGenerator.Fill(nonce);

        byte[] plaintext = Encoding.UTF8.GetBytes("Span-based encryption.");
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
    public void AesGcm_RecordsExpectedObservabilityMetrics()
    {
        using var meterListener = new System.Diagnostics.Metrics.MeterListener();
        // Use ConcurrentBag to avoid cross-thread modification: MeterListener fires callbacks on
        // a thread-pool thread while Assert.Contains enumerates on the test thread (flaky under parallelism).
        var capturedMeasurements = new ConcurrentBag<(string Instrument, string? Algorithm)>();
        meterListener.InstrumentPublished = (instrument, listener) =>
        {
            if (instrument.Meter.Name == "EricksonLopez.Security" &&
                (instrument.Name == "security.encrypt.total" || instrument.Name == "security.decrypt.total"))
            {
                listener.EnableMeasurementEvents(instrument);
            }
        };
        meterListener.SetMeasurementEventCallback<long>((instrument, measurement, tags, state) =>
        {
            string? algo = null;
            foreach (var tag in tags)
            {
                if (tag.Key == "security.algorithm")
                {
                    algo = tag.Value?.ToString();
                }
            }
            capturedMeasurements.Add((instrument.Name, algo));
        });
        meterListener.Start();

        var engine = AesGcmEncryptionEngine.Shared;
        byte[] key = new byte[32];
        System.Security.Cryptography.RandomNumberGenerator.Fill(key);
        byte[] plaintext = Encoding.UTF8.GetBytes("Metrics test payload");

        var encrypted = engine.Encrypt(plaintext, key).Value;
        Assert.Contains(capturedMeasurements, m => m.Instrument == "security.encrypt.total" && m.Algorithm == "aes-256-gcm");

        byte[] decrypted = new byte[plaintext.Length];
        engine.Decrypt(encrypted.Ciphertext.Span, key, encrypted.Nonce.Span, encrypted.Tag.Span, ReadOnlySpan<byte>.Empty, decrypted, out _);
        Assert.Contains(capturedMeasurements, m => m.Instrument == "security.decrypt.total" && m.Algorithm == "aes-256-gcm");
    }

    [Fact]
    public void AesGcm_PayloadExceedingMaxRecommendedPayloadBytes_ReturnsPayloadTooLargeError()
    {
        var engine = AesGcmEncryptionEngine.Shared;
        byte[] key = new byte[32];
        RandomNumberGenerator.Fill(key);

        try
        {
            byte[] oversized = GC.AllocateUninitializedArray<byte>(AesGcmEncryptionEngine.MaxRecommendedPayloadBytes + 1);
            var encResult = engine.Encrypt(oversized, key);
            Assert.True(encResult.IsFailure);
            Assert.Equal("Security.PayloadTooLarge", encResult.Error.Code);

            var decResult = engine.Decrypt(oversized, key, stackalloc byte[12], stackalloc byte[16], ReadOnlySpan<byte>.Empty, Span<byte>.Empty, out _);
            Assert.True(decResult.IsFailure);
            Assert.Equal("Security.PayloadTooLarge", decResult.Error.Code);

            // Exact boundary tests (MaxRecommendedPayloadBytes must NOT return PayloadTooLarge)
            var exactSlice = oversized.AsSpan(0, AesGcmEncryptionEngine.MaxRecommendedPayloadBytes);
            var encSpanExact = engine.Encrypt(exactSlice, key, nonceDestination: default, ciphertextDestination: default, tagDestination: default);
            Assert.True(encSpanExact.IsFailure);
            Assert.Equal("Security.InvalidNonce", encSpanExact.Error.Code);

            var decExact = engine.Decrypt(exactSlice, key, nonce: default, tag: default, ReadOnlySpan<byte>.Empty, Span<byte>.Empty, out _);
            Assert.True(decExact.IsFailure);
            Assert.Equal("Security.InvalidNonce", decExact.Error.Code);

            var encExact = engine.Encrypt(exactSlice, key);
            Assert.True(encExact.IsSuccess);
        }
        catch (OutOfMemoryException)
        {
            // Allowed on environments with constrained physical memory
        }
    }
}
