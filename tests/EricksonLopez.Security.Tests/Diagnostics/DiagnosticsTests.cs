// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Tests.Diagnostics;

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.Metrics;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using EricksonLopez.Security.Abstractions.Passwords;
using EricksonLopez.Security.Abstractions.Primitives;
using EricksonLopez.Security.Abstractions.Tokens;
using EricksonLopez.Security.Cryptography;
using EricksonLopez.Security.Diagnostics;
using EricksonLopez.Security.KeyManagement;
using EricksonLopez.Security.Passwords;
using EricksonLopez.Security.Tokens;
using Xunit;

public sealed class DiagnosticsTests
{
    [Fact]
    public void SecurityActivitySource_Constants_And_Instance_Match()
    {
        Assert.Equal("EricksonLopez.Security", SecurityActivitySource.SourceName);
        Assert.Equal("1.1.0", SecurityActivitySource.SourceVersion);
        Assert.NotNull(SecurityActivitySource.Instance);
        Assert.Equal("EricksonLopez.Security", SecurityActivitySource.Instance.Name);
        Assert.Equal("1.1.0", SecurityActivitySource.Instance.Version);

        // Activity operation constants
        Assert.Equal("security.encrypt", SecurityActivitySource.EncryptOperation);
        Assert.Equal("security.decrypt", SecurityActivitySource.DecryptOperation);
        Assert.Equal("security.secret.protect", SecurityActivitySource.ProtectSecretOperation);
        Assert.Equal("security.secret.unprotect", SecurityActivitySource.UnprotectSecretOperation);
        Assert.Equal("security.password.hash", SecurityActivitySource.HashPasswordOperation);
        Assert.Equal("security.password.verify", SecurityActivitySource.VerifyPasswordOperation);
        Assert.Equal("security.key.wrap", SecurityActivitySource.WrapKeyOperation);
        Assert.Equal("security.key.unwrap", SecurityActivitySource.UnwrapKeyOperation);

        // Tag keys
        Assert.Equal("security.algorithm", SecurityActivitySource.TagAlgorithm);
        Assert.Equal("security.key.version", SecurityActivitySource.TagKeyVersion);
        Assert.Equal("security.hash.algorithm", SecurityActivitySource.TagHashAlgorithm);
        Assert.Equal("security.result", SecurityActivitySource.TagResult);
        Assert.Equal("security.error.code", SecurityActivitySource.TagErrorCode);
    }

    [Fact]
    public void SecurityActivitySource_ActivityListener_CapturesActivitiesAndTags()
    {
        var startedActivities = new System.Collections.Concurrent.ConcurrentBag<Activity>();

        using var listener = new ActivityListener
        {
            ShouldListenTo = s => s.Name == SecurityActivitySource.SourceName,
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllData,
            ActivityStarted = a => startedActivities.Add(a)
        };
        ActivitySource.AddActivityListener(listener);

        using (var activity = SecurityActivitySource.Instance.StartActivity(SecurityActivitySource.EncryptOperation, ActivityKind.Internal))
        {
            activity?.SetTag(SecurityActivitySource.TagAlgorithm, "aes-256-gcm-diag");
            activity?.SetTag(SecurityActivitySource.TagResult, "success");
        }

        Assert.Contains(startedActivities, a => (string?)a.GetTagItem(SecurityActivitySource.TagAlgorithm) == "aes-256-gcm-diag");
    }

    [Fact]
    public void SecurityMeter_Constants_And_Instruments_Match()
    {
        Assert.Equal("EricksonLopez.Security", SecurityMeter.MeterName);
        Assert.NotNull(SecurityMeter.Instance);
        Assert.Equal("EricksonLopez.Security", SecurityMeter.Instance.Name);
        Assert.Equal("1.1.0", SecurityMeter.Instance.Version);

        // Counter names, units, and descriptions
        Assert.Equal("security.encrypt.total", SecurityMeter.EncryptTotal.Name);
        Assert.Equal("{operations}", SecurityMeter.EncryptTotal.Unit);
        Assert.Equal("Total number of AEAD encryption operations.", SecurityMeter.EncryptTotal.Description);

        Assert.Equal("security.decrypt.total", SecurityMeter.DecryptTotal.Name);
        Assert.Equal("{operations}", SecurityMeter.DecryptTotal.Unit);
        Assert.Equal("Total number of AEAD decryption operations.", SecurityMeter.DecryptTotal.Description);

        Assert.Equal("security.key.rotations_total", SecurityMeter.KeyRotationsTotal.Name);
        Assert.Equal("{rotations}", SecurityMeter.KeyRotationsTotal.Unit);
        Assert.Equal("Total number of cryptographic key rotation events.", SecurityMeter.KeyRotationsTotal.Description);

        Assert.Equal("security.key.revocations_total", SecurityMeter.KeyRevocationsTotal.Name);
        Assert.Equal("{revocations}", SecurityMeter.KeyRevocationsTotal.Unit);
        Assert.Equal("Total number of cryptographic key revocation events.", SecurityMeter.KeyRevocationsTotal.Description);

        Assert.Equal("security.apikey.validations_total", SecurityMeter.ApiKeyValidationsTotal.Name);
        Assert.Equal("{validations}", SecurityMeter.ApiKeyValidationsTotal.Unit);
        Assert.Equal("Total number of API key validation attempts.", SecurityMeter.ApiKeyValidationsTotal.Description);

        Assert.Equal("security.password.verifications_total", SecurityMeter.PasswordVerificationsTotal.Name);
        Assert.Equal("{verifications}", SecurityMeter.PasswordVerificationsTotal.Unit);
        Assert.Equal("Total number of password verification attempts.", SecurityMeter.PasswordVerificationsTotal.Description);

        // Histograms
        Assert.Equal("security.legacypbkdf2.hashing_duration_ms", SecurityMeter.LegacyPbkdf2HashingDurationMs.Name);
        Assert.Equal("ms", SecurityMeter.LegacyPbkdf2HashingDurationMs.Unit);
        Assert.Equal("Duration of LegacyPbkdf2PasswordHasher hashing operations in milliseconds. v1.x substrate: PBKDF2-HMAC-SHA512.", SecurityMeter.LegacyPbkdf2HashingDurationMs.Description);

        Assert.Equal("security.pbkdf2.hashing_duration_ms", SecurityMeter.Pbkdf2HashingDurationMs.Name);
        Assert.Equal("ms", SecurityMeter.Pbkdf2HashingDurationMs.Unit);
        Assert.Equal("Duration of PBKDF2 password hashing operations in milliseconds.", SecurityMeter.Pbkdf2HashingDurationMs.Description);
    }

    [Fact]
    public void SecurityMeter_Instruments_CanRecordMeasurements()
    {
        using var listener = new MeterListener();
        var recorded = new System.Collections.Concurrent.ConcurrentBag<(string InstrumentName, object Value)>();

        listener.InstrumentPublished = (instrument, l) =>
        {
            if (instrument.Meter.Name == SecurityMeter.MeterName)
            {
                l.EnableMeasurementEvents(instrument);
            }
        };

        listener.SetMeasurementEventCallback<long>((inst, val, tags, state) =>
        {
            recorded.Add((inst.Name, val));
        });

        listener.SetMeasurementEventCallback<double>((inst, val, tags, state) =>
        {
            recorded.Add((inst.Name, val));
        });

        listener.Start();

        SecurityMeter.EncryptTotal.Add(1);
        SecurityMeter.DecryptTotal.Add(1);
        SecurityMeter.KeyRotationsTotal.Add(1);
        SecurityMeter.KeyRevocationsTotal.Add(1);
        SecurityMeter.ApiKeyValidationsTotal.Add(1);
        SecurityMeter.PasswordVerificationsTotal.Add(1);
        SecurityMeter.LegacyPbkdf2HashingDurationMs.Record(42.5);
        SecurityMeter.Pbkdf2HashingDurationMs.Record(12.3);

        listener.RecordObservableInstruments();

        Assert.Contains(recorded, r => r.InstrumentName == "security.encrypt.total");
        Assert.Contains(recorded, r => r.InstrumentName == "security.decrypt.total");
        Assert.Contains(recorded, r => r.InstrumentName == "security.key.rotations_total");
        Assert.Contains(recorded, r => r.InstrumentName == "security.key.revocations_total");
        Assert.Contains(recorded, r => r.InstrumentName == "security.apikey.validations_total");
        Assert.Contains(recorded, r => r.InstrumentName == "security.password.verifications_total");
        Assert.Contains(recorded, r => r.InstrumentName == "security.legacypbkdf2.hashing_duration_ms");
        Assert.Contains(recorded, r => r.InstrumentName == "security.pbkdf2.hashing_duration_ms");
    }

    [Fact]
    public void AesGcmEncryptionEngine_Operations_EmitExpectedMetricsAndActivities()
    {
        var recorded = new ConcurrentBag<(string InstrumentName, object Value, Dictionary<string, object?> Tags)>();
        using var meterListener = new MeterListener();
        meterListener.InstrumentPublished = (inst, l) =>
        {
            if (inst.Meter.Name == SecurityMeter.MeterName)
            {
                l.EnableMeasurementEvents(inst);
            }
        };
        meterListener.SetMeasurementEventCallback<long>((inst, val, tags, state) =>
        {
            var dict = new Dictionary<string, object?>(StringComparer.Ordinal);
            foreach (var (k, v) in tags)
            {
                dict[k] = v;
            }
            recorded.Add((inst.Name, val, dict));
        });
        meterListener.Start();

        var stoppedActivities = new ConcurrentBag<Activity>();
        using var activityListener = new ActivityListener
        {
            ShouldListenTo = s => s.Name == SecurityActivitySource.SourceName,
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllData,
            ActivityStopped = a => stoppedActivities.Add(a)
        };
        ActivitySource.AddActivityListener(activityListener);

        byte[] key = new byte[32];
        RandomNumberGenerator.Fill(key);
        byte[] plaintext = Encoding.UTF8.GetBytes("Secret Plaintext Data");

        // 1. Encrypt
        var encResult = AesGcmEncryptionEngine.Shared.Encrypt(plaintext, key);
        Assert.True(encResult.IsSuccess);
        var encrypted = encResult.Value;

        Assert.Contains(recorded, r => r.InstrumentName == "security.encrypt.total" &&
            (string?)r.Tags.GetValueOrDefault(SecurityActivitySource.TagAlgorithm) == "aes-256-gcm");

        Assert.Contains(stoppedActivities, a => a.OperationName == SecurityActivitySource.EncryptOperation &&
            (string?)a.GetTagItem(SecurityActivitySource.TagAlgorithm) == "aes-256-gcm" &&
            (string?)a.GetTagItem(SecurityActivitySource.TagResult) == "success");

        // 2. Decrypt
        byte[] decrypted = new byte[plaintext.Length];
        var decResult = AesGcmEncryptionEngine.Shared.Decrypt(
            encrypted.Ciphertext.Span,
            key,
            encrypted.Nonce.Span,
            encrypted.Tag.Span,
            ReadOnlySpan<byte>.Empty,
            decrypted,
            out int bytesWritten);
        Assert.True(decResult.IsSuccess);
        Assert.Equal(plaintext.Length, bytesWritten);
        Assert.Equal(plaintext, decrypted);

        Assert.Contains(recorded, r => r.InstrumentName == "security.decrypt.total" &&
            (string?)r.Tags.GetValueOrDefault(SecurityActivitySource.TagAlgorithm) == "aes-256-gcm");

        Assert.Contains(stoppedActivities, a => a.OperationName == SecurityActivitySource.DecryptOperation &&
            (string?)a.GetTagItem(SecurityActivitySource.TagAlgorithm) == "aes-256-gcm" &&
            (string?)a.GetTagItem(SecurityActivitySource.TagResult) == "success");

        // 3. Tampered Decrypt
        byte[] tamperedTag = encrypted.Tag.ToArray();
        tamperedTag[0] ^= 0xFF;
        var failResult = AesGcmEncryptionEngine.Shared.Decrypt(
            encrypted.Ciphertext.Span,
            key,
            encrypted.Nonce.Span,
            tamperedTag,
            ReadOnlySpan<byte>.Empty,
            decrypted,
            out _);
        Assert.True(failResult.IsFailure);

        Assert.Contains(stoppedActivities, a => a.OperationName == SecurityActivitySource.DecryptOperation &&
            (string?)a.GetTagItem(SecurityActivitySource.TagResult) == "failure" &&
            (string?)a.GetTagItem(SecurityActivitySource.TagErrorCode) == "AuthenticationTagMismatch");
    }

    [Fact]
    public void PasswordHashers_Operations_EmitExpectedMetricsAndActivities()
    {
        var recordedLongs = new ConcurrentBag<(string InstrumentName, long Value, Dictionary<string, object?> Tags)>();
        var recordedDoubles = new ConcurrentBag<(string InstrumentName, double Value, Dictionary<string, object?> Tags)>();

        using var meterListener = new MeterListener();
        meterListener.InstrumentPublished = (inst, l) =>
        {
            if (inst.Meter.Name == SecurityMeter.MeterName)
            {
                l.EnableMeasurementEvents(inst);
            }
        };
        meterListener.SetMeasurementEventCallback<long>((inst, val, tags, state) =>
        {
            var dict = new Dictionary<string, object?>(StringComparer.Ordinal);
            foreach (var (k, v) in tags)
            {
                dict[k] = v;
            }
            recordedLongs.Add((inst.Name, val, dict));
        });
        meterListener.SetMeasurementEventCallback<double>((inst, val, tags, state) =>
        {
            var dict = new Dictionary<string, object?>(StringComparer.Ordinal);
            foreach (var (k, v) in tags)
            {
                dict[k] = v;
            }
            recordedDoubles.Add((inst.Name, val, dict));
        });
        meterListener.Start();

        var stoppedActivities = new ConcurrentBag<Activity>();
        using var activityListener = new ActivityListener
        {
            ShouldListenTo = s => s.Name == SecurityActivitySource.SourceName,
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllData,
            ActivityStopped = a => stoppedActivities.Add(a)
        };
        ActivitySource.AddActivityListener(activityListener);

        // 1. Pbkdf2PasswordHasher (fast iterations for unit test)
        var pbkdf2 = new Pbkdf2PasswordHasher(iterations: 10_000);
        var hash = pbkdf2.HashPassword("TestPass123!");

        Assert.Contains(recordedDoubles, r => r.InstrumentName == "security.pbkdf2.hashing_duration_ms");
        Assert.Contains(stoppedActivities, a => a.OperationName == SecurityActivitySource.HashPasswordOperation &&
            (string?)a.GetTagItem(SecurityActivitySource.TagHashAlgorithm) == "pbkdf2-sha512" &&
            (string?)a.GetTagItem(SecurityActivitySource.TagResult) == "success");

        var verifySuccess = pbkdf2.VerifyPassword("TestPass123!", hash);
        Assert.Equal(PasswordVerificationResult.Success, verifySuccess);

        Assert.Contains(recordedLongs, r => r.InstrumentName == "security.password.verifications_total" &&
            (string?)r.Tags.GetValueOrDefault(SecurityActivitySource.TagResult) == "success" &&
            (string?)r.Tags.GetValueOrDefault(SecurityActivitySource.TagHashAlgorithm) == "pbkdf2-sha512");

        Assert.Contains(stoppedActivities, a => a.OperationName == SecurityActivitySource.VerifyPasswordOperation &&
            (string?)a.GetTagItem(SecurityActivitySource.TagHashAlgorithm) == "pbkdf2-sha512" &&
            (string?)a.GetTagItem(SecurityActivitySource.TagResult) == "success");

        var verifyFail = pbkdf2.VerifyPassword("WrongPass!", hash);
        Assert.Equal(PasswordVerificationResult.Failed, verifyFail);

        Assert.Contains(recordedLongs, r => r.InstrumentName == "security.password.verifications_total" &&
            (string?)r.Tags.GetValueOrDefault(SecurityActivitySource.TagResult) == "failure" &&
            (string?)r.Tags.GetValueOrDefault(SecurityActivitySource.TagHashAlgorithm) == "pbkdf2-sha512");

        // 2. Argon2idPasswordHasher
        var argon2 = Argon2idPasswordHasher.Default;
        var argonHash = argon2.HashPassword("ArgonPass123!");

        Assert.Contains(stoppedActivities, a => a.OperationName == SecurityActivitySource.HashPasswordOperation &&
            (string?)a.GetTagItem(SecurityActivitySource.TagHashAlgorithm) == "argon2id" &&
            (string?)a.GetTagItem(SecurityActivitySource.TagResult) == "success");

        var argonVerify = argon2.VerifyPassword("ArgonPass123!", argonHash);
        Assert.Equal(PasswordVerificationResult.Success, argonVerify);

        Assert.Contains(recordedLongs, r => r.InstrumentName == "security.password.verifications_total" &&
            (string?)r.Tags.GetValueOrDefault(SecurityActivitySource.TagResult) == "success" &&
            (string?)r.Tags.GetValueOrDefault(SecurityActivitySource.TagHashAlgorithm) == "argon2id");
    }

    [Fact]
    public async Task ApiKeyValidator_ValidateApiKeyAsync_EmitsExpectedMetricsWithResultTags()
    {
        var recordedLongs = new ConcurrentBag<(string InstrumentName, long Value, Dictionary<string, object?> Tags)>();

        using var meterListener = new MeterListener();
        meterListener.InstrumentPublished = (inst, l) =>
        {
            if (inst.Meter.Name == SecurityMeter.MeterName)
            {
                l.EnableMeasurementEvents(inst);
            }
        };
        meterListener.SetMeasurementEventCallback<long>((inst, val, tags, state) =>
        {
            var dict = new Dictionary<string, object?>(StringComparer.Ordinal);
            foreach (var (k, v) in tags)
            {
                dict[k] = v;
            }
            recordedLongs.Add((inst.Name, val, dict));
        });
        meterListener.Start();

        var store = new InMemoryApiKeyStore();
        var hasher = new HmacSha256TokenHasher(new byte[32]);
        var validator = new ApiKeyValidator(store, hasher);

        var keyId = new ApiKeyId("ek_live_key1");
        var hashedSecret = hasher.HashToken("mysecret123");
        var activeKey = new ApiKey(keyId, "owner", "Active", "ek_live_key1_****", hashedSecret, DateTimeOffset.UtcNow, null, null);
        await store.SaveAsync(activeKey);

        var revokedId = new ApiKeyId("ek_live_revoked");
        var revokedKey = new ApiKey(revokedId, "owner", "Revoked", "ek_live_revoked_****", hashedSecret, DateTimeOffset.UtcNow, null, DateTimeOffset.UtcNow);
        await store.SaveAsync(revokedKey);

        var expiredId = new ApiKeyId("ek_live_expired");
        var expiredKey = new ApiKey(expiredId, "owner", "Expired", "ek_live_expired_****", hashedSecret, DateTimeOffset.UtcNow.AddHours(-2), DateTimeOffset.UtcNow.AddHours(-1), null);
        await store.SaveAsync(expiredKey);

        // 1. Null / empty -> invalid
        var res1 = await validator.ValidateApiKeyAsync("");
        Assert.True(res1.IsFailure);

        // 2. Malformed format -> invalid
        var res2 = await validator.ValidateApiKeyAsync("no_underscore");
        Assert.True(res2.IsFailure);

        // 3. Unknown ID -> invalid
        var res3 = await validator.ValidateApiKeyAsync("ek_live_unknown_mysecret123");
        Assert.True(res3.IsFailure);

        // 4. Bad secret -> invalid
        var res4 = await validator.ValidateApiKeyAsync("ek_live_key1_wrongsecret");
        Assert.True(res4.IsFailure);

        // 5. Valid -> success
        var res5 = await validator.ValidateApiKeyAsync("ek_live_key1_mysecret123");
        Assert.True(res5.IsSuccess);

        // 6. Revoked -> revoked
        var res6 = await validator.ValidateApiKeyAsync("ek_live_revoked_mysecret123");
        Assert.True(res6.IsFailure);

        // 7. Expired -> expired
        var res7 = await validator.ValidateApiKeyAsync("ek_live_expired_mysecret123");
        Assert.True(res7.IsFailure);

        var apiKeyMetrics = recordedLongs.Where(r => r.InstrumentName == "security.apikey.validations_total").ToList();
        Assert.Contains(apiKeyMetrics, m => (string?)m.Tags.GetValueOrDefault(SecurityActivitySource.TagResult) == "invalid");
        Assert.Contains(apiKeyMetrics, m => (string?)m.Tags.GetValueOrDefault(SecurityActivitySource.TagResult) == "success");
        Assert.Contains(apiKeyMetrics, m => (string?)m.Tags.GetValueOrDefault(SecurityActivitySource.TagResult) == "revoked");
        Assert.Contains(apiKeyMetrics, m => (string?)m.Tags.GetValueOrDefault(SecurityActivitySource.TagResult) == "expired");
    }

    [Fact]
    public async Task KeyLifecycleManager_Operations_EmitExpectedMetrics()
    {
        var recordedLongs = new ConcurrentBag<(string InstrumentName, long Value, Dictionary<string, object?> Tags)>();

        using var meterListener = new MeterListener();
        meterListener.InstrumentPublished = (inst, l) =>
        {
            if (inst.Meter.Name == SecurityMeter.MeterName)
            {
                l.EnableMeasurementEvents(inst);
            }
        };
        meterListener.SetMeasurementEventCallback<long>((inst, val, tags, state) =>
        {
            var dict = new Dictionary<string, object?>(StringComparer.Ordinal);
            foreach (var (k, v) in tags)
            {
                dict[k] = v;
            }
            recordedLongs.Add((inst.Name, val, dict));
        });
        meterListener.Start();

        var store = new InMemoryKeyStore();
        var manager = new KeyLifecycleManager(store);

        var initialKeyResult = await manager.GenerateAndActivateKeyAsync(KeyPurpose.Encryption);
        Assert.True(initialKeyResult.IsSuccess);
        using var initialKey = initialKeyResult.Value;

        var rotatedKeyResult = await manager.RotateKeyAsync(KeyPurpose.Encryption);
        Assert.True(rotatedKeyResult.IsSuccess);
        using var rotatedKey = rotatedKeyResult.Value;

        Assert.Equal(2, rotatedKey.Metadata.Version.Value);
        Assert.Contains(recordedLongs, r => r.InstrumentName == "security.key.rotations_total" &&
            (int?)r.Tags.GetValueOrDefault(SecurityActivitySource.TagKeyVersion) == 2);

        var revokeResult = await manager.RevokeKeyAsync(rotatedKey.Metadata.KeyId, rotatedKey.Metadata.Version, "Decommissioned");
        Assert.True(revokeResult.IsSuccess);

        Assert.Contains(recordedLongs, r => r.InstrumentName == "security.key.revocations_total" &&
            (int?)r.Tags.GetValueOrDefault(SecurityActivitySource.TagKeyVersion) == 2 &&
            (string?)r.Tags.GetValueOrDefault(SecurityActivitySource.TagResult) == "success");
    }
}
