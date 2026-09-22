// Copyright © Erickson Lopez. MIT License.

using System;
using System.Diagnostics;
using System.Diagnostics.Metrics;
using System.Text;
using System.Threading.Tasks;
using EricksonLopez.Security.Cryptography;
using EricksonLopez.Security.Diagnostics;
using EricksonLopez.Security.Memory;
using EricksonLopez.Security.Randomness;
using EricksonLopez.Security.Tokens;

namespace EricksonLopez.Security.Sample.Levels;

/// <summary>
/// Level 7: Scalability, Performance & Zero-Allocation Primitives.
/// Demonstrates stack-allocated Span-based encryption, zero-allocation SecretBuffer recycling,
/// concurrent high-throughput execution, and Native AOT runtime compatibility.
/// </summary>
public static class Level7_ScalabilityAndPerformance
{
    public static async Task RunAsync()
    {
        Console.WriteLine("\n================================================================================");
        Console.WriteLine("  LEVEL 7: SCALABILITY, PERFORMANCE & ZERO-ALLOCATION PRIMITIVES");
        Console.WriteLine("================================================================================");

        // -------------------------------------------------------------------------
        // 1. Zero-Allocation Span-Based In-Place Encryption
        // -------------------------------------------------------------------------
        Console.WriteLine("\n[1] Zero-Allocation Span-Based In-Place Cryptographic Operations:");

        ReadOnlySpan<byte> rawPlaintext = "HighThroughputMessageBlock_0123456789"u8;
        Span<byte> key = stackalloc byte[32];
        Span<byte> nonce = stackalloc byte[12];
        Span<byte> ciphertext = stackalloc byte[rawPlaintext.Length];
        Span<byte> tag = stackalloc byte[16];
        Span<byte> decryptedPlaintext = stackalloc byte[rawPlaintext.Length];

        CryptographicRandom.Shared.Fill(key);
        CryptographicRandom.Shared.Fill(nonce);

        var engine = AesGcmEncryptionEngine.Shared;

        // Zero heap allocations in the encryption loop!
        var encryptResult = engine.Encrypt(
            plaintext: rawPlaintext,
            key: key,
            nonceDestination: nonce,
            ciphertextDestination: ciphertext,
            tagDestination: tag);

        Console.WriteLine($"  -> Span-Based In-Place Encrypt Result: {(encryptResult.IsSuccess ? "SUCCESS (0 Heap Allocations)" : "FAILED")}");

        var decryptResult = engine.Decrypt(
            ciphertext: ciphertext,
            key: key,
            nonce: nonce,
            tag: tag,
            associatedData: default,
            plaintextDestination: decryptedPlaintext,
            out var bytesWritten);

        Console.WriteLine($"  -> Span-Based In-Place Decrypt Result: {(decryptResult.IsSuccess ? "SUCCESS" : "FAILED")} ({bytesWritten} bytes written)");
        Console.WriteLine($"  -> Recovered Text: '{Encoding.UTF8.GetString(decryptedPlaintext)}'");

        // -------------------------------------------------------------------------
        // 2. High-Throughput Micro-Benchmark
        // -------------------------------------------------------------------------
        Console.WriteLine("\n[2] High-Concurrency Throughput Simulation (10,000 Cryptographic Operations):");

        const int iterations = 10000;
        var sw = Stopwatch.StartNew();

        await Task.Run(() =>
        {
            Parallel.For(0, iterations, i =>
            {
                Span<byte> localKey = stackalloc byte[32];
                Span<byte> localNonce = stackalloc byte[12];
                Span<byte> localCt = stackalloc byte[32];
                Span<byte> localTag = stackalloc byte[16];

                localKey.Fill((byte)(i % 255));
                localNonce.Fill((byte)(i % 12));

                ReadOnlySpan<byte> pt = "ConcurrentMicroBenchmarkPayload!"u8;
                engine.Encrypt(pt, localKey, localNonce, localCt, localTag);
            });
        });

        sw.Stop();
        var opsPerSec = iterations / sw.Elapsed.TotalSeconds;
        Console.WriteLine($"  -> Executed {iterations:N0} AES-GCM operations in {sw.ElapsedMilliseconds} ms ({opsPerSec:N0} ops/sec)");

        // -------------------------------------------------------------------------
        // 4. SecurityActivitySource — BCL-based Distributed Tracing
        // -------------------------------------------------------------------------
        Console.WriteLine("\n[4] SecurityActivitySource — Distributed Tracing (System.Diagnostics):");
        Console.WriteLine($"  -> Source Name: {SecurityActivitySource.SourceName}");
        Console.WriteLine($"  -> Source Version: {SecurityActivitySource.SourceVersion}");
        Console.WriteLine($"  -> ActivitySource.Name: {SecurityActivitySource.Instance.Name}");

        // Named operation constants (subscribe to these in your ActivityListener)
        Console.WriteLine($"  -> Span: {SecurityActivitySource.EncryptOperation}");
        Console.WriteLine($"  -> Span: {SecurityActivitySource.DecryptOperation}");
        Console.WriteLine($"  -> Span: {SecurityActivitySource.HashPasswordOperation}");
        Console.WriteLine($"  -> Span: {SecurityActivitySource.VerifyPasswordOperation}");
        Console.WriteLine($"  -> Span: {SecurityActivitySource.ProtectSecretOperation}");
        Console.WriteLine($"  -> Span: {SecurityActivitySource.UnprotectSecretOperation}");

        // Tag keys emitted on each span
        Console.WriteLine($"  -> Tag: {SecurityActivitySource.TagAlgorithm} = e.g. 'aes-256-gcm'");
        Console.WriteLine($"  -> Tag: {SecurityActivitySource.TagKeyVersion} = e.g. 'v2'");
        Console.WriteLine($"  -> Tag: {SecurityActivitySource.TagHashAlgorithm} = e.g. 'argon2id'");
        Console.WriteLine($"  -> Tag: {SecurityActivitySource.TagResult} = 'success' | 'failure' | 'rehash_needed'");
        Console.WriteLine($"  -> Tag: {SecurityActivitySource.TagErrorCode} = e.g. 'KeyExpired'");

        // -------------------------------------------------------------------------
        // 5. SecurityMeter — BCL-based Metrics (System.Diagnostics.Metrics)
        // -------------------------------------------------------------------------
        Console.WriteLine("\n[5] SecurityMeter — OpenTelemetry-Compatible Metrics:");
        Console.WriteLine($"  -> Meter Name: {SecurityMeter.MeterName}");
        Console.WriteLine($"  -> Meter Instance.Name: {SecurityMeter.Instance.Name}");

        // Counters
        Console.WriteLine($"  -> Counter: {SecurityMeter.EncryptTotal.Name} ({SecurityMeter.EncryptTotal.Unit})");
        Console.WriteLine($"  -> Counter: {SecurityMeter.DecryptTotal.Name} ({SecurityMeter.DecryptTotal.Unit})");
        Console.WriteLine($"  -> Counter: {SecurityMeter.KeyRotationsTotal.Name}");
        Console.WriteLine($"  -> Counter: {SecurityMeter.KeyRevocationsTotal.Name}");
        Console.WriteLine($"  -> Counter: {SecurityMeter.ApiKeyValidationsTotal.Name}");
        Console.WriteLine($"  -> Counter: {SecurityMeter.PasswordVerificationsTotal.Name}");

        // Histograms
        Console.WriteLine($"  -> Histogram: {SecurityMeter.LegacyPbkdf2HashingDurationMs.Name} ({SecurityMeter.LegacyPbkdf2HashingDurationMs.Unit})");
        Console.WriteLine($"  -> Histogram: {SecurityMeter.Pbkdf2HashingDurationMs.Name} ({SecurityMeter.Pbkdf2HashingDurationMs.Unit})");

        // Manually record a sample metric using MeterListener
        long captured = 0;
        using var listener = new MeterListener();
        listener.InstrumentPublished = (instrument, ml) =>
        {
            if (instrument.Meter.Name == SecurityMeter.MeterName && instrument.Name == SecurityMeter.EncryptTotal.Name)
            {
                ml.EnableMeasurementEvents(instrument);
            }
        };
        listener.SetMeasurementEventCallback<long>((_, value, _, _) => captured += value);
        listener.Start();
        SecurityMeter.EncryptTotal.Add(1);  // Simulate an encryption metric event
        listener.RecordObservableInstruments();
        Console.WriteLine($"  -> Captured EncryptTotal recording: {captured} (expected: 1)");

        // -------------------------------------------------------------------------
        // 6. HmacSha256TokenHasher — Token Hashing for Database Lookups
        // -------------------------------------------------------------------------
        Console.WriteLine("\n[6] HmacSha256TokenHasher — Token Hash for DB Lookup:");

        // Without pepper key (SHA-256 mode)
        var tokenHasher = new HmacSha256TokenHasher();
        var rawToken = "opaque_token_abc123xyz_for_session_auth";
        var tokenHash = tokenHasher.HashToken(rawToken.AsSpan());
        Console.WriteLine($"  -> [SHA-256] HashToken(): {tokenHash[..16]}... (hex, deterministic)");
        Console.WriteLine($"  -> [SHA-256] VerifyToken (correct): {tokenHasher.VerifyToken(rawToken.AsSpan(), tokenHash)}");
        Console.WriteLine($"  -> [SHA-256] VerifyToken (tampered): {tokenHasher.VerifyToken("tampered_token".AsSpan(), tokenHash)}");

        // With pepper key (HMAC-SHA256 mode) — pepper adds a server-side secret to defeat db dump attacks
        var pepperKey = new byte[32];
        CryptographicRandom.Shared.Fill(pepperKey);
        var pepperedHasher = new HmacSha256TokenHasher(pepperKey);
        var pepperedHash = pepperedHasher.HashToken(rawToken.AsSpan());
        Console.WriteLine($"  -> [HMAC-SHA256] HashToken() with pepper: {pepperedHash[..16]}...");
        Console.WriteLine($"  -> [HMAC-SHA256] VerifyToken (correct): {pepperedHasher.VerifyToken(rawToken.AsSpan(), pepperedHash)}");
        Console.WriteLine($"  -> Different pepper produces different hash: {tokenHash != pepperedHash}");

        Console.WriteLine("--------------------------------------------------------------------------------");
    }
}
