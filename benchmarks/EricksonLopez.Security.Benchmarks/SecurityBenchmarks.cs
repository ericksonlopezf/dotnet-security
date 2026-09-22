// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Benchmarks;

using System;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using BenchmarkDotNet.Attributes;
using EricksonLopez.Security.Abstractions.Cryptography;
using EricksonLopez.Security.Abstractions.Passwords;
using EricksonLopez.Security.Abstractions.Primitives;
using EricksonLopez.Security.Cryptography;
using EricksonLopez.Security.Memory;
using EricksonLopez.Security.Passwords;
using EricksonLopez.Security.Randomness;
using EricksonLopez.Security.Tokens;

/// <summary>
/// Performance and memory allocation benchmarks for EricksonLopez.Security core cryptographic primitives.
/// </summary>
[MemoryDiagnoser]
[SuppressMessage("Performance", "CA1822:Mark members as static", Justification = "BenchmarkDotNet requires instance benchmark methods.")]
public class SecurityBenchmarks
{
    private byte[] _key = null!;
    private byte[] _nonce = null!;
    private byte[] _plaintext = null!;
    private byte[] _ciphertext = null!;
    private byte[] _tag = null!;
    private byte[] _decryptedBuffer = null!;
    private string _password = null!;
    private string _token = null!;
    private byte[] _leftBytes = null!;
    private byte[] _rightBytes = null!;
    private Pbkdf2PasswordHasher _fastPbkdf2 = null!;
    private Pbkdf2PasswordHasher _productionPbkdf2 = null!;
    private LegacyPbkdf2PasswordHasher _legacyPbkdf2 = null!;
    private CompositePasswordHasher _compositeHasher = null!;
    private string _legacyPbkdf2Hash = null!;
    private SecurityEnvelope _envelope = null!;
    private byte[] _serializedEnvelope = null!;
    private byte[] _envelopeDestination = null!;

    [GlobalSetup]
    public void Setup()
    {
        _key = new byte[32];
        _nonce = new byte[12];
        RandomNumberGenerator.Fill(_key);
        RandomNumberGenerator.Fill(_nonce);

        _plaintext = Encoding.UTF8.GetBytes("Realistic JSON confidential payload with 128 bytes of data to benchmark throughput.");
        _ciphertext = new byte[_plaintext.Length];
        _tag = new byte[16];
        _decryptedBuffer = new byte[_plaintext.Length];

        AesGcmEncryptionEngine.Shared.Encrypt(_plaintext, _key, _nonce, _ciphertext, _tag);

        _password = "Password123!Secure";
        _token = "user-refresh-token-session-9876543210";

        _leftBytes = new byte[32];
        _rightBytes = new byte[32];
        RandomNumberGenerator.Fill(_leftBytes);
        Array.Copy(_leftBytes, _rightBytes, 32);

        _fastPbkdf2 = new Pbkdf2PasswordHasher(iterations: 10_000);
        // HARD-003: Production-realistic hasher using the actual 600,000 iteration default
        _productionPbkdf2 = new Pbkdf2PasswordHasher(iterations: 600_000);
        // Fast parameters suitable for benchmark iterations while exercising real legacy algorithms
        _legacyPbkdf2 = new LegacyPbkdf2PasswordHasher(memorySizeKb: 1024, iterations: 1, parallelism: 1);
        _compositeHasher = new CompositePasswordHasher(
            primaryHasher: _legacyPbkdf2,
            additionalHashers: new[] { _fastPbkdf2 });

        _legacyPbkdf2Hash = _fastPbkdf2.HashPassword(_password);

        _envelope = new SecurityEnvelope(
            FormatVersion: SecurityEnvelope.CurrentFormatVersion,
            Algorithm: AeadAlgorithm.Aes256Gcm,
            KeyId: KeyIdentifier.Prefixed("bench"),
            KeyVersion: KeyVersion.Initial,
            Nonce: _nonce,
            Tag: _tag,
            Ciphertext: _ciphertext,
            AssociatedData: Encoding.UTF8.GetBytes("tenant:benchmark-tenant"));

        _serializedEnvelope = BinarySecurityEnvelopeSerializer.Shared.Serialize(_envelope);
        _envelopeDestination = new byte[_serializedEnvelope.Length + 64];
    }

    [Benchmark(Description = "AES-GCM 256-bit Encrypt (Span, Zero-Alloc)")]
    public void AesGcm_Encrypt_Span()
    {
        AesGcmEncryptionEngine.Shared.Encrypt(_plaintext, _key, _nonce, _ciphertext, _tag);
    }

    [Benchmark(Description = "AES-GCM 256-bit Decrypt (Span, Zero-Alloc)")]
    public void AesGcm_Decrypt_Span()
    {
        AesGcmEncryptionEngine.Shared.Decrypt(_ciphertext, _key, _nonce, _tag, ReadOnlySpan<byte>.Empty, _decryptedBuffer, out _);
    }

    [Benchmark(Description = "AES-GCM Parallel Concurrent Throughput (100 ops)")]
    public void AesGcm_Concurrent_Throughput()
    {
        Parallel.For(0, 100, _ =>
        {
            Span<byte> cipher = stackalloc byte[128];
            Span<byte> tag = stackalloc byte[16];
            AesGcmEncryptionEngine.Shared.Encrypt(_plaintext, _key, _nonce, cipher, tag);
        });
    }

    [Benchmark(Description = "PBKDF2-SHA512 Password Hash (10k iters)")]
    public string Pbkdf2_HashPassword()
    {
        return _fastPbkdf2.HashPassword(_password);
    }

    /// <summary>
    /// HARD-003: Benchmark using production-realistic 600,000 PBKDF2-SHA512 iterations.
    /// This benchmark is excluded from fast CI runs by default; it represents real-world hashing cost.
    /// Compare this with <see cref="Pbkdf2_HashPassword"/> (10K iters) to understand the ~60× difference.
    /// </summary>
    [Benchmark(Description = "PBKDF2-SHA512 Password Hash (600K iters — PRODUCTION COST)")]
    public string Pbkdf2_HashPassword_Production()
    {
        return _productionPbkdf2.HashPassword(_password);
    }

    [Benchmark(Description = "LegacyPbkdf2 Password Hash (Fast Config)")]
    public string LegacyPbkdf2_HashPassword()
    {
        return _legacyPbkdf2.HashPassword(_password);
    }

    [Benchmark(Description = "CompositePasswordHasher Verify & Rehash Check")]
    public PasswordVerificationResult Composite_VerifyPassword()
    {
        return _compositeHasher.VerifyPassword(_password, _legacyPbkdf2Hash);
    }

    [Benchmark(Description = "SecurityEnvelope Serialize (Span, Zero-Alloc)")]
    public bool Envelope_Serialize_Span()
    {
        return BinarySecurityEnvelopeSerializer.Shared.TrySerialize(_envelope, _envelopeDestination, out _);
    }

    [Benchmark(Description = "SecurityEnvelope Deserialize (Span)")]
    public EricksonLopez.Result.Result<SecurityEnvelope> Envelope_Deserialize_Span()
    {
        return BinarySecurityEnvelopeSerializer.Shared.Deserialize(_serializedEnvelope);
    }

    [Benchmark(Description = "ConstantTime FixedTimeEquals (32 bytes)")]
    public bool ConstantTime_Compare()
    {
        return ConstantTimeComparer.Shared.FixedTimeEquals(_leftBytes, _rightBytes);
    }

    [Benchmark(Description = "Token Generation (URL-Safe 32 bytes)")]
    public string Token_Generate()
    {
        return OpaqueTokenGenerator.Shared.GenerateUrlSafeToken(32);
    }

    [Benchmark(Description = "Token Hash (SHA-256)")]
    public string Token_Hash()
    {
        return new HmacSha256TokenHasher().HashToken(_token);
    }

    [Benchmark(Description = "SecretBuffer Allocate & Dispose (ZeroMemory)")]
    public void SecretBuffer_RentAndScrub()
    {
        using var buffer = new SecretBuffer(32);
    }
}
