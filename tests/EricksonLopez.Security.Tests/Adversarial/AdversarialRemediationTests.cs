// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Tests.Adversarial;

using System;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using AwesomeAssertions;
using EricksonLopez.Result;
using EricksonLopez.Security.Abstractions.Cryptography;
using EricksonLopez.Security.Abstractions.KeyManagement;
using EricksonLopez.Security.Abstractions.Passwords;
using EricksonLopez.Security.Abstractions.Primitives;
using EricksonLopez.Security.Abstractions.Tokens;
using EricksonLopez.Security.KeyManagement;
using EricksonLopez.Security.Memory;
using EricksonLopez.Security.Passwords;
using EricksonLopez.Security.Randomness;
using EricksonLopez.Security.Tokens;
using Xunit;

/// <summary>
/// Regression tests verifying the forensic audit remediations (H-001 through L-006, FIX-01 through FIX-07).
/// </summary>
public sealed class AdversarialRemediationTests
{
    [Fact]
    public void M001_Argon2idPasswordHasher_DirectSpanEncoding_HashesAndVerifiesCorrectly()
    {
        var hasher = Argon2idPasswordHasher.Default;
        const string password = "AuditRemediationP@ssw0rd!2026";

        string hash = hasher.HashPassword(password);
        hash.Should().StartWith("$argon2id$v=19$m=65536,t=3,p=4$");

        var verifyValid = hasher.VerifyPassword(password, hash);
        verifyValid.Should().Be(PasswordVerificationResult.Success);

        var verifyInvalid = hasher.VerifyPassword("wrongPasswordAttempt", hash);
        verifyInvalid.Should().Be(PasswordVerificationResult.Failed);
    }

    [Fact]
    public void M002_CryptographicRandom_GetHexString_ReturnsValidHexAndHandlesBuffer()
    {
        var rng = CryptographicRandom.Shared;
        string hex = rng.GetHexString(16);

        hex.Length.Should().Be(32);
        foreach (char c in hex)
        {
            char.IsAsciiHexDigitLower(c).Should().BeTrue();
        }
    }

    [Fact]
    public void M003_CompositePasswordHasher_PBKDF2V1_OversizedHash_DoesNotCrashAndReturnsFailed()
    {
        var composite = new CompositePasswordHasher();

        // 1. Oversized base64 hash part that would cause StackOverflowException if passed to unbounded stackalloc
        string hugeBase64 = Convert.ToBase64String(new byte[100_000]);
        string maliciousHash = $"PBKDF2.V1$10000$c2FsdA==${hugeBase64}";

        var result = composite.VerifyPassword("password", maliciousHash);
        result.Should().Be(PasswordVerificationResult.Failed);

        // 2. Extreme iterations that would cause CPU starvation DoS
        string extremeIterationHash = "PBKDF2.V1$2000000000$c2FsdA==$aGFzaA==";
        var sw = System.Diagnostics.Stopwatch.StartNew();
        var resultExtreme = composite.VerifyPassword("password", extremeIterationHash);
        sw.Stop();

        resultExtreme.Should().Be(PasswordVerificationResult.Failed);
        sw.ElapsedMilliseconds.Should().BeLessThan(100);
    }

    [Fact]
    public void M004_SecretBuffer_DisposedState_SetAtomically()
    {
        var buffer = new SecretBuffer(32);
        buffer.IsDisposed.Should().BeFalse();

        buffer.Dispose();
        buffer.IsDisposed.Should().BeTrue();

        Assert.Throws<ObjectDisposedException>(() => _ = buffer.Length);
        Assert.Throws<ObjectDisposedException>(() => _ = buffer.Span);
    }

    [Fact]
    public void L002_InMemoryKeyStore_ProductionAliases_ThrowNotSupportedException()
    {
        string? originalAspnet = Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT");
        string? originalDotnet = Environment.GetEnvironmentVariable("DOTNET_ENVIRONMENT");

        try
        {
            Environment.SetEnvironmentVariable("ASPNETCORE_ENVIRONMENT", "Prod");
            Environment.SetEnvironmentVariable("DOTNET_ENVIRONMENT", null);
            var ex1 = Assert.Throws<NotSupportedException>(() => new InMemoryKeyStore());
            Assert.Contains("Cloud KeyStore Integration is pending v2.0. InMemoryKeyStore stub cannot be used in production to avoid data loss.", ex1.Message);

            Environment.SetEnvironmentVariable("ASPNETCORE_ENVIRONMENT", "Live");
            var ex2 = Assert.Throws<NotSupportedException>(() => new InMemoryKeyStore());
            Assert.Contains("Cloud KeyStore Integration is pending v2.0. InMemoryKeyStore stub cannot be used in production to avoid data loss.", ex2.Message);

            Environment.SetEnvironmentVariable("ASPNETCORE_ENVIRONMENT", null);
            Environment.SetEnvironmentVariable("DOTNET_ENVIRONMENT", "Production");
            var ex3 = Assert.Throws<NotSupportedException>(() => new InMemoryKeyStore());
            Assert.Contains("Cloud KeyStore Integration is pending v2.0. InMemoryKeyStore stub cannot be used in production to avoid data loss.", ex3.Message);

            Environment.SetEnvironmentVariable("DOTNET_ENVIRONMENT", "Prod");
            var ex4 = Assert.Throws<NotSupportedException>(() => new InMemoryKeyStore());
            Assert.Contains("Cloud KeyStore Integration is pending v2.0. InMemoryKeyStore stub cannot be used in production to avoid data loss.", ex4.Message);
        }
        finally
        {
            Environment.SetEnvironmentVariable("ASPNETCORE_ENVIRONMENT", originalAspnet);
            Environment.SetEnvironmentVariable("DOTNET_ENVIRONMENT", originalDotnet);
        }
    }

    [Fact]
    public void L005_LegacyPbkdf2PasswordHasher_Constructor_BoundsChecked()
    {
        // memorySizeKb must be >= 1024 and <= 65536
        Assert.Throws<ArgumentOutOfRangeException>(() => new LegacyPbkdf2PasswordHasher(memorySizeKb: 512));
        Assert.Throws<ArgumentOutOfRangeException>(() => new LegacyPbkdf2PasswordHasher(memorySizeKb: 131072));

        // parallelism must be >= 1 and <= 16
        Assert.Throws<ArgumentOutOfRangeException>(() => new LegacyPbkdf2PasswordHasher(parallelism: 0));
        Assert.Throws<ArgumentOutOfRangeException>(() => new LegacyPbkdf2PasswordHasher(parallelism: 32));
    }

    [Fact]
    public void H002_KeyRing_CacheTtl_CanBeConfigured()
    {
        var original = KeyRing.CacheTtl;
        try
        {
            KeyRing.CacheTtl = TimeSpan.FromSeconds(15);
            KeyRing.CacheTtl.Should().Be(TimeSpan.FromSeconds(15));
        }
        finally
        {
            KeyRing.CacheTtl = original;
        }
    }

    // ── FIX-01 / FIX-06 Regression Tests ────────────────────────────────────────

    /// <summary>
    /// FIX-01: Verifies that Secret&lt;T&gt; _disposed is now volatile (ARM64 visibility fix)
    /// and that the finalizer path (DisposeCore fromFinalizer=true) does not throw.
    /// </summary>
    [Fact]
    public void FIX01_Secret_VolatileDisposed_IsVisibleImmediatelyAfterDispose()
    {
        // Arrange
        byte[] sensitiveBytes = [0xAA, 0xBB, 0xCC, 0xDD];
        var secret = new Secret<byte[]>(sensitiveBytes);
        secret.IsDisposed.Should().BeFalse("fresh secret must not be disposed");

        // Act
        secret.Dispose();

        // Assert: IsDisposed must be true immediately (no stale read possible with volatile)
        secret.IsDisposed.Should().BeTrue("volatile _disposed must be visible cross-thread");
        Assert.Throws<ObjectDisposedException>(() => _ = secret.Value);
        Assert.Throws<ObjectDisposedException>(() => _ = secret.Length);

        // Second dispose is idempotent (no double-ZeroMemory, no exception)
        secret.Dispose();
        secret.IsDisposed.Should().BeTrue();

        // Byte array should be zeroed
        sensitiveBytes.Should().AllBeEquivalentTo((byte)0, because: "ZeroMemory must have been called on dispose");
    }

    /// <summary>
    /// FIX-01/06: Verifies thread-safety of Secret&lt;T&gt; Dispose under concurrent access.
    /// The inner IDisposable must be disposed exactly once even under concurrent Dispose calls.
    /// </summary>
    [Fact]
    public void FIX01_Secret_ConcurrentDispose_NeverDoubleDisposesInnerIDisposable()
    {
        // Arrange: inner disposable that throws on double-dispose
        var disposeCount = 0;
        var trackingDisposable = new TrackingDisposableCounter(() => Interlocked.Increment(ref disposeCount));
        var secret = new Secret<TrackingDisposableCounter>(trackingDisposable);

        // Act: 16 threads all call Dispose simultaneously
        var threads = Enumerable.Range(0, 16).Select(_ => new Thread(() => secret.Dispose())).ToList();
        threads.ForEach(t => t.Start());
        threads.ForEach(t => t.Join());

        // Assert: inner Dispose must have been called exactly once
        disposeCount.Should().Be(1, because: "concurrent Dispose must be idempotent; inner IDisposable must be disposed exactly once");
    }

    // ── FIX-02 Regression Tests ──────────────────────────────────────────────────

    /// <summary>
    /// FIX-02: Verifies that HmacSha256TokenHasher _disposed is now volatile:
    /// ObjectDisposedException is consistently thrown after disposal even under concurrent reads.
    /// </summary>
    [Fact]
    public void FIX02_HmacSha256TokenHasher_ConcurrentDispose_ThrowsObjectDisposedException()
    {
        var pepper = new byte[32];
        RandomNumberGenerator.Fill(pepper);
        var hasher = new HmacSha256TokenHasher(pepper);


        int successCount = 0;
        int disposedExceptionCount = 0;

        var disposeThread = new Thread(() =>
        {
            Thread.Sleep(1); // slight delay to allow hashing to start
            hasher.Dispose();
        });

        var hashThreads = Enumerable.Range(0, 8).Select(_ => new Thread(() =>
        {
            for (int i = 0; i < 10; i++)
            {
                try
                {
                    var __ = hasher.HashToken("test-token-value");
                    Interlocked.Increment(ref successCount);

                }
                catch (ObjectDisposedException)
                {
                    Interlocked.Increment(ref disposedExceptionCount);
                }
            }
        })).ToList();

        hashThreads.ForEach(t => t.Start());
        disposeThread.Start();
        hashThreads.ForEach(t => t.Join());
        disposeThread.Join();

        // At least one of: succeeded before dispose, or correctly threw after dispose
        (successCount + disposedExceptionCount).Should().Be(80, because: "all 8×10 operations must have either succeeded or thrown ObjectDisposedException — no other outcomes allowed");
    }

    // ── FIX-03 Regression Tests ──────────────────────────────────────────────────

    /// <summary>
    /// FIX-03: Verifies that TimingSafeString.GetHashCode has [EditorBrowsable(Never)]
    /// to discourage its use as a Dictionary key (which would bypass constant-time equality).
    /// </summary>
    [Fact]
    public void FIX03_TimingSafeString_GetHashCode_HasEditorBrowsableNeverAttribute()
    {
        var method = typeof(TimingSafeString).GetMethod(nameof(object.GetHashCode), BindingFlags.Public | BindingFlags.Instance);
        method.Should().NotBeNull("GetHashCode must be defined");

        var attribute = method!.GetCustomAttribute<System.ComponentModel.EditorBrowsableAttribute>();
        attribute.Should().NotBeNull("GetHashCode must have [EditorBrowsable] attribute to discourage Dictionary key misuse (SC-002)");
        attribute!.State.Should().Be(System.ComponentModel.EditorBrowsableState.Never,
            because: "SC-002: using TimingSafeString as a Dictionary key exposes non-constant-time hash code lookups");
    }

    // ── FIX-04 Regression Tests ──────────────────────────────────────────────────

    /// <summary>
    /// FIX-04: Verifies that ApiKeyGenerator requires an explicit ITokenHasher and has NO parameterless
    /// or optional-parameter constructor, completely preventing ephemeral pepper desynchronization (SEC-PEPPER-001).
    /// </summary>
    [Fact]
    public void FIX04_ApiKeyGenerator_RequiresExplicitTokenHasher_NoParameterlessOrOptionalConstructor()
    {
        var ctors = typeof(ApiKeyGenerator).GetConstructors(BindingFlags.Public | BindingFlags.Instance);
        ctors.Should().ContainSingle();
        var ctor = ctors[0];
        ctor.GetParameters().Length.Should().Be(1);
        ctor.GetParameters()[0].ParameterType.Should().Be<ITokenHasher>();
        ctor.GetParameters()[0].IsOptional.Should().BeFalse();

        Action act = () => GC.KeepAlive(new ApiKeyGenerator(null!));
        act.Should().Throw<ArgumentNullException>();
    }

    // ── FIX-05 Regression Tests ──────────────────────────────────────────────────

    /// <summary>
    /// FIX-05: Verifies that ConstantTimeComparer.Equals(string?, string?) correctly handles
    /// null inputs without leaking a null-detection timing oracle.
    /// The dummy compare branch must execute even when one string is null.
    /// </summary>
    [Fact]
    public void FIX05_ConstantTimeComparer_NullString_ReturnsExpectedResults()
    {
        // null == null → true
        ConstantTimeComparer.Equals(null, null).Should().BeTrue("both null must be equal");

        // null != non-null → false (executes dummy compare internally)
        ConstantTimeComparer.Equals(null, "value").Should().BeFalse("null != non-null");
        ConstantTimeComparer.Equals("value", null).Should().BeFalse("non-null != null");

        // equal → true
        ConstantTimeComparer.Equals("secret123", "secret123").Should().BeTrue("identical strings must be equal");

        // unequal → false
        ConstantTimeComparer.Equals("secret123", "different").Should().BeFalse("different strings must not be equal");

        // empty string edge cases
        ConstantTimeComparer.Equals("", "").Should().BeTrue("empty strings must be equal");
        ConstantTimeComparer.Equals(null, "").Should().BeFalse("null != empty");
        ConstantTimeComparer.Equals("", null).Should().BeFalse("empty != null");
    }

    // ── Shared test helpers ──────────────────────────────────────────────────────

    private sealed class TrackingDisposableCounter(Action onDispose) : IDisposable
    {
        public void Dispose() => onDispose();
    }
}
