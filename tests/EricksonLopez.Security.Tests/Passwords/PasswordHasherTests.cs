// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Tests.Passwords;

using System;
using System.Collections.Concurrent;
using System.Diagnostics.Metrics;
using EricksonLopez.Security.Abstractions.Passwords;
using EricksonLopez.Security.Diagnostics;
using EricksonLopez.Security.Passwords;
using Xunit;

public sealed class PasswordHasherTests
{
    private sealed class FakeBcryptPasswordHasher : IPasswordHasher
    {
        public PasswordHashAlgorithm Algorithm => PasswordHashAlgorithm.BCrypt;

        public string HashPassword(ReadOnlySpan<char> password) => "$2a$10$customHash";

        public PasswordVerificationResult VerifyPassword(ReadOnlySpan<char> password, string hashedPassword) =>
            password.SequenceEqual("password") && hashedPassword == "$2a$10$customHash" ? PasswordVerificationResult.Success : PasswordVerificationResult.Failed;

        public bool NeedsRehash(string hashedPassword) => false;
    }

    private sealed class FakeUnknownPasswordHasher : IPasswordHasher
    {
        public PasswordHashAlgorithm Algorithm => (PasswordHashAlgorithm)99;

        public string HashPassword(ReadOnlySpan<char> password) => "$99$customHash";

        public PasswordVerificationResult VerifyPassword(ReadOnlySpan<char> password, string hashedPassword) =>
            hashedPassword == "$99$customHash" ? PasswordVerificationResult.Success : PasswordVerificationResult.Failed;

        public bool NeedsRehash(string hashedPassword) => false;
    }

    private sealed class FakeLegacyPbkdf2PasswordHasher : IPasswordHasher
    {
        public PasswordHashAlgorithm Algorithm => PasswordHashAlgorithm.Argon2id;
        public bool WasCalled { get; private set; }

        public string HashPassword(ReadOnlySpan<char> password) => "$argon2id$custom";

        public PasswordVerificationResult VerifyPassword(ReadOnlySpan<char> password, string hashedPassword)
        {
            WasCalled = true;
            return PasswordVerificationResult.Success;
        }

        public bool NeedsRehash(string hashedPassword) => false;
    }

    // ==========================================
    // Pbkdf2PasswordHasher Tests
    // ==========================================

    [Fact]
    public void Pbkdf2PasswordHasher_Constructor_ValidatesIterations()
    {
        var ex = Assert.Throws<ArgumentOutOfRangeException>(() => new Pbkdf2PasswordHasher(iterations: 9999));
        Assert.Equal("iterations", ex.ParamName);
        Assert.Contains("Iterations must be between 10,000 and 600,000 to prevent DoS.", ex.Message);

        var exHigh = Assert.Throws<ArgumentOutOfRangeException>(() => new Pbkdf2PasswordHasher(iterations: 600_001));
        Assert.Equal("iterations", exHigh.ParamName);
        Assert.Contains("Iterations must be between 10,000 and 600,000 to prevent DoS.", exHigh.Message);

        var validHasher = new Pbkdf2PasswordHasher(iterations: 10_000, saltSizeBytes: 32, derivedKeySizeBytes: 64);
        Assert.Equal(PasswordHashAlgorithm.Pbkdf2HmacSha512, validHasher.Algorithm);
        Assert.NotNull(Pbkdf2PasswordHasher.Default);
        Assert.Equal(210_000, Pbkdf2PasswordHasher.DefaultIterations);
    }

    [Fact]
    public void Pbkdf2PasswordHasher_HashAndVerify_SucceedsForMatchingPassword()
    {
        var hasher = new Pbkdf2PasswordHasher(iterations: 10_000);
        var password = "CorrectHorseBatteryStaple!";

        var hash = hasher.HashPassword(password);
        var secondHash = hasher.HashPassword(password);
        Assert.NotEqual(hash, secondHash);

        var verifySuccess = hasher.VerifyPassword(password, hash);
        var verifyWrong = hasher.VerifyPassword("WrongPassword!", hash);

        Assert.StartsWith("$pbkdf2-sha512$", hash, StringComparison.Ordinal);
        Assert.Equal(PasswordVerificationResult.Success, verifySuccess);
        Assert.Equal(PasswordVerificationResult.Failed, verifyWrong);
    }

    [Fact]
    public void Pbkdf2PasswordHasher_VerifyPassword_MalformedHashes_ReturnsFailed()
    {
        var hasher = new Pbkdf2PasswordHasher(iterations: 10_000);
        var pwd = "password";

        Assert.Equal(PasswordVerificationResult.Failed, hasher.VerifyPassword(pwd, ""));
        Assert.Equal(PasswordVerificationResult.Failed, hasher.VerifyPassword(pwd, "   "));
        Assert.Equal(PasswordVerificationResult.Failed, hasher.VerifyPassword(pwd, null!));
        Assert.Equal(PasswordVerificationResult.Failed, hasher.VerifyPassword(pwd, "$argon2id$v=19$m=65536$salt$hash"));
        Assert.Equal(PasswordVerificationResult.Failed, hasher.VerifyPassword(pwd, "$pbkdf2-sha512$i=10000$s=onlyThreeParts"));
        Assert.Equal(PasswordVerificationResult.Failed, hasher.VerifyPassword(pwd, "$pbkdf2-sha512$notAnIteration$s=c2FsdA==$aGFzaA=="));
        Assert.Equal(PasswordVerificationResult.Failed, hasher.VerifyPassword(pwd, "$pbkdf2-sha512$x=210000$s=c2FsdA==$aGFzaA=="));
        Assert.Equal(PasswordVerificationResult.Failed, hasher.VerifyPassword(pwd, "$pbkdf2-sha512$i=notANumber$s=c2FsdA==$aGFzaA=="));
        Assert.Equal(PasswordVerificationResult.Failed, hasher.VerifyPassword(pwd, "$pbkdf2-sha512$i=10000$notSalt$aGFzaA=="));
        Assert.Equal(PasswordVerificationResult.Failed, hasher.VerifyPassword(pwd, "$pbkdf2-sha512$i=10000$x=c2FsdA==$aGFzaA=="));
        Assert.Equal(PasswordVerificationResult.Failed, hasher.VerifyPassword(pwd, "$pbkdf2-sha512$i=10000$s=notBase64!@#$aGFzaA=="));
        Assert.Equal(PasswordVerificationResult.Failed, hasher.VerifyPassword(pwd, "$pbkdf2-sha512$i=10000$s=c2FsdA==$notBase64!@#"));

        // Corrupted tag prefixes on genuine valid hashes fail verification
        var validHash = hasher.HashPassword(pwd);
        var badIterPrefixHash = validHash.Replace("$i=", "$x=");
        var badSaltPrefixHash = validHash.Replace("$s=", "$x=");
        Assert.Equal(PasswordVerificationResult.Failed, hasher.VerifyPassword(pwd, badIterPrefixHash));
        Assert.Equal(PasswordVerificationResult.Failed, hasher.VerifyPassword(pwd, badSaltPrefixHash));
    }

    [Fact]
    public void Pbkdf2PasswordHasher_NeedsRehash_EvaluatesCorrectly()
    {
        var oldHasher = new Pbkdf2PasswordHasher(iterations: 10_000);
        var newHasher = new Pbkdf2PasswordHasher(iterations: 50_000);
        var password = "MySecurePassword2026!";

        var oldHash = oldHasher.HashPassword(password);
        var newHash = newHasher.HashPassword(password);

        // Verification with old hash against new hasher triggers rehash
        Assert.Equal(PasswordVerificationResult.SuccessRehashNeeded, newHasher.VerifyPassword(password, oldHash));
        Assert.True(newHasher.NeedsRehash(oldHash));
        Assert.False(newHasher.NeedsRehash(newHash));

        // Malformed hashes require rehash
        Assert.True(newHasher.NeedsRehash(""));
        Assert.True(newHasher.NeedsRehash("   "));
        Assert.True(newHasher.NeedsRehash(null!));
        Assert.True(newHasher.NeedsRehash("$pbkdf2-sha512$i=bad$s=salt$hash"));
        Assert.True(newHasher.NeedsRehash("$pbkdf2-sha512$short"));
        Assert.True(newHasher.NeedsRehash("$pbkdf2-sha512$x=10000$s=salt$hash")); // parts[1] doesn't start with i=
        Assert.True(newHasher.NeedsRehash("$pbkdf2-sha512$x=500000$s=salt$hash")); // parts[1] doesn't start with i=, iterations > default
        Assert.True(newHasher.NeedsRehash("$pbkdf2-sha512$i=10000$x=salt$hash")); // parts[2] doesn't start with s=
        Assert.True(newHasher.NeedsRehash("$pbkdf2-sha512$i=500000$x=salt$hash")); // parts[2] doesn't start with s=, iterations > default
        Assert.True(newHasher.NeedsRehash("$pbkdf2-sha512$i=notInt$s=salt$hash"));
        Assert.True(newHasher.NeedsRehash("$argon2id$v=19$m=65536,t=1,p=1$salt$hash"));
    }

    // ==========================================
    // LegacyPbkdf2PasswordHasher Tests
    // ==========================================

    [Fact]
    public void LegacyPbkdf2PasswordHasher_Properties_And_Hash_Verify_Work()
    {
        var hasher = new LegacyPbkdf2PasswordHasher(memorySizeKb: 32768, iterations: 1, parallelism: 2, saltSizeBytes: 32);
        // SEC-005 fix: Algorithm now returns the accurate substrate (Pbkdf2HmacSha512), not Argon2id.
        // The $argon2id$ hash prefix is a format compatibility label, not the actual algorithm.
        Assert.Equal(PasswordHashAlgorithm.Pbkdf2HmacSha512, hasher.Algorithm);
        Assert.NotNull(LegacyPbkdf2PasswordHasher.Default);

        var password = "Argon2Password123!";
        var hash = hasher.HashPassword(password);
        var secondHash = hasher.HashPassword(password);
        Assert.NotEqual(hash, secondHash);

        // P0-001: LegacyPbkdf2PasswordHasher now uses the accurate $legacy-pbkdf2$ prefix
        Assert.StartsWith("$legacy-pbkdf2$v=19$m=32768,t=1,p=2$", hash, StringComparison.Ordinal);

        var verifySuccess = hasher.VerifyPassword(password, hash);
        Assert.Equal(PasswordVerificationResult.Success, verifySuccess);

        var verifyWrong = hasher.VerifyPassword("WrongPass!", hash);
        Assert.Equal(PasswordVerificationResult.Failed, verifyWrong);
    }

    [Fact]
    public void LegacyPbkdf2PasswordHasher_Verify_MalformedHashes_ReturnsFailed()
    {
        var hasher = new LegacyPbkdf2PasswordHasher(iterations: 1);
        var pwd = "test";

        Assert.Equal(PasswordVerificationResult.Failed, hasher.VerifyPassword(pwd, ""));
        Assert.Equal(PasswordVerificationResult.Failed, hasher.VerifyPassword(pwd, "   "));
        Assert.Equal(PasswordVerificationResult.Failed, hasher.VerifyPassword(pwd, null!));
        Assert.Equal(PasswordVerificationResult.Failed, hasher.VerifyPassword(pwd, "$pbkdf2-sha512$i=1000$s=salt$hash"));
        Assert.Equal(PasswordVerificationResult.Failed, hasher.VerifyPassword(pwd, "$argon2id$v=19$m=64$salt")); // only 4 parts
        Assert.Equal(PasswordVerificationResult.Failed, hasher.VerifyPassword(pwd, "$argon2id$v=19$m=64$salt$hash$extra")); // 6 parts
        Assert.Equal(PasswordVerificationResult.Failed, hasher.VerifyPassword(pwd, "$argon2id$v=19$m=64$notBase64!@#$hash"));
        // Invalid non-integer in t= parameter falls back to default iterations
        var salt = Convert.ToBase64String(new byte[16]);
        var hash = Convert.ToBase64String(new byte[32]);
        Assert.Equal(PasswordVerificationResult.Failed, hasher.VerifyPassword(pwd, $"$argon2id$v=19$m=64,t=invalid_num,p=1${salt}${hash}"));
    }

    [Fact]
    public void LegacyPbkdf2PasswordHasher_NeedsRehash_EvaluatesCorrectly()
    {
        var hasher1 = new LegacyPbkdf2PasswordHasher(memorySizeKb: 65536, iterations: 1);
        var hasher2 = new LegacyPbkdf2PasswordHasher(memorySizeKb: 65536, iterations: 2);

        var hash1 = hasher1.HashPassword("secret");

        Assert.False(hasher1.NeedsRehash(hash1));
        Assert.True(hasher2.NeedsRehash(hash1));

        // Memory mismatch triggers rehash
        var hasherMemMismatch = new LegacyPbkdf2PasswordHasher(memorySizeKb: 32768, iterations: 1);
        Assert.True(hasherMemMismatch.NeedsRehash(hash1));

        // Parallelism mismatch triggers rehash
        var hasherParMismatch = new LegacyPbkdf2PasswordHasher(parallelism: 2);
        Assert.True(hasherParMismatch.NeedsRehash(hash1));

        // When verifying with hasher2 on hash generated by hasher1, rehash is needed
        var verifyRehash = hasher2.VerifyPassword("secret", hash1);
        Assert.Equal(PasswordVerificationResult.SuccessRehashNeeded, verifyRehash);

        Assert.True(hasher1.NeedsRehash(""));
        Assert.True(hasher1.NeedsRehash("   "));
        Assert.True(hasher1.NeedsRehash(null!));
        Assert.True(hasher1.NeedsRehash("$pbkdf2-sha512$hash"));
        Assert.True(hasher1.NeedsRehash("$argon2id$short"));

        // Hash with corrupted parallelism tag prefix triggers rehash
        var hasher4 = new LegacyPbkdf2PasswordHasher(memorySizeKb: 65536, iterations: 3, parallelism: 4);
        Assert.True(hasher4.NeedsRehash("$legacy-pbkdf2$v=19$m=65536,t=3,x=4$salt$hash"));
    }

    // ==========================================
    // CompositePasswordHasher Tests
    // ==========================================

    [Fact]
    public void CompositePasswordHasher_VerifiesDifferentFormatsAndSignalsRehash()
    {
        var pbkdf2 = new Pbkdf2PasswordHasher(iterations: 10_000);
        var argon2 = new LegacyPbkdf2PasswordHasher(iterations: 1);
        var composite = new CompositePasswordHasher(primaryHasher: pbkdf2, additionalHashers: [argon2]);

        // Custom Argon2id additional hasher is preserved via prefix routing.
        // FakeLegacyPbkdf2PasswordHasher.Algorithm == Argon2id, so it is registered under $argon2id$.
        // To trigger it, we must verify a hash with the $argon2id$ prefix.
        var customArgon = new FakeLegacyPbkdf2PasswordHasher();
        var compositeWithArgon = new CompositePasswordHasher(primaryHasher: pbkdf2, additionalHashers: [customArgon]);
        var resCustom = compositeWithArgon.VerifyPassword("password", "$argon2id$anyHash");
        Assert.Equal(PasswordVerificationResult.SuccessRehashNeeded, resCustom);
        Assert.True(customArgon.WasCalled);

        Assert.Equal(PasswordHashAlgorithm.Pbkdf2HmacSha512, composite.Algorithm);

        var password = "MultiAlgorithmPassword123!";

        // Hash with PBKDF2
        var pbkdf2Hash = composite.HashPassword(password);
        var pbkdf2Verify = composite.VerifyPassword(password, pbkdf2Hash);
        Assert.Equal(PasswordVerificationResult.Success, pbkdf2Verify);

        // Hash with Argon2id and verify via Composite
        var argon2Hash = argon2.HashPassword(password);
        var argon2Verify = composite.VerifyPassword(password, argon2Hash);

        // Since primary is PBKDF2, verifying an Argon2 hash signals RehashNeeded
        Assert.Equal(PasswordVerificationResult.SuccessRehashNeeded, argon2Verify);

        // Failed password with Argon2 format
        Assert.Equal(PasswordVerificationResult.Failed, composite.VerifyPassword("WrongPass!", argon2Hash));

        // Unknown format falls back to primary
        Assert.Equal(PasswordVerificationResult.Failed, composite.VerifyPassword("WrongPass!", "$unknown$format"));

        // Null or whitespace
        Assert.Equal(PasswordVerificationResult.Failed, composite.VerifyPassword(password, ""));
        Assert.Equal(PasswordVerificationResult.Failed, composite.VerifyPassword(password, "   "));
        Assert.Equal(PasswordVerificationResult.Failed, composite.VerifyPassword(password, null!));

        // NeedsRehash
        Assert.False(composite.NeedsRehash(pbkdf2Hash));
        Assert.True(composite.NeedsRehash(""));
        Assert.True(composite.NeedsRehash(null!));
    }

    [Fact]
    public void CompositePasswordHasher_DefaultConstructor_RegistersDefaults()
    {
        var defaultComposite = new CompositePasswordHasher();
        Assert.Equal(PasswordHashAlgorithm.Pbkdf2HmacSha512, defaultComposite.Algorithm);

        var password = "DefaultCompositePassword";
        var hash = defaultComposite.HashPassword(password);
        Assert.StartsWith("$pbkdf2-sha512$", hash, StringComparison.Ordinal);
        Assert.Equal(PasswordVerificationResult.Success, defaultComposite.VerifyPassword(password, hash));
    }

    [Fact]
    public void CompositePasswordHasher_RegistersCustomAlgorithmPrefixes()
    {
        var customBcrypt = new FakeBcryptPasswordHasher();
        var customUnknown = new FakeUnknownPasswordHasher();
        var composite = new CompositePasswordHasher(primaryHasher: null, additionalHashers: [customBcrypt, customUnknown]);

        var resBcrypt = composite.VerifyPassword("password", "$2a$10$customHash");
        Assert.Equal(PasswordVerificationResult.SuccessRehashNeeded, resBcrypt);

        var resUnknown = composite.VerifyPassword("password", "$99$customHash");
        Assert.Equal(PasswordVerificationResult.SuccessRehashNeeded, resUnknown);

        // Test with custom primary hasher that does not have PBKDF2 or Argon2id initially
        var compositeWithCustomPrimary = new CompositePasswordHasher(primaryHasher: customBcrypt, additionalHashers: [customUnknown]);
        Assert.Equal(PasswordHashAlgorithm.BCrypt, compositeWithCustomPrimary.Algorithm);

        // Primary hasher dispatch returns Success
        var resBcryptPrimary = compositeWithCustomPrimary.VerifyPassword("password", "$2a$10$customHash");
        Assert.Equal(PasswordVerificationResult.Success, resBcryptPrimary);

        // Default PBKDF2 and Argon2id were registered automatically
        var validPbkdf2Hash = Pbkdf2PasswordHasher.Default.HashPassword("valid-password");
        var resPbkdf2 = compositeWithCustomPrimary.VerifyPassword("valid-password", validPbkdf2Hash);
        Assert.Equal(PasswordVerificationResult.SuccessRehashNeeded, resPbkdf2);

        var validArgon2Hash = LegacyPbkdf2PasswordHasher.Default.HashPassword("valid-password");
        var resArgon2 = compositeWithCustomPrimary.VerifyPassword("valid-password", validArgon2Hash);
        Assert.Equal(PasswordVerificationResult.SuccessRehashNeeded, resArgon2);

        // Custom unknown hasher dispatch returns SuccessRehashNeeded
        var resUnknownCustom = compositeWithCustomPrimary.VerifyPassword("password", "$99$customHash");
        Assert.Equal(PasswordVerificationResult.SuccessRehashNeeded, resUnknownCustom);

        // Re-verify primary bcrypt to ensure no empty-string prefix shadowed the primary hasher
        var resBcryptRecheck = compositeWithCustomPrimary.VerifyPassword("password", "$2a$10$customHash");
        Assert.Equal(PasswordVerificationResult.Success, resBcryptRecheck);
    }

    [Fact]
    public void CompositePasswordHasher_NormalizesPhpAndBsdBcryptPrefixes()
    {
        var customBcrypt = new FakeBcryptPasswordHasher();
        var composite = new CompositePasswordHasher(primaryHasher: LegacyPbkdf2PasswordHasher.Default, additionalHashers: [customBcrypt]);
        ISimplePasswordHasher simpleHasher = composite;

        // $2y$ (PHP) should route to BCrypt hasher and succeed with rehash needed
        var resPhp = composite.VerifyPassword("password", "$2y$10$customHash");
        Assert.Equal(PasswordVerificationResult.SuccessRehashNeeded, resPhp);
        Assert.True(simpleHasher.Verify("password", "$2y$10$customHash"));

        // $2b$ (BSD/Openwall) should route to BCrypt hasher and succeed with rehash needed
        var resBsd = composite.VerifyPassword("password", "$2b$10$customHash");
        Assert.Equal(PasswordVerificationResult.SuccessRehashNeeded, resBsd);
        Assert.True(simpleHasher.Verify("password", "$2b$10$customHash"));

        // SimpleHasher Verify with invalid password or hash returns false
        Assert.False(simpleHasher.Verify("wrong_password", "$2y$10$customHash"));
        Assert.False(simpleHasher.Verify("wrong_password", "non-existent-hash"));

        // NeedsRehash should return true for legacy BCrypt hashes
        Assert.True(composite.NeedsRehash("$2a$10$customHash"));
        Assert.True(composite.NeedsRehash("$2y$10$customHash"));
        Assert.True(composite.NeedsRehash("$2b$10$customHash"));
        Assert.True(simpleHasher.NeedsRehash("$2y$10$customHash"));
    }

    [Fact]
    public void LegacyPbkdf2PasswordHasher_VerifyPassword_RecordsExpectedObservabilityTags()
    {
        using var meterListener = new System.Diagnostics.Metrics.MeterListener();
        var capturedTags = new System.Collections.Generic.List<System.Collections.Generic.Dictionary<string, object?>>();
        meterListener.InstrumentPublished = (instrument, listener) =>
        {
            if (instrument.Meter.Name == "EricksonLopez.Security" && instrument.Name == "security.password.verifications_total")
            {
                listener.EnableMeasurementEvents(instrument);
            }
        };
        meterListener.SetMeasurementEventCallback<long>((instrument, measurement, tags, state) =>
        {
            var dict = new System.Collections.Generic.Dictionary<string, object?>();
            foreach (var tag in tags)
            {
                dict[tag.Key] = tag.Value;
            }
            capturedTags.Add(dict);
        });
        meterListener.Start();

        var hasher = LegacyPbkdf2PasswordHasher.Default;
        var validHash = hasher.HashPassword("Secr3tP@ssword!");

        // 1. Success
        hasher.VerifyPassword("Secr3tP@ssword!", validHash);
        var lastSuccess = capturedTags[^1];
        Assert.Equal("success", lastSuccess["security.result"]);
        Assert.Equal("legacy-pbkdf2", lastSuccess["security.hash.algorithm"]);

        // 2. Failure
        hasher.VerifyPassword("WrongPassword!", validHash);
        var lastFailure = capturedTags[^1];
        Assert.Equal("failure", lastFailure["security.result"]);
        Assert.Equal("legacy-pbkdf2", lastFailure["security.hash.algorithm"]);

        // 3. SuccessRehashNeeded (hash with lower iterations verified by default hasher)
        var legacyHasher = new LegacyPbkdf2PasswordHasher(iterations: 1);
        var legacyHash = legacyHasher.HashPassword("Secr3tP@ssword!");
        hasher.VerifyPassword("Secr3tP@ssword!", legacyHash);
        var lastRehash = capturedTags[^1];
        Assert.Equal("rehash_needed", lastRehash["security.result"]);
        Assert.Equal("legacy-pbkdf2", lastRehash["security.hash.algorithm"]);
    }

    // ==========================================
    // P0-002 Regression: DoS via Malicious Iteration Count
    // ==========================================

    // FINDING-CRIT-01 (resolved): threshold is 500ms on net8 (JIT cold-start adds ~57ms overhead)
    // and 100ms on net9/net10. The security guard (reject before PBKDF2) is correct on all TFMs.
#if NET8_0
    private const int TimingThresholdMs = 500;
#else
    private const int TimingThresholdMs = 100;
#endif

    [Fact]
    public void Pbkdf2PasswordHasher_MaliciousIterationsInHash_RejectsFast()
    {
        // SECURITY REGRESSION: DOS-001
        // A maliciously crafted hash with int.MaxValue iterations must be rejected
        // immediately without computing PBKDF2 (which would take hours).
        var maliciousHash = $"$pbkdf2-sha512$i={int.MaxValue}$s={Convert.ToBase64String(new byte[16])}${Convert.ToBase64String(new byte[32])}";
        var hasher = new Pbkdf2PasswordHasher(iterations: 210_000);

        var sw = System.Diagnostics.Stopwatch.StartNew();
        var result = hasher.VerifyPassword("anypassword", maliciousHash);
        sw.Stop();

        Assert.Equal(PasswordVerificationResult.Failed, result);
        Assert.True(sw.ElapsedMilliseconds < TimingThresholdMs,
            $"P0-002: Malicious hash with {int.MaxValue} iterations must be rejected in <{TimingThresholdMs}ms but took {sw.ElapsedMilliseconds}ms.");
    }

    [Fact]
    public void Pbkdf2PasswordHasher_ExceedingMaxIterationsInCrossTierFormat_RejectsFast()
    {
        // SECURITY REGRESSION: DOS-001 — cross-tier PBKDF2.V1$ format
        var maliciousHash = $"PBKDF2.V1${int.MaxValue}${Convert.ToBase64String(new byte[16])}${Convert.ToBase64String(new byte[32])}";
        var hasher = new Pbkdf2PasswordHasher(iterations: 210_000);

        var sw = System.Diagnostics.Stopwatch.StartNew();
        var result = hasher.VerifyPassword("anypassword", maliciousHash);
        sw.Stop();

        Assert.Equal(PasswordVerificationResult.Failed, result);
        Assert.True(sw.ElapsedMilliseconds < TimingThresholdMs,
            $"P0-002: Cross-tier PBKDF2.V1 with {int.MaxValue} iterations must be rejected in <{TimingThresholdMs}ms but took {sw.ElapsedMilliseconds}ms.");
    }

    [Fact]
    public void LegacyPbkdf2PasswordHasher_MaliciousTimeCostInHash_RejectsFast()
    {
        // SECURITY REGRESSION: DOS-001 — LegacyPbkdf2PasswordHasher uses t= multiplier × 70,000
        // A t=int.MaxValue hash would compute int.MaxValue * 70,000 PBKDF2 iterations.
        var salt = Convert.ToBase64String(new byte[16]);
        var hashVal = Convert.ToBase64String(new byte[32]);
        var maliciousHash = $"$legacy-pbkdf2$v=19$m=65536,t={int.MaxValue},p=4${salt}${hashVal}";
        var hasher = new LegacyPbkdf2PasswordHasher(iterations: 3);

        var sw = System.Diagnostics.Stopwatch.StartNew();
        var result = hasher.VerifyPassword("anypassword", maliciousHash);
        sw.Stop();

        Assert.Equal(PasswordVerificationResult.Failed, result);
        Assert.True(sw.ElapsedMilliseconds < TimingThresholdMs,
            $"P0-002: LegacyPbkdf2 with t={int.MaxValue} must be rejected in <{TimingThresholdMs}ms but took {sw.ElapsedMilliseconds}ms.");
    }

    // ==========================================
    // P0-001 Regression: CompositePasswordHasher dispatches $legacy-pbkdf2$ hashes correctly
    // ==========================================

    [Fact]
    public void CompositePasswordHasher_WithLegacyPbkdf2PrefixHash_VerifiesAndSignalsRehash()
    {
        // SECURITY REGRESSION: BLOCKER-001 (PWD-002)
        // LegacyPbkdf2PasswordHasher.HashPassword() produces $legacy-pbkdf2$... hashes,
        // but the composite was only keyed under $argon2id$. Dispatch never found the hasher,
        // causing all $legacy-pbkdf2$ verifications to return Failed.
        var primaryHasher = new Pbkdf2PasswordHasher(iterations: 10_000);
        var legacyHasher = new LegacyPbkdf2PasswordHasher(iterations: 1);
        var composite = new CompositePasswordHasher(
            primaryHasher: primaryHasher,
            additionalHashers: [legacyHasher]);

        var password = "CorrectHorseBatteryStaple";
        var legacyHash = legacyHasher.HashPassword(password);

        // Verify the hash starts with the legacy prefix
        Assert.StartsWith("$legacy-pbkdf2$", legacyHash);

        // Composite MUST verify it and return SuccessRehashNeeded (not Failed)
        var result = composite.VerifyPassword(password, legacyHash);
        Assert.Equal(PasswordVerificationResult.SuccessRehashNeeded, result);

        // Wrong password MUST still fail
        Assert.Equal(PasswordVerificationResult.Failed, composite.VerifyPassword("WrongPassword", legacyHash));
    }

    [Fact]
    public void Argon2idPasswordHasher_MaliciousTimeCostInHash_RejectsFast()
    {
        // SECURITY REGRESSION: SEC-002 — Argon2idPasswordHasher rejects out-of-bounds t= without computing
        var salt = Convert.ToBase64String(new byte[16]);
        var hashVal = Convert.ToBase64String(new byte[32]);
        var maliciousHash = $"$argon2id$v=19$m=65536,t=15,p=4${salt}${hashVal}";
        var hasher = Argon2idPasswordHasher.Default;

        // Warm up JIT to avoid measuring initial JIT compilation overhead
        _ = hasher.VerifyPassword("warmup", "$argon2id$v=19$invalid");

        var sw = System.Diagnostics.Stopwatch.StartNew();
        var result = hasher.VerifyPassword("anypassword", maliciousHash);
        sw.Stop();

        Assert.Equal(PasswordVerificationResult.Failed, result);
        Assert.True(sw.ElapsedMilliseconds < 50,
            $"SEC-002: Malicious hash with t=15 must be rejected in <50ms without computing, but took {sw.ElapsedMilliseconds}ms.");
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(11)]
    [InlineData(100)]
    public void Argon2idPasswordHasher_Constructor_ValidatesIterationsBounds(int invalidIterations)
    {
        Assert.Throws<ArgumentOutOfRangeException>("iterations", () => new Argon2idPasswordHasher(iterations: invalidIterations));
    }

    [Fact]
    public void LegacyPbkdf2PasswordHasher_MaliciousModerateTimeCost_RejectsFast()
    {
        var salt = Convert.ToBase64String(new byte[16]);
        var hashVal = Convert.ToBase64String(new byte[32]);
        var maliciousHash = $"$legacy-pbkdf2$v=19$m=65536,t=15,p=4${salt}${hashVal}";
        var hasher = LegacyPbkdf2PasswordHasher.Default;

        var sw = System.Diagnostics.Stopwatch.StartNew();
        var result = hasher.VerifyPassword("anypassword", maliciousHash);
        sw.Stop();

        Assert.Equal(PasswordVerificationResult.Failed, result);
        Assert.True(sw.ElapsedMilliseconds < 50,
            $"SEC-002: Malicious hash with t=15 must be rejected in <50ms without computing, but took {sw.ElapsedMilliseconds}ms.");
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(11)]
    [InlineData(100)]
    public void LegacyPbkdf2PasswordHasher_Constructor_ValidatesIterationsBounds(int invalidIterations)
    {
        Assert.Throws<ArgumentOutOfRangeException>("iterations", () => new LegacyPbkdf2PasswordHasher(iterations: invalidIterations));
    }

    [Fact]
    public void PasswordHashers_RejectEmptyOrMalformedSaltAndHashLengths()
    {
        var hasher = Argon2idPasswordHasher.Default;
        var legacy = LegacyPbkdf2PasswordHasher.Default;

        // Salt too short (< 8 bytes)
        var shortSalt = Convert.ToBase64String(new byte[4]);
        var validHash = Convert.ToBase64String(new byte[32]);
        Assert.Equal(PasswordVerificationResult.Failed, hasher.VerifyPassword("pwd", $"$argon2id$v=19$m=65536,t=3,p=4${shortSalt}${validHash}"));
        Assert.Equal(PasswordVerificationResult.Failed, legacy.VerifyPassword("pwd", $"$legacy-pbkdf2$v=19$m=65536,t=3,p=4${shortSalt}${validHash}"));

        // Hash too short (< 16 bytes) or empty (0 bytes)
        var validSalt = Convert.ToBase64String(new byte[16]);
        var emptyHash = Convert.ToBase64String([]);
        var shortHash = Convert.ToBase64String(new byte[8]);
        Assert.Equal(PasswordVerificationResult.Failed, hasher.VerifyPassword("pwd", $"$argon2id$v=19$m=65536,t=3,p=4${validSalt}${emptyHash}"));
        Assert.Equal(PasswordVerificationResult.Failed, hasher.VerifyPassword("pwd", $"$argon2id$v=19$m=65536,t=3,p=4${validSalt}${shortHash}"));
        Assert.Equal(PasswordVerificationResult.Failed, legacy.VerifyPassword("pwd", $"$legacy-pbkdf2$v=19$m=65536,t=3,p=4${validSalt}${emptyHash}"));
        Assert.Equal(PasswordVerificationResult.Failed, legacy.VerifyPassword("pwd", $"$legacy-pbkdf2$v=19$m=65536,t=3,p=4${validSalt}${shortHash}"));

        // Hash too long (> 64 bytes)
        var longHash = Convert.ToBase64String(new byte[128]);
        Assert.Equal(PasswordVerificationResult.Failed, hasher.VerifyPassword("pwd", $"$argon2id$v=19$m=65536,t=3,p=4${validSalt}${longHash}"));
        Assert.Equal(PasswordVerificationResult.Failed, legacy.VerifyPassword("pwd", $"$legacy-pbkdf2$v=19$m=65536,t=3,p=4${validSalt}${longHash}"));
    }

    [Fact]
    public void PasswordHashers_Exceeding256Characters_ThrowsArgumentOutOfRangeException_WithStrictMessage()
    {
        string longPassword = new('P', 257);

        var pbkdf2Ex = Assert.Throws<ArgumentOutOfRangeException>(() => Pbkdf2PasswordHasher.Default.HashPassword(longPassword));
        Assert.Equal("password", pbkdf2Ex.ParamName);
        Assert.Contains("Password length cannot exceed 256 characters.", pbkdf2Ex.Message);

        var argon2Ex = Assert.Throws<ArgumentOutOfRangeException>(() => Argon2idPasswordHasher.Default.HashPassword(longPassword));
        Assert.Equal("password", argon2Ex.ParamName);
        Assert.Contains("Password length cannot exceed 256 characters.", argon2Ex.Message);

        var legacyEx = Assert.Throws<ArgumentOutOfRangeException>(() => LegacyPbkdf2PasswordHasher.Default.HashPassword(longPassword));
        Assert.Equal("password", legacyEx.ParamName);
        Assert.Contains("Password length cannot exceed 256 characters.", legacyEx.Message);

        var compositeEx = Assert.Throws<ArgumentOutOfRangeException>(() => new CompositePasswordHasher().HashPassword(longPassword));
        Assert.Equal("password", compositeEx.ParamName);
        Assert.Contains("Password length cannot exceed 256 characters.", compositeEx.Message);
    }

    [Fact]
    public void PasswordHashers_Exceeding256Characters_VerifyPassword_ReturnsFailed()
    {
        string longPassword = new('P', 257);
        var pbkdf2ValidHash = Pbkdf2PasswordHasher.Default.HashPassword("ValidPassword123!");
        var argon2ValidHash = Argon2idPasswordHasher.Default.HashPassword("ValidPassword123!");
        var legacyValidHash = LegacyPbkdf2PasswordHasher.Default.HashPassword("ValidPassword123!");

        Assert.Equal(PasswordVerificationResult.Failed, Pbkdf2PasswordHasher.Default.VerifyPassword(longPassword, pbkdf2ValidHash));
        Assert.Equal(PasswordVerificationResult.Failed, Argon2idPasswordHasher.Default.VerifyPassword(longPassword, argon2ValidHash));
        Assert.Equal(PasswordVerificationResult.Failed, LegacyPbkdf2PasswordHasher.Default.VerifyPassword(longPassword, legacyValidHash));
        Assert.Equal(PasswordVerificationResult.Failed, new CompositePasswordHasher().VerifyPassword(longPassword, pbkdf2ValidHash));
    }

    [Fact]
    public void PasswordHashers_Exact256Characters_And_512CharacterHash_Boundaries()
    {
        string exact256 = new('A', 256);

        var pbkdf2 = new Pbkdf2PasswordHasher(iterations: 10_000);
        var pHash = pbkdf2.HashPassword(exact256);
        Assert.Equal(PasswordVerificationResult.Success, pbkdf2.VerifyPassword(exact256, pHash));

        var argon2 = new Argon2idPasswordHasher(memorySizeKb: 1024, iterations: 1, parallelism: 1);
        var aHash = argon2.HashPassword(exact256);
        Assert.Equal(PasswordVerificationResult.Success, argon2.VerifyPassword(exact256, aHash));

        var legacy = new LegacyPbkdf2PasswordHasher(memorySizeKb: 1024, iterations: 1, parallelism: 1);
        var lHash = legacy.HashPassword(exact256);
        Assert.Equal(PasswordVerificationResult.Success, legacy.VerifyPassword(exact256, lHash));

        var composite = new CompositePasswordHasher(primaryHasher: pbkdf2);
        Assert.Equal(PasswordVerificationResult.Success, composite.VerifyPassword(exact256, pHash));

        // 512 and 513 char hash limits
        string hash512 = new('X', 512);
        string hash513 = new('X', 513);
        Assert.Equal(PasswordVerificationResult.Failed, pbkdf2.VerifyPassword(exact256, hash512));
        Assert.Equal(PasswordVerificationResult.Failed, pbkdf2.VerifyPassword(exact256, hash513));
        Assert.Equal(PasswordVerificationResult.Failed, argon2.VerifyPassword(exact256, hash512));
        Assert.Equal(PasswordVerificationResult.Failed, argon2.VerifyPassword(exact256, hash513));
        Assert.Equal(PasswordVerificationResult.Failed, legacy.VerifyPassword(exact256, hash512));
        Assert.Equal(PasswordVerificationResult.Failed, legacy.VerifyPassword(exact256, hash513));
        Assert.Equal(PasswordVerificationResult.Failed, composite.VerifyPassword(exact256, hash512));
        Assert.Equal(PasswordVerificationResult.Failed, composite.VerifyPassword(exact256, hash513));
    }

    [Fact]
    public void Argon2idPasswordHasher_ComprehensiveBoundariesAndRehash()
    {
        // 1. Constructor parameter boundaries
        Assert.NotNull(new Argon2idPasswordHasher(iterations: 1));
        Assert.NotNull(new Argon2idPasswordHasher(iterations: 10));
        Assert.NotNull(new Argon2idPasswordHasher(memorySizeKb: 1024));
        Assert.NotNull(new Argon2idPasswordHasher(memorySizeKb: 65536));
        Assert.Throws<ArgumentOutOfRangeException>("memorySizeKb", () => new Argon2idPasswordHasher(memorySizeKb: 1023));
        Assert.Throws<ArgumentOutOfRangeException>("memorySizeKb", () => new Argon2idPasswordHasher(memorySizeKb: 65537));
        Assert.NotNull(new Argon2idPasswordHasher(parallelism: 1));
        Assert.NotNull(new Argon2idPasswordHasher(parallelism: 16));
        Assert.Throws<ArgumentOutOfRangeException>("parallelism", () => new Argon2idPasswordHasher(parallelism: 0));
        Assert.Throws<ArgumentOutOfRangeException>("parallelism", () => new Argon2idPasswordHasher(parallelism: 17));
        Assert.NotNull(new Argon2idPasswordHasher(saltSizeBytes: 8));
        Assert.NotNull(new Argon2idPasswordHasher(saltSizeBytes: 64));
        Assert.Throws<ArgumentOutOfRangeException>("saltSizeBytes", () => new Argon2idPasswordHasher(saltSizeBytes: 7));
        Assert.Throws<ArgumentOutOfRangeException>("saltSizeBytes", () => new Argon2idPasswordHasher(saltSizeBytes: 65));

        var sut = new Argon2idPasswordHasher(memorySizeKb: 1024, iterations: 1, parallelism: 1);
        var validSalt = Convert.ToBase64String(new byte[16]);
        var validHash = Convert.ToBase64String(new byte[32]);

        // 2. Missing parameter tags
        Assert.Equal(PasswordVerificationResult.Failed, sut.VerifyPassword("p", $"$argon2id$v=19$m=1024,p=1${validSalt}${validHash}")); // missing t=
        Assert.Equal(PasswordVerificationResult.Failed, sut.VerifyPassword("p", $"$argon2id$v=19$t=1,p=1${validSalt}${validHash}"));  // missing m=
        Assert.Equal(PasswordVerificationResult.Failed, sut.VerifyPassword("p", $"$argon2id$v=19$m=1024,t=1${validSalt}${validHash}")); // missing p=

        // 3. Out-of-bounds parameter values
        Assert.Equal(PasswordVerificationResult.Failed, sut.VerifyPassword("p", $"$argon2id$v=19$m=1024,t=0,p=1${validSalt}${validHash}"));
        Assert.Equal(PasswordVerificationResult.Failed, sut.VerifyPassword("p", $"$argon2id$v=19$m=1024,t=11,p=1${validSalt}${validHash}"));
        Assert.Equal(PasswordVerificationResult.Failed, sut.VerifyPassword("p", $"$argon2id$v=19$m=1023,t=1,p=1${validSalt}${validHash}"));
        Assert.Equal(PasswordVerificationResult.Failed, sut.VerifyPassword("p", $"$argon2id$v=19$m=65537,t=1,p=1${validSalt}${validHash}"));
        Assert.Equal(PasswordVerificationResult.Failed, sut.VerifyPassword("p", $"$argon2id$v=19$m=1024,t=1,p=0${validSalt}${validHash}"));
        Assert.Equal(PasswordVerificationResult.Failed, sut.VerifyPassword("p", $"$argon2id$v=19$m=1024,t=1,p=17${validSalt}${validHash}"));

        // 4. String length bounds for salt and hash
        var salt7 = new string('A', 7);
        var salt129 = new string('A', 129);
        var hash15 = new string('A', 15);
        var hash129 = new string('A', 129);
        Assert.Equal(PasswordVerificationResult.Failed, sut.VerifyPassword("p", $"$argon2id$v=19$m=1024,t=1,p=1${salt7}${validHash}"));
        Assert.Equal(PasswordVerificationResult.Failed, sut.VerifyPassword("p", $"$argon2id$v=19$m=1024,t=1,p=1${salt129}${validHash}"));
        Assert.Equal(PasswordVerificationResult.Failed, sut.VerifyPassword("p", $"$argon2id$v=19$m=1024,t=1,p=1${validSalt}${hash15}"));
        Assert.Equal(PasswordVerificationResult.Failed, sut.VerifyPassword("p", $"$argon2id$v=19$m=1024,t=1,p=1${validSalt}${hash129}"));

        // Format exception in base64
        Assert.Equal(PasswordVerificationResult.Failed, sut.VerifyPassword("p", $"$argon2id$v=19$m=1024,t=1,p=1$not_base64!!!${validHash}"));
        Assert.Equal(PasswordVerificationResult.Failed, sut.VerifyPassword("p", $"$argon2id$v=19$m=1024,t=1,p=1${validSalt}$not_base64!!!"));

        // 5. Rehash needed (different parameters)
        var lowCostHasher = new Argon2idPasswordHasher(memorySizeKb: 1024, iterations: 1, parallelism: 1);
        var highCostHasher = new Argon2idPasswordHasher(memorySizeKb: 2048, iterations: 2, parallelism: 2);
        var lowHash = lowCostHasher.HashPassword("TestPass!");
        Assert.Equal(PasswordVerificationResult.Success, lowCostHasher.VerifyPassword("TestPass!", lowHash));
        Assert.Equal(PasswordVerificationResult.SuccessRehashNeeded, highCostHasher.VerifyPassword("TestPass!", lowHash));
        Assert.True(highCostHasher.NeedsRehash(lowHash));
        Assert.False(lowCostHasher.NeedsRehash(lowHash));
    }

    [Fact]
    public void Pbkdf2PasswordHasher_ComprehensiveBoundariesAndRehash()
    {
        // 1. Constructor parameter boundaries
        Assert.NotNull(new Pbkdf2PasswordHasher(iterations: 10_000));
        Assert.NotNull(new Pbkdf2PasswordHasher(iterations: 600_000));
        Assert.NotNull(new Pbkdf2PasswordHasher(saltSizeBytes: 8));
        Assert.NotNull(new Pbkdf2PasswordHasher(saltSizeBytes: 64));
        Assert.Throws<ArgumentOutOfRangeException>("saltSizeBytes", () => new Pbkdf2PasswordHasher(saltSizeBytes: 7));
        Assert.Throws<ArgumentOutOfRangeException>("saltSizeBytes", () => new Pbkdf2PasswordHasher(saltSizeBytes: 65));
        Assert.NotNull(new Pbkdf2PasswordHasher(derivedKeySizeBytes: 16));
        Assert.NotNull(new Pbkdf2PasswordHasher(derivedKeySizeBytes: 64));
        Assert.Throws<ArgumentOutOfRangeException>("derivedKeySizeBytes", () => new Pbkdf2PasswordHasher(derivedKeySizeBytes: 15));
        Assert.Throws<ArgumentOutOfRangeException>("derivedKeySizeBytes", () => new Pbkdf2PasswordHasher(derivedKeySizeBytes: 65));

        var sut = new Pbkdf2PasswordHasher(iterations: 10_000);
        var validSalt = Convert.ToBase64String(new byte[16]);
        var validHash = Convert.ToBase64String(new byte[32]);

        // 2. Iterations boundaries
        Assert.Equal(PasswordVerificationResult.Failed, sut.VerifyPassword("p", $"$pbkdf2-sha512$i=0$s={validSalt}${validHash}"));
        Assert.Equal(PasswordVerificationResult.Failed, sut.VerifyPassword("p", $"$pbkdf2-sha512$i=-1$s={validSalt}${validHash}"));
        Assert.Equal(PasswordVerificationResult.Failed, sut.VerifyPassword("p", $"$pbkdf2-sha512$i=1000001$s={validSalt}${validHash}"));

        // 3. String length boundaries
        var shortSalt = new string('A', 10);
        var longSalt = new string('A', 129);
        var shortHash = new string('A', 21);
        var longHash = new string('A', 129);
        Assert.Equal(PasswordVerificationResult.Failed, sut.VerifyPassword("p", $"PBKDF2.V1$1000${shortSalt}${validHash}"));
        Assert.Equal(PasswordVerificationResult.Failed, sut.VerifyPassword("p", $"PBKDF2.V1$1000${longSalt}${validHash}"));
        Assert.Equal(PasswordVerificationResult.Failed, sut.VerifyPassword("p", $"PBKDF2.V1$1000${validSalt}${shortHash}"));
        Assert.Equal(PasswordVerificationResult.Failed, sut.VerifyPassword("p", $"PBKDF2.V1$1000${validSalt}${longHash}"));

        // Decoded byte limits
        var salt7 = Convert.ToBase64String(new byte[7]);
        var salt65 = Convert.ToBase64String(new byte[65]);
        var hash15 = Convert.ToBase64String(new byte[15]);
        var hash65 = Convert.ToBase64String(new byte[65]);
        Assert.Equal(PasswordVerificationResult.Failed, sut.VerifyPassword("p", $"PBKDF2.V1$1000${salt7}${validHash}"));
        Assert.Equal(PasswordVerificationResult.Failed, sut.VerifyPassword("p", $"PBKDF2.V1$1000${salt65}${validHash}"));
        Assert.Equal(PasswordVerificationResult.Failed, sut.VerifyPassword("p", $"PBKDF2.V1$1000${validSalt}${hash15}"));
        Assert.Equal(PasswordVerificationResult.Failed, sut.VerifyPassword("p", $"PBKDF2.V1$1000${validSalt}${hash65}"));

        // Rehash Needed
        var hash = sut.HashPassword("MySecretPass!");
        Assert.Equal(PasswordVerificationResult.Success, sut.VerifyPassword("MySecretPass!", hash));
        var sutHigh = new Pbkdf2PasswordHasher(iterations: 20_000);
        Assert.Equal(PasswordVerificationResult.SuccessRehashNeeded, sutHigh.VerifyPassword("MySecretPass!", hash));
    }

    [Fact]
    public void CompositePasswordHasher_CrossTierAndLegacySpoofedArgon2idFallback()
    {
        var pbkdf2 = new Pbkdf2PasswordHasher(iterations: 10_000);
        var composite = new CompositePasswordHasher(primaryHasher: pbkdf2);

        // 1. Cross-tier PBKDF2.V1 format
        var saltBytes = new byte[16];
        var saltBase64 = Convert.ToBase64String(saltBytes);
        var derivedBytes = System.Security.Cryptography.Rfc2898DeriveBytes.Pbkdf2("CrossTierPass", saltBytes, 1000, System.Security.Cryptography.HashAlgorithmName.SHA512, 32);
        var hashBase64 = Convert.ToBase64String(derivedBytes);

        var tier1Valid = $"PBKDF2.V1$1000${saltBase64}${hashBase64}";
        Assert.Equal(PasswordVerificationResult.SuccessRehashNeeded, composite.VerifyPassword("CrossTierPass", tier1Valid));
        Assert.Equal(PasswordVerificationResult.Failed, composite.VerifyPassword("WrongPass", tier1Valid));

        // Boundaries in PBKDF2.V1 inside Composite
        Assert.Equal(PasswordVerificationResult.Failed, composite.VerifyPassword("p", $"PBKDF2.V1$999${saltBase64}${hashBase64}"));
        Assert.Equal(PasswordVerificationResult.Failed, composite.VerifyPassword("p", $"PBKDF2.V1$600001${saltBase64}${hashBase64}"));
        Assert.Equal(PasswordVerificationResult.Failed, composite.VerifyPassword("p", $"PBKDF2.V1$1000$short${hashBase64}"));
        Assert.Equal(PasswordVerificationResult.Failed, composite.VerifyPassword("p", $"PBKDF2.V1$1000${new string('A', 129)}${hashBase64}"));
        Assert.Equal(PasswordVerificationResult.Failed, composite.VerifyPassword("p", $"PBKDF2.V1$1000${saltBase64}$short"));
        Assert.Equal(PasswordVerificationResult.Failed, composite.VerifyPassword("p", $"PBKDF2.V1$1000${saltBase64}${new string('A', 129)}"));

        // 2. Legacy spoofed Argon2id hash verified via Composite fallback to LegacyPbkdf2PasswordHasher
        var legacy = new LegacyPbkdf2PasswordHasher(memorySizeKb: 1024, iterations: 1, parallelism: 1);
        var spoofedHash = legacy.HashPassword("SpoofedPass");
        // Replace prefix with $argon2id$ to simulate legacy spoofed hash
        var spoofedArgonHash = string.Concat("$argon2id$", spoofedHash.AsSpan("$legacy-pbkdf2$".Length));

        // When passed to Composite, genuine Argon2id verification fails, and fallback to LegacyPbkdf2PasswordHasher succeeds!
        var fallbackResult = composite.VerifyPassword("SpoofedPass", spoofedArgonHash);
        Assert.Equal(PasswordVerificationResult.SuccessRehashNeeded, fallbackResult);
    }

    [Fact]
    public void PasswordHasher_ComprehensiveBoundaries_And_EdgeCases()
    {
        // 1. Argon2id properties & NeedsRehash missing params
        Assert.True(Argon2idPasswordHasher.IsMemoryHard);
        Assert.Equal("Argon2id (RFC 9106)", Argon2idPasswordHasher.SubstrateDescription);

        var argon1 = new Argon2idPasswordHasher(iterations: 1, memorySizeKb: 65536, parallelism: 4);
        Assert.True(argon1.NeedsRehash("invalid"));
        Assert.True(argon1.NeedsRehash("$argon2id$v=19$m=65536,p=4$c2FsdHNhbHQ$aGFzaGhhc2hoYXNo")); // missing t=
        Assert.True(argon1.NeedsRehash("$argon2id$v=19$t=1,p=4$c2FsdHNhbHQ$aGFzaGhhc2hoYXNo")); // missing m=
        Assert.True(argon1.NeedsRehash("$argon2id$v=19$t=1,m=65536$c2FsdHNhbHQ$aGFzaGhhc2hoYXNo")); // missing p=

        // 2. Pbkdf2PasswordHasher NeedsRehash with PBKDF2.V1
        var pbkdf2 = new Pbkdf2PasswordHasher(iterations: 10_000);
        Assert.True(pbkdf2.NeedsRehash("PBKDF2.V1$1000$c2FsdHNhbHQ$aGFzaGhhc2hoYXNo"));
        Assert.False(pbkdf2.NeedsRehash("PBKDF2.V1$10000$c2FsdHNhbHQ$aGFzaGhhc2hoYXNo"));
        Assert.False(pbkdf2.NeedsRehash("PBKDF2.V1$20000$c2FsdHNhbHQ$aGFzaGhhc2hoYXNo"));
        Assert.True(pbkdf2.NeedsRehash("PBKDF2.V1$malformed"));
        Assert.True(pbkdf2.NeedsRehash("PBKDF2.V1$notanumber$c2FsdHNhbHQ$aGFzaGhhc2hoYXNo"));

        // 3. CompositePasswordHasher PBKDF2.V1 boundary tests
        var composite = new CompositePasswordHasher(primaryHasher: pbkdf2);

        // ExpectedHash exact boundaries (16 bytes and 128 bytes)
        byte[] salt64 = new byte[48]; // base64 len 64
        string salt64Str = Convert.ToBase64String(salt64);

        // 16 bytes hash (boundary min)
        byte[] derived16 = System.Security.Cryptography.Rfc2898DeriveBytes.Pbkdf2("p", salt64, 1000, System.Security.Cryptography.HashAlgorithmName.SHA512, 16);
        string hash16Str = Convert.ToBase64String(derived16);
        Assert.Equal(PasswordVerificationResult.SuccessRehashNeeded, composite.VerifyPassword("p", $"PBKDF2.V1$1000${salt64Str}${hash16Str}"));

        // 15 bytes hash (invalid)
        byte[] derived15 = new byte[15];
        string hash15Str = Convert.ToBase64String(derived15);
        Assert.Equal(PasswordVerificationResult.Failed, composite.VerifyPassword("p", $"PBKDF2.V1$1000${salt64Str}${hash15Str}"));

        // 64 bytes hash (boundary max)
        byte[] derived64 = System.Security.Cryptography.Rfc2898DeriveBytes.Pbkdf2("p", salt64, 1000, System.Security.Cryptography.HashAlgorithmName.SHA512, 64);
        string hash64Str = Convert.ToBase64String(derived64);
        Assert.Equal(PasswordVerificationResult.SuccessRehashNeeded, composite.VerifyPassword("p", $"PBKDF2.V1$1000${salt64Str}${hash64Str}"));

        // 65 bytes hash (invalid)
        byte[] derived65 = new byte[65];
        string hash65Str = Convert.ToBase64String(derived65);
        Assert.Equal(PasswordVerificationResult.Failed, composite.VerifyPassword("p", $"PBKDF2.V1$1000${salt64Str}${hash65Str}"));

        // 600,000 iterations (boundary max)
        byte[] derived600k = System.Security.Cryptography.Rfc2898DeriveBytes.Pbkdf2("p", salt64, 600_000, System.Security.Cryptography.HashAlgorithmName.SHA512, 16);
        string hash600kStr = Convert.ToBase64String(derived600k);
        Assert.Equal(PasswordVerificationResult.SuccessRehashNeeded, composite.VerifyPassword("p", $"PBKDF2.V1$600000${salt64Str}${hash600kStr}"));

        // Invalid base64 in PBKDF2.V1 (FormatException catch branch)
        Assert.Equal(PasswordVerificationResult.Failed, composite.VerifyPassword("p", "PBKDF2.V1$1000$notbase64!$notbase64!"));
    }
}
