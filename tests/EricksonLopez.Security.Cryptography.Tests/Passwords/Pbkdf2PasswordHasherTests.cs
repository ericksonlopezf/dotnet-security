// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Cryptography.Tests.Passwords;

using System;
using EricksonLopez.Security.Abstractions.Passwords;
using EricksonLopez.Security.Cryptography.Passwords;
using EricksonLopez.Security.Cryptography.Randomness;
using AwesomeAssertions;
using Xunit;

public sealed class Pbkdf2PasswordHasherTests
{
    private readonly Pbkdf2PasswordHasher _sut;
    private readonly Pbkdf2PasswordHasher _defaultSut;

    public Pbkdf2PasswordHasherTests()
    {
        var comparer = new ConstantTimeComparer();
        var random = new CryptographicRandomNumberGenerator();
        _sut = new Pbkdf2PasswordHasher(comparer, random, 1000);
        _defaultSut = new Pbkdf2PasswordHasher(comparer, random);
    }

    [Fact]
    public void Constructor_NullArguments_ThrowsArgumentNullException()
    {
        var comparer = new ConstantTimeComparer();
        var random = new CryptographicRandomNumberGenerator();

        Assert.Throws<ArgumentNullException>(() => new Pbkdf2PasswordHasher(null!, random));
        Assert.Throws<ArgumentNullException>(() => new Pbkdf2PasswordHasher(comparer, null!));
        Assert.Throws<ArgumentNullException>(() => new Pbkdf2PasswordHasher(null!, random, 1000));
        Assert.Throws<ArgumentNullException>(() => new Pbkdf2PasswordHasher(comparer, null!, 1000));
    }

    [Fact]
    public void Constructor_InvalidIterations_ThrowsArgumentOutOfRangeException()
    {
        var comparer = new ConstantTimeComparer();
        var random = new CryptographicRandomNumberGenerator();

        Assert.Throws<ArgumentOutOfRangeException>(() => new Pbkdf2PasswordHasher(comparer, random, 500));
        Assert.Throws<ArgumentOutOfRangeException>(() => new Pbkdf2PasswordHasher(comparer, random, 1_000_000));
    }

    [Fact]
    public void Algorithm_ReturnsPbkdf2HmacSha512()
    {
        _sut.Algorithm.Should().Be(PasswordHashAlgorithm.Pbkdf2HmacSha512);
        _defaultSut.Algorithm.Should().Be(PasswordHashAlgorithm.Pbkdf2HmacSha512);
    }

    [Fact]
    public void HashPassword_GeneratesValidFormat_And_RandomSalt()
    {
        var password = "MySecurePassword123!".AsSpan();

        var hash1 = _defaultSut.HashPassword(password);
        var hash2 = _defaultSut.HashPassword(password);

        hash1.Should().StartWith($"PBKDF2.V1${Pbkdf2PasswordHasher.DefaultIterations}$");
        hash1.Split('$').Should().HaveCount(4);

        // Different salts produce different hashes
        hash1.Should().NotBe(hash2);
    }

    [Fact]
    public void VerifyPassword_WithCorrectPassword_ReturnsSuccess()
    {
        var chars = "MySecurePassword123!".AsSpan();
        var hash = _sut.HashPassword(chars);

        var result = _sut.VerifyPassword(chars, hash);
        result.Should().Be(PasswordVerificationResult.Success);
    }

    [Fact]
    public void VerifyPassword_WithIncorrectPassword_ReturnsFailed()
    {
        var chars = "MySecurePassword123!".AsSpan();
        var hash = _sut.HashPassword(chars);

        var wrongChars = "WrongPassword".AsSpan();
        var result = _sut.VerifyPassword(wrongChars, hash);
        result.Should().Be(PasswordVerificationResult.Failed);
    }

    [Fact]
    public void VerifyPassword_WithMalformedHashes_ReturnsFailed()
    {
        var password = "password".AsSpan();

        // Null, empty, whitespace
        _sut.VerifyPassword(password, "").Should().Be(PasswordVerificationResult.Failed);
        _sut.VerifyPassword(password, "   ").Should().Be(PasswordVerificationResult.Failed);

        // Wrong parts count
        _sut.VerifyPassword(password, "PBKDF2.V1$1000$salt").Should().Be(PasswordVerificationResult.Failed);
        _sut.VerifyPassword(password, "PBKDF2.V1$1000$salt$hash$extra").Should().Be(PasswordVerificationResult.Failed);

        // Wrong prefix
        _sut.VerifyPassword(password, "ARGON2$1000$c2FsdA==$aGFzaA==").Should().Be(PasswordVerificationResult.Failed);

        var validSaltForPrefix = Convert.ToBase64String(new byte[16]);
        var validDerivedForPrefix = Convert.ToBase64String(System.Security.Cryptography.Rfc2898DeriveBytes.Pbkdf2("password", new byte[16], 1000, System.Security.Cryptography.HashAlgorithmName.SHA512, 32));
        _sut.VerifyPassword(password, $"WRONG.V1$1000${validSaltForPrefix}${validDerivedForPrefix}").Should().Be(PasswordVerificationResult.Failed);

        // Non-integer iterations
        _sut.VerifyPassword(password, "PBKDF2.V1$notanumber$c2FsdA==$aGFzaA==").Should().Be(PasswordVerificationResult.Failed);

        // Non-base64 salt or hash
        _sut.VerifyPassword(password, "PBKDF2.V1$1000$!!!invalid_base64!!!$aGFzaA==").Should().Be(PasswordVerificationResult.Failed);
        _sut.VerifyPassword(password, "PBKDF2.V1$1000$c2FsdA==$!!!invalid_base64!!!").Should().Be(PasswordVerificationResult.Failed);
    }

    [Fact]
    public void VerifyPassword_WithLowerIterations_ReturnsSuccessRehashNeeded()
    {
        // Hash with only 500 iterations (lower than _sut's 1000)
        var salt = Convert.ToBase64String(new byte[16]);
        var derived = System.Security.Cryptography.Rfc2898DeriveBytes.Pbkdf2("myPassword", new byte[16], 500, System.Security.Cryptography.HashAlgorithmName.SHA512, 32);
        var oldHash = $"PBKDF2.V1$500${salt}${Convert.ToBase64String(derived)}";

        var result = _sut.VerifyPassword("myPassword".AsSpan(), oldHash);
        result.Should().Be(PasswordVerificationResult.SuccessRehashNeeded);
    }

    [Fact]
    public void NeedsRehash_ValidatesProperly()
    {
        // Empty or whitespace hashes always need rehashing (they are invalid/missing hashes)
        _defaultSut.NeedsRehash("").Should().BeTrue();
        _defaultSut.NeedsRehash("   ").Should().BeTrue();

        _defaultSut.NeedsRehash("INVALID$HASH").Should().BeTrue();
        _defaultSut.NeedsRehash("OTHER.V1$600000$c2FsdA==$aGFzaA==").Should().BeTrue();
        _defaultSut.NeedsRehash("PBKDF2.V1$not_int$c2FsdA==$aGFzaA==").Should().BeTrue();

        _defaultSut.NeedsRehash("PBKDF2.V1$10000$c2FsdA==$aGFzaA==").Should().BeTrue();
        _defaultSut.NeedsRehash("PBKDF2.V1$600000$c2FsdA==$aGFzaA==").Should().BeFalse();
        _defaultSut.NeedsRehash("PBKDF2.V1$700000$c2FsdA==$aGFzaA==").Should().BeFalse();
    }

    [Fact]
    public void HashPassword_BoundaryLengths_BehavesCorrectly()
    {
        var valid256 = new string('A', 256);
        var hash256 = _sut.HashPassword(valid256.AsSpan());
        hash256.Should().NotBeNullOrWhiteSpace();

        var invalid257 = new string('A', 257);
        var ex = Assert.Throws<ArgumentOutOfRangeException>(() => _sut.HashPassword(invalid257.AsSpan()));
        ex.Message.Should().Contain("Password length cannot exceed 256 characters.");
    }

    [Fact]
    public void VerifyPassword_PasswordAndHashLengthBoundaries_ReturnsExpectedResult()
    {
        var password256 = new string('P', 256);
        var hash256 = _sut.HashPassword(password256.AsSpan());

        _sut.VerifyPassword(password256.AsSpan(), hash256).Should().Be(PasswordVerificationResult.Success);

        var password257 = new string('P', 257);
        _sut.VerifyPassword(password257.AsSpan(), hash256).Should().Be(PasswordVerificationResult.Failed);

        // Hashed password exceeding 512 characters
        var longHash = hash256 + new string('X', 513);
        _sut.VerifyPassword("password".AsSpan(), longHash).Should().Be(PasswordVerificationResult.Failed);

        // Hashed password exactly 512 characters with valid format using padded iterations
        var rawSalt = new byte[16];
        var rawHash = System.Security.Cryptography.Rfc2898DeriveBytes.Pbkdf2("password", rawSalt, 1000, System.Security.Cryptography.HashAlgorithmName.SHA512, 32);
        var baseStr = $"PBKDF2.V1$1000${Convert.ToBase64String(rawSalt)}${Convert.ToBase64String(rawHash)}";
        var neededPadding = 512 - baseStr.Length;
        var paddedIterations = new string('0', neededPadding) + "1000";
        var hash512Valid = $"PBKDF2.V1${paddedIterations}${Convert.ToBase64String(rawSalt)}${Convert.ToBase64String(rawHash)}";
        hash512Valid.Length.Should().Be(512);
        _sut.VerifyPassword("password".AsSpan(), hash512Valid).Should().Be(PasswordVerificationResult.Success);

        // 513 characters fails immediately at line 104
        var hash513 = "0" + hash512Valid;
        hash513.Length.Should().Be(513);
        _sut.VerifyPassword("password".AsSpan(), hash513).Should().Be(PasswordVerificationResult.Failed);
    }

    [Fact]
    public void VerifyPassword_IterationBoundaries_EnforcedProperly()
    {
        var salt = Convert.ToBase64String(new byte[16]);
        var hash = Convert.ToBase64String(new byte[32]);

        // Zero and negative iterations rejected
        _sut.VerifyPassword("pass".AsSpan(), $"PBKDF2.V1$0${salt}${hash}").Should().Be(PasswordVerificationResult.Failed);
        _sut.VerifyPassword("pass".AsSpan(), $"PBKDF2.V1$-1${salt}${hash}").Should().Be(PasswordVerificationResult.Failed);

        // Greater than MaxStoredIterations (600_000) rejected
        _sut.VerifyPassword("pass".AsSpan(), $"PBKDF2.V1$600001${salt}${hash}").Should().Be(PasswordVerificationResult.Failed);

        // Boundary: 1 iteration allowed to proceed
        var derived1 = System.Security.Cryptography.Rfc2898DeriveBytes.Pbkdf2("pass", new byte[16], 1, System.Security.Cryptography.HashAlgorithmName.SHA512, 32);
        var hash1 = $"PBKDF2.V1$1${salt}${Convert.ToBase64String(derived1)}";
        _sut.VerifyPassword("pass".AsSpan(), hash1).Should().Be(PasswordVerificationResult.SuccessRehashNeeded);

        // Boundary: 600_000 iterations allowed to proceed
        var dummyHashMax = $"PBKDF2.V1$600000${salt}${hash}";
        _sut.VerifyPassword("wrong".AsSpan(), dummyHashMax).Should().Be(PasswordVerificationResult.Failed);

        // Boundary: 600_000 iterations with correct password succeeds
        var saltMax = new byte[16];
        var derivedMax = System.Security.Cryptography.Rfc2898DeriveBytes.Pbkdf2("pass", saltMax, 600000, System.Security.Cryptography.HashAlgorithmName.SHA512, 32);
        var hashMaxSuccess = $"PBKDF2.V1$600000${Convert.ToBase64String(saltMax)}${Convert.ToBase64String(derivedMax)}";
        _sut.VerifyPassword("pass".AsSpan(), hashMaxSuccess).Should().Be(PasswordVerificationResult.Success);
    }

    [Fact]
    public void VerifyPassword_Base64AndDecodedBytesBoundaries_EnforcedProperly()
    {
        // 1. Salt string length: min 11, max 128
        var shortSaltStr = new string('A', 10);
        var validHashStr = Convert.ToBase64String(new byte[32]);
        _sut.VerifyPassword("pass".AsSpan(), $"PBKDF2.V1$1000${shortSaltStr}${validHashStr}").Should().Be(PasswordVerificationResult.Failed);

        var longSaltStr = new string('A', 129);
        _sut.VerifyPassword("pass".AsSpan(), $"PBKDF2.V1$1000${longSaltStr}${validHashStr}").Should().Be(PasswordVerificationResult.Failed);

        // 2. Hash string length: min 22, max 128
        var validSaltStr = Convert.ToBase64String(new byte[16]);
        var shortHashStr = new string('A', 21);
        _sut.VerifyPassword("pass".AsSpan(), $"PBKDF2.V1$1000${validSaltStr}${shortHashStr}").Should().Be(PasswordVerificationResult.Failed);

        var longHashStr = new string('A', 129);
        _sut.VerifyPassword("pass".AsSpan(), $"PBKDF2.V1$1000${validSaltStr}${longHashStr}").Should().Be(PasswordVerificationResult.Failed);

        // 3. Decoded byte boundaries:
        // Salt: 8 <= saltBytesWritten <= 64
        var salt7Bytes = Convert.ToBase64String(new byte[7]);
        var derived7 = System.Security.Cryptography.Rfc2898DeriveBytes.Pbkdf2("pass", new byte[7], 1000, System.Security.Cryptography.HashAlgorithmName.SHA512, 32);
        _sut.VerifyPassword("pass".AsSpan(), $"PBKDF2.V1$1000${salt7Bytes}${Convert.ToBase64String(derived7)}").Should().Be(PasswordVerificationResult.Failed);

        var salt8Bytes = Convert.ToBase64String(new byte[8]);
        var derived8 = System.Security.Cryptography.Rfc2898DeriveBytes.Pbkdf2("pass", new byte[8], 1000, System.Security.Cryptography.HashAlgorithmName.SHA512, 32);
        _sut.VerifyPassword("pass".AsSpan(), $"PBKDF2.V1$1000${salt8Bytes}${Convert.ToBase64String(derived8)}").Should().Be(PasswordVerificationResult.Success);

        var salt64Bytes = Convert.ToBase64String(new byte[64]);
        var derived64 = System.Security.Cryptography.Rfc2898DeriveBytes.Pbkdf2("pass", new byte[64], 1000, System.Security.Cryptography.HashAlgorithmName.SHA512, 32);
        _sut.VerifyPassword("pass".AsSpan(), $"PBKDF2.V1$1000${salt64Bytes}${Convert.ToBase64String(derived64)}").Should().Be(PasswordVerificationResult.Success);

        var salt65Bytes = Convert.ToBase64String(new byte[65]);
        var derived65 = System.Security.Cryptography.Rfc2898DeriveBytes.Pbkdf2("pass", new byte[65], 1000, System.Security.Cryptography.HashAlgorithmName.SHA512, 32);
        _sut.VerifyPassword("pass".AsSpan(), $"PBKDF2.V1$1000${salt65Bytes}${Convert.ToBase64String(derived65)}").Should().Be(PasswordVerificationResult.Failed);

        // Hash: 16 <= hashBytesWritten <= 64
        var hash15Bytes = Convert.ToBase64String(new byte[15]);
        _sut.VerifyPassword("pass".AsSpan(), $"PBKDF2.V1$1000${validSaltStr}${hash15Bytes}").Should().Be(PasswordVerificationResult.Failed);

        var hash16Bytes = Convert.ToBase64String(System.Security.Cryptography.Rfc2898DeriveBytes.Pbkdf2("pass", new byte[16], 1000, System.Security.Cryptography.HashAlgorithmName.SHA512, 16));
        _sut.VerifyPassword("pass".AsSpan(), $"PBKDF2.V1$1000${validSaltStr}${hash16Bytes}").Should().Be(PasswordVerificationResult.Success);

        var hash64Bytes = Convert.ToBase64String(System.Security.Cryptography.Rfc2898DeriveBytes.Pbkdf2("pass", new byte[16], 1000, System.Security.Cryptography.HashAlgorithmName.SHA512, 64));
        _sut.VerifyPassword("pass".AsSpan(), $"PBKDF2.V1$1000${validSaltStr}${hash64Bytes}").Should().Be(PasswordVerificationResult.Success);

        var hash65Bytes = Convert.ToBase64String(new byte[65]);
        _sut.VerifyPassword("pass".AsSpan(), $"PBKDF2.V1$1000${validSaltStr}${hash65Bytes}").Should().Be(PasswordVerificationResult.Failed);
    }

    [Fact]
    public void VerifyTier2Pbkdf2Format_ValidHash_ReturnsSuccessRehashNeeded()
    {
        var salt = new byte[16];
        var derived = System.Security.Cryptography.Rfc2898DeriveBytes.Pbkdf2("CorrectPassword", salt, 1000, System.Security.Cryptography.HashAlgorithmName.SHA512, 64);
        var tier2Hash = $"$pbkdf2-sha512$i=1000$s={Convert.ToBase64String(salt)}${Convert.ToBase64String(derived)}";

        _sut.VerifyPassword("CorrectPassword".AsSpan(), tier2Hash).Should().Be(PasswordVerificationResult.SuccessRehashNeeded);
        _sut.VerifyPassword("WrongPassword".AsSpan(), tier2Hash).Should().Be(PasswordVerificationResult.Failed);
        _sut.NeedsRehash(tier2Hash).Should().BeTrue();
    }

    [Fact]
    public void VerifyTier2Pbkdf2Format_MalformedStructure_ReturnsFailed()
    {
        var salt = Convert.ToBase64String(new byte[16]);
        var hash = Convert.ToBase64String(new byte[32]);

        // Missing parts
        _sut.VerifyPassword("pass".AsSpan(), "$pbkdf2-sha512$i=1000").Should().Be(PasswordVerificationResult.Failed);
        _sut.VerifyPassword("pass".AsSpan(), $"$pbkdf2-sha512$i=1000$s={salt}").Should().Be(PasswordVerificationResult.Failed);
        _sut.VerifyPassword("pass".AsSpan(), $"$pbkdf2-sha512$i=1000$s={salt}${hash}$extra").Should().Be(PasswordVerificationResult.Failed);

        // Wrong parameter prefixes
        var saltT2Prefix = new byte[16];
        var derivedT2Prefix = System.Security.Cryptography.Rfc2898DeriveBytes.Pbkdf2("pass", saltT2Prefix, 1000, System.Security.Cryptography.HashAlgorithmName.SHA512, 64);
        _sut.VerifyPassword("pass".AsSpan(), $"$pbkdf2-sha512$x=1000$s={Convert.ToBase64String(saltT2Prefix)}${Convert.ToBase64String(derivedT2Prefix)}").Should().Be(PasswordVerificationResult.Failed);
        _sut.VerifyPassword("pass".AsSpan(), $"$pbkdf2-sha512$i=1000$x={Convert.ToBase64String(saltT2Prefix)}${Convert.ToBase64String(derivedT2Prefix)}").Should().Be(PasswordVerificationResult.Failed);

        // Invalid iterations
        _sut.VerifyPassword("pass".AsSpan(), $"$pbkdf2-sha512$i=abc$s={salt}${hash}").Should().Be(PasswordVerificationResult.Failed);
        _sut.VerifyPassword("pass".AsSpan(), $"$pbkdf2-sha512$i=0$s={salt}${hash}").Should().Be(PasswordVerificationResult.Failed);
        _sut.VerifyPassword("pass".AsSpan(), $"$pbkdf2-sha512$i=-10$s={salt}${hash}").Should().Be(PasswordVerificationResult.Failed);
        _sut.VerifyPassword("pass".AsSpan(), $"$pbkdf2-sha512$i=600001$s={salt}${hash}").Should().Be(PasswordVerificationResult.Failed);

        // Iteration boundary: 1 iteration and 600_000 iterations
        var derived1 = System.Security.Cryptography.Rfc2898DeriveBytes.Pbkdf2("pass", new byte[16], 1, System.Security.Cryptography.HashAlgorithmName.SHA512, 32);
        var hash1 = $"$pbkdf2-sha512$i=1$s={salt}${Convert.ToBase64String(derived1)}";
        _sut.VerifyPassword("pass".AsSpan(), hash1).Should().Be(PasswordVerificationResult.SuccessRehashNeeded);

        var hashMax = $"$pbkdf2-sha512$i=600000$s={salt}${hash}";
        _sut.VerifyPassword("wrong".AsSpan(), hashMax).Should().Be(PasswordVerificationResult.Failed);

        // 600_000 iterations with correct password in Tier 2
        var derivedT2Max = System.Security.Cryptography.Rfc2898DeriveBytes.Pbkdf2("pass", new byte[16], 600000, System.Security.Cryptography.HashAlgorithmName.SHA512, 64);
        var hashT2Max = $"$pbkdf2-sha512$i=600000$s={salt}${Convert.ToBase64String(derivedT2Max)}";
        _sut.VerifyPassword("pass".AsSpan(), hashT2Max).Should().Be(PasswordVerificationResult.SuccessRehashNeeded);
    }

    [Fact]
    public void VerifyTier2Pbkdf2Format_BoundariesAndInvalidBase64_EnforcedProperly()
    {
        var validSaltStr = Convert.ToBase64String(new byte[16]);
        var validHashStr = Convert.ToBase64String(new byte[32]);

        // String length boundaries:
        // parts[2] length: min 13, max 130 (includes "s=")
        _sut.VerifyPassword("pass".AsSpan(), $"$pbkdf2-sha512$i=1000$s={new string('A', 10)}${validHashStr}").Should().Be(PasswordVerificationResult.Failed); // len 12
        _sut.VerifyPassword("pass".AsSpan(), $"$pbkdf2-sha512$i=1000$s={new string('A', 129)}${validHashStr}").Should().Be(PasswordVerificationResult.Failed); // len 131

        // parts[3] length: min 22, max 128
        _sut.VerifyPassword("pass".AsSpan(), $"$pbkdf2-sha512$i=1000$s={validSaltStr}${new string('A', 21)}").Should().Be(PasswordVerificationResult.Failed);
        _sut.VerifyPassword("pass".AsSpan(), $"$pbkdf2-sha512$i=1000$s={validSaltStr}${new string('A', 129)}").Should().Be(PasswordVerificationResult.Failed);

        // Invalid base64 characters
        _sut.VerifyPassword("pass".AsSpan(), $"$pbkdf2-sha512$i=1000$s=invalid!!!base64${validHashStr}").Should().Be(PasswordVerificationResult.Failed);
        _sut.VerifyPassword("pass".AsSpan(), $"$pbkdf2-sha512$i=1000$s={validSaltStr}$invalid!!!base64!").Should().Be(PasswordVerificationResult.Failed);

        // Decoded byte boundaries:
        // Salt: 8 <= saltBytesWritten <= 64
        var salt7Bytes = Convert.ToBase64String(new byte[7]);
        var derivedT2_7 = System.Security.Cryptography.Rfc2898DeriveBytes.Pbkdf2("pass", new byte[7], 1000, System.Security.Cryptography.HashAlgorithmName.SHA512, 64);
        _sut.VerifyPassword("pass".AsSpan(), $"$pbkdf2-sha512$i=1000$s={salt7Bytes}${Convert.ToBase64String(derivedT2_7)}").Should().Be(PasswordVerificationResult.Failed);

        var salt8Bytes = Convert.ToBase64String(new byte[8]);
        var derived8 = System.Security.Cryptography.Rfc2898DeriveBytes.Pbkdf2("pass", new byte[8], 1000, System.Security.Cryptography.HashAlgorithmName.SHA512, 32);
        _sut.VerifyPassword("pass".AsSpan(), $"$pbkdf2-sha512$i=1000$s={salt8Bytes}${Convert.ToBase64String(derived8)}").Should().Be(PasswordVerificationResult.SuccessRehashNeeded);

        var salt64Bytes = Convert.ToBase64String(new byte[64]);
        var derived64 = System.Security.Cryptography.Rfc2898DeriveBytes.Pbkdf2("pass", new byte[64], 1000, System.Security.Cryptography.HashAlgorithmName.SHA512, 32);
        _sut.VerifyPassword("pass".AsSpan(), $"$pbkdf2-sha512$i=1000$s={salt64Bytes}${Convert.ToBase64String(derived64)}").Should().Be(PasswordVerificationResult.SuccessRehashNeeded);

        var salt65Bytes = Convert.ToBase64String(new byte[65]);
        var derivedT2_65 = System.Security.Cryptography.Rfc2898DeriveBytes.Pbkdf2("pass", new byte[65], 1000, System.Security.Cryptography.HashAlgorithmName.SHA512, 64);
        _sut.VerifyPassword("pass".AsSpan(), $"$pbkdf2-sha512$i=1000$s={salt65Bytes}${Convert.ToBase64String(derivedT2_65)}").Should().Be(PasswordVerificationResult.Failed);

        // Hash: 16 <= hashBytesWritten <= 64
        var hash15Bytes = Convert.ToBase64String(new byte[15]);
        _sut.VerifyPassword("pass".AsSpan(), $"$pbkdf2-sha512$i=1000$s={validSaltStr}${hash15Bytes}").Should().Be(PasswordVerificationResult.Failed);

        var hash16Bytes = Convert.ToBase64String(System.Security.Cryptography.Rfc2898DeriveBytes.Pbkdf2("pass", new byte[16], 1000, System.Security.Cryptography.HashAlgorithmName.SHA512, 16));
        _sut.VerifyPassword("pass".AsSpan(), $"$pbkdf2-sha512$i=1000$s={validSaltStr}${hash16Bytes}").Should().Be(PasswordVerificationResult.SuccessRehashNeeded);

        var hash64Bytes = Convert.ToBase64String(System.Security.Cryptography.Rfc2898DeriveBytes.Pbkdf2("pass", new byte[16], 1000, System.Security.Cryptography.HashAlgorithmName.SHA512, 64));
        _sut.VerifyPassword("pass".AsSpan(), $"$pbkdf2-sha512$i=1000$s={validSaltStr}${hash64Bytes}").Should().Be(PasswordVerificationResult.SuccessRehashNeeded);

        var hash65Bytes = Convert.ToBase64String(new byte[65]);
        _sut.VerifyPassword("pass".AsSpan(), $"$pbkdf2-sha512$i=1000$s={validSaltStr}${hash65Bytes}").Should().Be(PasswordVerificationResult.Failed);
    }
}

