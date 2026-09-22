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
}

