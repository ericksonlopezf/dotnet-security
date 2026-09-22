// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Testing.Tests;

using System;
using AwesomeAssertions;
using EricksonLopez.Security.Abstractions.Passwords;
using EricksonLopez.Security.Testing.Fakes;
using Xunit;

public sealed class FakePasswordHasherTests
{
    [Fact]
    public void HashPassword_ProducesPrefixedDeterministicHash()
    {
        var hasher = new FakePasswordHasher();
        var hash = hasher.HashPassword("SecretPassword123!");

        hash.Should().StartWith("$fake_test_hash$");
        hash.Should().Contain("SecretPassword123!");
    }

    [Fact]
    public void VerifyPassword_CorrectPassword_ReturnsSuccess()
    {
        var hasher = new FakePasswordHasher();
        var hash = hasher.HashPassword("CorrectPassword");

        var result = hasher.VerifyPassword("CorrectPassword", hash);
        result.Should().Be(PasswordVerificationResult.Success);
    }

    [Fact]
    public void VerifyPassword_IncorrectPassword_ReturnsFailed()
    {
        var hasher = new FakePasswordHasher();
        var hash = hasher.HashPassword("CorrectPassword");

        var result = hasher.VerifyPassword("WrongPassword", hash);
        result.Should().Be(PasswordVerificationResult.Failed);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("invalid_hash_prefix")]
    [InlineData("wrongprefix_password")]
    [InlineData("1234567890123456password")]
    public void VerifyPassword_InvalidHash_ReturnsFailed(string invalidHash)
    {
        var hasher = new FakePasswordHasher();
        var result = hasher.VerifyPassword("password", invalidHash);
        result.Should().Be(PasswordVerificationResult.Failed);
    }

    [Fact]
    public void VerifyPassword_WithSimulateNeedsRehash_ReturnsSuccessRehashNeeded()
    {
        var hasher = new FakePasswordHasher
        {
            SimulateNeedsRehash = true
        };

        var hash = hasher.HashPassword("password");
        var result = hasher.VerifyPassword("password", hash);
        result.Should().Be(PasswordVerificationResult.SuccessRehashNeeded);
        hasher.NeedsRehash(hash).Should().BeTrue();
    }

    [Fact]
    public void Algorithm_ReturnsPbkdf2HmacSha512()
    {
        var hasher = new FakePasswordHasher();
        hasher.Algorithm.Should().Be(PasswordHashAlgorithm.Pbkdf2HmacSha512);
    }
}
