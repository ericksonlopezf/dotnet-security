// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.AspNetCore.Tests;

using System;
using AwesomeAssertions;
using EricksonLopez.Security.AspNetCore.Identity;
using EricksonLopez.Security.Passwords;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

public sealed class IdentityPasswordHasherBridgeTests
{
    private sealed class TestUser
    {
        public string Email { get; set; } = "user@example.com";
    }

    [Fact]
    public void Bridge_NullHasher_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => new IdentityPasswordHasherBridge<TestUser>(null!));
    }

    [Fact]
    public void Bridge_HashPassword_ProducesValidHash()
    {
        var hasher = LegacyPbkdf2PasswordHasher.Default;
        var bridge = new IdentityPasswordHasherBridge<TestUser>(hasher);
        var user = new TestUser();

        var hash = bridge.HashPassword(user, "SecurePass123!");

        hash.Should().NotBeNullOrWhiteSpace();
        hash.Should().StartWith("$legacy-pbkdf2$");
    }

    [Fact]
    public void Bridge_VerifyHashedPassword_Success_OnValidPassword()
    {
        var hasher = LegacyPbkdf2PasswordHasher.Default;
        var bridge = new IdentityPasswordHasherBridge<TestUser>(hasher);
        var user = new TestUser();

        var hash = bridge.HashPassword(user, "SecurePass123!");
        var result = bridge.VerifyHashedPassword(user, hash, "SecurePass123!");

        result.Should().Be(PasswordVerificationResult.Success);
    }

    [Fact]
    public void Bridge_VerifyHashedPassword_Failed_OnInvalidPassword()
    {
        var hasher = LegacyPbkdf2PasswordHasher.Default;
        var bridge = new IdentityPasswordHasherBridge<TestUser>(hasher);
        var user = new TestUser();

        var hash = bridge.HashPassword(user, "SecurePass123!");
        var result = bridge.VerifyHashedPassword(user, hash, "WrongPass123!");

        result.Should().Be(PasswordVerificationResult.Failed);
    }

    [Fact]
    public void Bridge_VerifyHashedPassword_SuccessRehashNeeded_OnLegacyHash()
    {
        var legacyHasher = Pbkdf2PasswordHasher.Default;
        var composite = new CompositePasswordHasher(
            primaryHasher: LegacyPbkdf2PasswordHasher.Default,
            additionalHashers: [legacyHasher]);

        var bridge = new IdentityPasswordHasherBridge<TestUser>(composite);
        var user = new TestUser();

        var legacyHash = legacyHasher.HashPassword("OldLegacyPass123!");
        var result = bridge.VerifyHashedPassword(user, legacyHash, "OldLegacyPass123!");

        result.Should().Be(PasswordVerificationResult.SuccessRehashNeeded);
    }

    private sealed class AlwaysSuccessPasswordHasher : EricksonLopez.Security.Abstractions.Passwords.IPasswordHasher
    {
        public EricksonLopez.Security.Abstractions.Passwords.PasswordHashAlgorithm Algorithm =>
            EricksonLopez.Security.Abstractions.Passwords.PasswordHashAlgorithm.Argon2id;

        public string HashPassword(ReadOnlySpan<char> password) => "mock_hash";

        public EricksonLopez.Security.Abstractions.Passwords.PasswordVerificationResult VerifyPassword(
            ReadOnlySpan<char> password, string hashedPassword)
        {
            return EricksonLopez.Security.Abstractions.Passwords.PasswordVerificationResult.Success;
        }

        public bool NeedsRehash(string hashedPassword) => false;
    }

    [Theory]
    [InlineData(null, "Pass123!")]
    [InlineData("", "Pass123!")]
    [InlineData("hash", null)]
    [InlineData("hash", "")]
    public void Bridge_VerifyHashedPassword_NullOrEmptyInputs_ReturnsFailed(string? hashedPassword, string? providedPassword)
    {
        var hasher = new AlwaysSuccessPasswordHasher();
        var bridge = new IdentityPasswordHasherBridge<TestUser>(hasher);
        var user = new TestUser();

        var result = bridge.VerifyHashedPassword(user, hashedPassword!, providedPassword!);

        result.Should().Be(PasswordVerificationResult.Failed);
    }

    [Fact]
    public void Bridge_HashPassword_NullPassword_ThrowsArgumentNullException()
    {
        var hasher = LegacyPbkdf2PasswordHasher.Default;
        var bridge = new IdentityPasswordHasherBridge<TestUser>(hasher);
        var user = new TestUser();

        Assert.Throws<ArgumentNullException>(() => bridge.HashPassword(user, null!));
    }

    [Fact]
    public void AddEricksonLopezIdentityPasswordHasher_RegistersBridgeInDI()
    {
        var services = new ServiceCollection();
        services.AddSingleton<EricksonLopez.Security.Abstractions.Passwords.IPasswordHasher>(LegacyPbkdf2PasswordHasher.Default);
        services.AddEricksonLopezIdentityPasswordHasher<TestUser>();

        var provider = services.BuildServiceProvider();
        var hasher = provider.GetService<IPasswordHasher<TestUser>>();

        hasher.Should().NotBeNull();
        hasher.Should().BeOfType<IdentityPasswordHasherBridge<TestUser>>();
    }
}
