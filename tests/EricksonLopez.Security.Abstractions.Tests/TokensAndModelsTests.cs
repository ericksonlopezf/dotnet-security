// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Abstractions.Tests;

using System;
using System.Collections.Generic;
using EricksonLopez.Security.Abstractions.Cryptography;
using EricksonLopez.Security.Abstractions.Events;
using EricksonLopez.Security.Abstractions.Policies;
using EricksonLopez.Security.Abstractions.Primitives;
using EricksonLopez.Security.Abstractions.Tokens;
using Xunit;

public sealed class TokensAndModelsTests
{
    [Fact]
    public void ApiKeyIssuanceResult_Properties_Match()
    {
        var now = DateTimeOffset.UtcNow;
        var keyId = ApiKeyId.New();
        var key = new ApiKey(
            Id: keyId,
            OwnerId: "user-99",
            Name: "Integration Key",
            DisplayPrefix: "ek_live_***",
            HashedSecret: "hashed-val",
            CreatedAtUtc: now,
            ExpiresAtUtc: now.AddDays(30),
            RevokedAtUtc: null,
            Scopes: new HashSet<string> { "read:all" });

        var issuance = new ApiKeyIssuanceResult(key, "ek_live_secret_plaintext_key");

        Assert.Same(key, issuance.Key);
        Assert.Equal("ek_live_secret_plaintext_key", issuance.PlaintextApiKey);

        // Verify all record properties on ApiKey
        Assert.Equal(keyId, key.Id);
        Assert.Equal("user-99", key.OwnerId);
        Assert.Equal("Integration Key", key.Name);
        Assert.Equal("ek_live_***", key.DisplayPrefix);
        Assert.Equal("hashed-val", key.HashedSecret);
        Assert.Equal(now, key.CreatedAtUtc);
        Assert.Equal(now.AddDays(30), key.ExpiresAtUtc);
        Assert.Null(key.RevokedAtUtc);
        Assert.NotNull(key.Scopes);
        Assert.Contains("read:all", key.Scopes);
    }

    [Fact]
    public void KeyMetadata_AllProperties_Match()
    {
        var now = DateTimeOffset.UtcNow;
        var keyId = KeyIdentifier.New();
        var meta = new KeyMetadata(
            KeyId: keyId,
            Version: KeyVersion.Initial,
            Purpose: KeyPurpose.KeyWrapping,
            Status: KeyStatus.Active,
            AlgorithmId: "AES-256-KW",
            CreatedAtUtc: now,
            ExpiresAtUtc: now.AddDays(90),
            RevokedAtUtc: null);

        Assert.Equal(keyId, meta.KeyId);
        Assert.Equal(KeyVersion.Initial, meta.Version);
        Assert.Equal(KeyPurpose.KeyWrapping, meta.Purpose);
        Assert.Equal(KeyStatus.Active, meta.Status);
        Assert.Equal("AES-256-KW", meta.AlgorithmId);
        Assert.Equal(now, meta.CreatedAtUtc);
        Assert.Equal(now.AddDays(90), meta.ExpiresAtUtc);
        Assert.Null(meta.RevokedAtUtc);
    }

    [Fact]
    public void Policies_AllProperties_Match()
    {
        var keyPol = new KeyRotationPolicy(TimeSpan.FromDays(30), TimeSpan.FromDays(60), AeadAlgorithm.ChaCha20Poly1305);
        Assert.Equal(TimeSpan.FromDays(30), keyPol.RotationInterval);
        Assert.Equal(TimeSpan.FromDays(60), keyPol.RetirementGracePeriod);
        Assert.Equal(AeadAlgorithm.ChaCha20Poly1305, keyPol.PreferredAlgorithm);

        var tokenPol = new TokenPolicy(48, TimeSpan.FromDays(7));
        Assert.Equal(48, tokenPol.MinimumByteLength);
        Assert.Equal(TimeSpan.FromDays(7), tokenPol.MaxLifetime);

        var apiKeyPol = new ApiKeyPolicy(64, TimeSpan.FromDays(180), true);
        Assert.Equal(64, apiKeyPol.SecretByteLength);
        Assert.Equal(TimeSpan.FromDays(180), apiKeyPol.MaxLifetime);
        Assert.True(apiKeyPol.RequireExpiration);

        var pwdPol = new PasswordPolicy(16, 64, true, true, true, true, 2);
        Assert.Equal(16, pwdPol.MinimumLength);
        Assert.Equal(64, pwdPol.MaximumLength);
        Assert.True(pwdPol.RequireDigit);
        Assert.True(pwdPol.RequireUppercase);
        Assert.True(pwdPol.RequireLowercase);
        Assert.True(pwdPol.RequireNonAlphanumeric);
        Assert.Equal(2, pwdPol.MaxConsecutiveRepeatedChars);
    }

    [Fact]
    public void Events_AllRecordProperties_Match()
    {
        var evt1 = ApiKeyCreatedEvent.Create(ApiKeyId.New(), "owner-1", "ek_live_***", "t1", "a1");
        Assert.Equal("owner-1", evt1.OwnerId);
        Assert.Equal("ek_live_***", evt1.DisplayPrefix);

        var evt2 = ApiKeyRevokedEvent.Create(ApiKeyId.New(), "owner-2", "security incident", "t2", "a2");
        Assert.Equal("owner-2", evt2.OwnerId);
        Assert.Equal("security incident", evt2.Reason);

        var evt3 = KeyRevokedEvent.Create(KeyIdentifier.New(), KeyVersion.Initial, KeyPurpose.Signing, "leaked key", "t3", "a3");
        Assert.Equal(KeyPurpose.Signing, evt3.Purpose);
        Assert.Equal("leaked key", evt3.Reason);

        var evt4 = KeyRotatedEvent.Create(KeyIdentifier.New(), KeyVersion.Initial, KeyVersion.Initial.Next(), KeyPurpose.Encryption, "t4", "a4");
        Assert.Equal(KeyPurpose.Encryption, evt4.Purpose);

        var evt5 = SecretRotatedEvent.Create("DbSecret", "t5", "a5");
        Assert.Equal("DbSecret", evt5.SecretName);

        var evt6 = SecurityPolicyViolatedEvent.Create("TokenPolicy", "Too short", "/auth", "t6", "a6");
        Assert.Equal("TokenPolicy", evt6.PolicyName);
        Assert.Equal("Too short", evt6.ViolationDetails);
        Assert.Equal("/auth", evt6.TargetResource);
    }

    private sealed class DefaultTokenGenerator : ITokenGenerator
    {
        public OpaqueToken GenerateToken(int byteLength = 32) => throw new NotImplementedException();
        public string GenerateUrlSafeToken(int byteLength = 32) => "TOKEN_123456";
        public string GenerateHexToken(int byteLength = 32) => "abcdef";
        public string GenerateNumericCode(int digits = 6) => "123456";
    }

    [Fact]
    public void ITokenGenerator_TryGenerateUrlSafeToken_DefaultImplementation_Tests()
    {
        ITokenGenerator generator = new DefaultTokenGenerator();
        Span<char> tooSmall = stackalloc char[5];
        bool failed = generator.TryGenerateUrlSafeToken(tooSmall, 32, out int charsWritten);
        Assert.False(failed);
        Assert.Equal(0, charsWritten);

        Span<char> exact = stackalloc char[12];
        bool success = generator.TryGenerateUrlSafeToken(exact, 32, out charsWritten);
        Assert.True(success);
        Assert.Equal(12, charsWritten);
        Assert.Equal("TOKEN_123456", exact.ToString());
    }
}

