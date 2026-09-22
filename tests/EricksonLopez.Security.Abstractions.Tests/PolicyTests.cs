// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Abstractions.Tests;

using System;
using EricksonLopez.Security.Abstractions.Cryptography;
using EricksonLopez.Security.Abstractions.Policies;
using EricksonLopez.Security.Abstractions.Primitives;
using Xunit;

public sealed class PolicyTests
{
    // ==========================================
    // PasswordPolicy Tests
    // ==========================================

    [Fact]
    public void PasswordPolicy_DefaultAndNist_Configurations_AreCorrect()
    {
        var def = PasswordPolicy.Default;
        Assert.Equal(12, def.MinimumLength);
        Assert.Equal(128, def.MaximumLength);
        Assert.True(def.RequireDigit);
        Assert.True(def.RequireUppercase);
        Assert.True(def.RequireLowercase);
        Assert.True(def.RequireNonAlphanumeric);
        Assert.Equal(3, def.MaxConsecutiveRepeatedChars);

        var nist = PasswordPolicy.NistAligned;
        Assert.Equal(15, nist.MinimumLength);
        Assert.Equal(128, nist.MaximumLength);
        Assert.False(nist.RequireDigit);
        Assert.False(nist.RequireUppercase);
        Assert.False(nist.RequireLowercase);
        Assert.False(nist.RequireNonAlphanumeric);
        Assert.Equal(4, nist.MaxConsecutiveRepeatedChars);
    }

    [Fact]
    public void PasswordPolicy_NullOrInvalidString_ReturnsPolicyViolation()
    {
        var policy = PasswordPolicy.Default;
        var result = policy.Validate((string)null!);

        Assert.True(result.IsFailure);
        Assert.Equal("Security.PolicyViolation", result.Error.Code);
        Assert.Contains("Password cannot be null.", result.Error.Description);
    }

    [Fact]
    public void PasswordPolicy_ReadOnlyMemory_ValidatesCorrectly()
    {
        var policy = PasswordPolicy.Default;
        ReadOnlyMemory<char> memory = "CorrectHorseBatteryStaple!123".AsMemory();

        var result = policy.Validate(memory);
        Assert.True(result.IsSuccess);
    }

    [Fact]
    public void PasswordPolicy_LengthBoundaries_Enforced()
    {
        var policy = new PasswordPolicy(MinimumLength: 8, MaximumLength: 16);

        // Too short (< 8)
        var shortRes = policy.Validate("Ab1!xyz");
        Assert.True(shortRes.IsFailure);
        Assert.Contains("less than required minimum (8)", shortRes.Error.Description);

        // Min length (8)
        var minRes = policy.Validate("Ab1!xyzw");
        Assert.True(minRes.IsSuccess);

        // Max length (16)
        var maxRes = policy.Validate("Ab1!xyzwAb1!xyzw");
        Assert.True(maxRes.IsSuccess);

        // Too long (> 16)
        var longRes = policy.Validate("Ab1!xyzwAb1!xyzwA");
        Assert.True(longRes.IsFailure);
        Assert.Contains("exceeds maximum allowed (16)", longRes.Error.Description);
    }

    [Fact]
    public void PasswordPolicy_CharacterClasses_Enforced()
    {
        var policy = PasswordPolicy.Default;

        // Missing digit
        var noDigitRes = policy.Validate("Abcdefghijk!@#");
        Assert.True(noDigitRes.IsFailure);
        Assert.Contains("at least one numeric digit", noDigitRes.Error.Description);

        // Missing uppercase
        var noUpperRes = policy.Validate("abcdefghijk!123");
        Assert.True(noUpperRes.IsFailure);
        Assert.Contains("at least one uppercase letter", noUpperRes.Error.Description);

        // Missing lowercase
        var noLowerRes = policy.Validate("ABCDEFGHIJK!123");
        Assert.True(noLowerRes.IsFailure);
        Assert.Contains("at least one lowercase letter", noLowerRes.Error.Description);

        // Missing special
        var noSpecialRes = policy.Validate("Abcdefghijk12345");
        Assert.True(noSpecialRes.IsFailure);
        Assert.Contains("at least one special character", noSpecialRes.Error.Description);
    }

    [Fact]
    public void PasswordPolicy_ConsecutiveRepeatedChars_EnforcedAndReset()
    {
        // Limit: 2 consecutive chars allowed, 3 disallowed
        var policy = new PasswordPolicy(MinimumLength: 6, MaxConsecutiveRepeatedChars: 2);

        // 3 consecutive identical chars -> failure
        var failRes = policy.Validate("Abcdeeef!1");
        Assert.True(failRes.IsFailure);
        Assert.Contains("more than 2 consecutive repeated characters ('e')", failRes.Error.Description);

        // 2 consecutive 'e's then reset with 'f', then 2 'g's -> success
        var passRes = policy.Validate("Abcdeefgg!1");
        Assert.True(passRes.IsSuccess);

        // First character null character test (i == 0 check)
        var policyNoSpecialReq = new PasswordPolicy(MinimumLength: 2, RequireDigit: false, RequireUppercase: false, RequireLowercase: false, RequireNonAlphanumeric: false, MaxConsecutiveRepeatedChars: 1);
        var twoCharsDifferent = policyNoSpecialReq.Validate("ab");
        Assert.True(twoCharsDifferent.IsSuccess);
        var twoCharsSame = policyNoSpecialReq.Validate("aa");
        Assert.True(twoCharsSame.IsFailure);
        Assert.Contains("more than 1 consecutive repeated characters ('a')", twoCharsSame.Error.Description);

        // Starting with \0 must not increment consecutive count at i=0
        var nullPrefixPass = policyNoSpecialReq.Validate("\0ab");
        Assert.True(nullPrefixPass.IsSuccess);

        // MaxConsecutiveRepeatedChars = 0 disables consecutive check
        var disabledPolicy = new PasswordPolicy(MinimumLength: 6, MaxConsecutiveRepeatedChars: 0);
        var disabledRes = disabledPolicy.Validate("Abcdeeeeee!1");
        Assert.True(disabledRes.IsSuccess);
    }

    // ==========================================
    // KeyRotationPolicy Tests
    // ==========================================

    [Fact]
    public void Validate_KeyMetadataUnderVariousAgesAndStatuses_ValidatesExpectedResult()
    {
        Assert.NotNull(KeyRotationPolicy.Default);
        Assert.Equal(TimeSpan.FromDays(90), KeyRotationPolicy.Default.RotationInterval);
        Assert.Equal(TimeSpan.FromDays(365), KeyRotationPolicy.Default.RetirementGracePeriod);
        Assert.Equal(AeadAlgorithm.Aes256Gcm, KeyRotationPolicy.Default.PreferredAlgorithm);

        var interval = TimeSpan.FromDays(90);
        var policy = new KeyRotationPolicy(interval, TimeSpan.FromDays(365));

        // Null target
        var nullRes = policy.Validate(null!);
        Assert.True(nullRes.IsFailure);
        Assert.Equal("Security.PolicyViolation", nullRes.Error.Code);
        Assert.Contains("Key metadata cannot be null.", nullRes.Error.Description);

        var keyId = KeyIdentifier.New();

        // Active key within rotation interval (< 90 days)
        var freshKey = new KeyMetadata(
            KeyId: keyId,
            Version: KeyVersion.Initial,
            Purpose: KeyPurpose.Encryption,
            Status: KeyStatus.Active,
            AlgorithmId: "AES-256-GCM",
            CreatedAtUtc: DateTimeOffset.UtcNow.AddDays(-30));
        Assert.True(policy.Validate(freshKey).IsSuccess);

        // Key within boundary (e.g. 89 days old)
        var boundaryKey = freshKey with { CreatedAtUtc = DateTimeOffset.UtcNow - interval + TimeSpan.FromDays(1) };
        Assert.True(policy.Validate(boundaryKey).IsSuccess);

        // Exact boundary: age == RotationInterval (must pass!)
        var testNow = DateTimeOffset.UtcNow;
        var exactAgeKey = freshKey with { CreatedAtUtc = testNow - interval };
        Assert.True(policy.Validate(exactAgeKey, testNow).IsSuccess);

        // Active key exceeding rotation interval (> 90 days)
        var oldKey = freshKey with { CreatedAtUtc = DateTimeOffset.UtcNow.AddDays(-91) };
        var oldRes = policy.Validate(oldKey);
        Assert.True(oldRes.IsFailure);
        Assert.Contains("exceeds rotation interval", oldRes.Error.Description);

        // Retired key older than rotation interval -> should not trigger rotation violation
        var retiredKey = oldKey with { Status = KeyStatus.Retired };
        Assert.True(policy.Validate(retiredKey).IsSuccess);
    }

    // ==========================================
    // ApiKeyPolicy Tests
    // ==========================================

    [Fact]
    public void Validate_ApiKeyUnderVariousLifetimesAndConfigs_ValidatesExpectedResult()
    {
        Assert.True(ApiKeyPolicy.Default.RequireExpiration);
        Assert.Equal(32, ApiKeyPolicy.Default.SecretByteLength);
        Assert.Equal(TimeSpan.FromDays(365), ApiKeyPolicy.Default.MaxLifetime);

        var maxLifetime = TimeSpan.FromDays(365);
        var policy = new ApiKeyPolicy(SecretByteLength: 32, MaxLifetime: maxLifetime, RequireExpiration: true);
        var now = DateTimeOffset.UtcNow;

        // Null target
        var nullRes = policy.Validate(null!);
        Assert.True(nullRes.IsFailure);
        Assert.Contains("API key cannot be null.", nullRes.Error.Description);

        var validKey = new ApiKey(
            Id: ApiKeyId.New(),
            OwnerId: "owner-1",
            Name: "Valid Key",
            DisplayPrefix: "ek_live_***",
            HashedSecret: "hash",
            CreatedAtUtc: now,
            ExpiresAtUtc: now.AddDays(180));
        Assert.True(policy.Validate(validKey).IsSuccess);

        // Exact boundary: lifetime == MaxLifetime (must pass!)
        // If mutated to lifetime >= MaxLifetime, it fails
        var exactBoundaryKey = validKey with { ExpiresAtUtc = now + maxLifetime };
        Assert.True(policy.Validate(exactBoundaryKey).IsSuccess);

        // RequireExpiration = true, but ExpiresAtUtc is null
        var noExpKey = validKey with { ExpiresAtUtc = null };
        var noExpRes = policy.Validate(noExpKey);
        Assert.True(noExpRes.IsFailure);
        Assert.Contains("must define an expiration date", noExpRes.Error.Description);
        Assert.True(ApiKeyPolicy.Default.Validate(noExpKey).IsFailure);

        // RequireExpiration = false, ExpiresAtUtc is null -> success
        var policyNoReqExp = new ApiKeyPolicy(RequireExpiration: false);
        Assert.True(policyNoReqExp.Validate(noExpKey).IsSuccess);

        // Lifetime exceeds MaxLifetime
        var longKey = validKey with { ExpiresAtUtc = now.AddDays(400) };
        var longRes = policy.Validate(longKey);
        Assert.True(longRes.IsFailure);
        Assert.Contains("exceeds maximum allowed", longRes.Error.Description);

        // MaxLifetime is null -> any long duration allowed
        var policyNoMaxLife = new ApiKeyPolicy(MaxLifetime: null, RequireExpiration: true);
        Assert.True(policyNoMaxLife.Validate(longKey).IsSuccess);
    }

    // ==========================================
    // TokenPolicy Tests
    // ==========================================

    [Fact]
    public void Validate_OpaqueTokenUnderVariousLengths_ValidatesExpectedResult()
    {
        Assert.NotNull(TokenPolicy.Default);
        Assert.Equal(32, TokenPolicy.Default.MinimumByteLength);
        Assert.Equal(TimeSpan.FromDays(30), TokenPolicy.Default.MaxLifetime);

        var policy = new TokenPolicy(MinimumByteLength: 32, MaxLifetime: TimeSpan.FromDays(30));

        // Empty token
        OpaqueToken defToken = default;
        var emptyRes = policy.Validate(defToken);
        Assert.True(emptyRes.IsFailure);
        Assert.Contains("Token cannot be empty.", emptyRes.Error.Description);

        // Short token (< 32)
        var shortToken = new OpaqueToken("short-token-12345"); // 17 chars
        var shortRes = policy.Validate(shortToken);
        Assert.True(shortRes.IsFailure);
        Assert.Contains("less than required minimum length (32)", shortRes.Error.Description);

        // Exact boundary: Length == 32 (must pass!)
        // If mutated to target.Length <= MinimumByteLength, it fails
        var exactToken = new OpaqueToken("12345678901234567890123456789012"); // exactly 32 chars
        Assert.Equal(32, exactToken.Length);
        Assert.True(policy.Validate(exactToken).IsSuccess);

        // Valid length token (> 32 chars)
        var validToken = new OpaqueToken("this-is-a-valid-opaque-token-with-sufficient-entropy-123456789");
        Assert.True(policy.Validate(validToken).IsSuccess);
    }
}
