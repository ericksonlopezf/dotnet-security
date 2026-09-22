// Copyright © Erickson Lopez. MIT License.
// Regression tests for SEC-005: LegacyPbkdf2PasswordHasher.Algorithm must return Pbkdf2HmacSha512

namespace EricksonLopez.Security.Tests.Passwords;

using AwesomeAssertions;
using EricksonLopez.Security.Abstractions.Passwords;
using EricksonLopez.Security.Passwords;
using Xunit;

/// <summary>
/// Regression tests for SEC-005: LegacyPbkdf2PasswordHasher.Algorithm was incorrectly
/// returning PasswordHashAlgorithm.Argon2id (with #pragma to silence the Obsolete warning),
/// which misled callers into thinking the hasher was memory-hard.
/// </summary>
public sealed class LegacyPbkdf2HasherAlgorithmTests
{
    // ── SEC-005 REGRESSION TESTS ─────────────────────────────────────────────────

    [Fact]
    public void LegacyPbkdf2PasswordHasher_Algorithm_ReturnsPbkdf2HmacSha512_NotArgon2id()
    {
        // Before SEC-005 fix: Algorithm returned PasswordHashAlgorithm.Argon2id (#pragma disabled).
        // This was misleading because Argon2id is memory-hard; PBKDF2 is not.
        // After fix: Algorithm returns Pbkdf2HmacSha512 to correctly describe the actual substrate.
        var hasher = LegacyPbkdf2PasswordHasher.Default;

        hasher.Algorithm.Should().Be(PasswordHashAlgorithm.Pbkdf2HmacSha512,
            because: "LegacyPbkdf2PasswordHasher uses PBKDF2-HMAC-SHA512 as its KDF, not Argon2id");
    }

    [Fact]
    public void LegacyPbkdf2PasswordHasher_IsNotMemoryHard()
    {
        // IsMemoryHard should be false — the class explicitly declares this per ADR-024
        LegacyPbkdf2PasswordHasher.IsMemoryHard.Should().BeFalse(
            because: "PBKDF2-HMAC-SHA512 is not a memory-hard algorithm; Argon2id is needed for that");
    }

    [Fact]
    public void LegacyPbkdf2PasswordHasher_Algorithm_IsNeverArgon2id()
    {
        var hasher = LegacyPbkdf2PasswordHasher.Default;

        // Critical regression: Algorithm must NOT return the obsolete Argon2id value.
        // Code that checks if (hasher.Algorithm == Argon2id) and then assumes GPU-resistance
        // would make incorrect security decisions.
        hasher.Algorithm.Should().NotBe(PasswordHashAlgorithm.Argon2id,
            because: "returning Argon2id misleads callers into believing the hasher is memory-hard when it is not");
    }

    [Fact]
    public void LegacyPbkdf2PasswordHasher_SubstrateDescription_MentionsPbkdf2()
    {
        LegacyPbkdf2PasswordHasher.SubstrateDescription.Should().Contain("PBKDF2",
            because: "the substrate description must accurately document the actual KDF used");
    }

    [Fact]
    public void LegacyPbkdf2PasswordHasher_HashAndVerify_StillWorkAfterAlgorithmFix()
    {
        // The algorithm property fix must not break hash/verify functionality
        var hasher = LegacyPbkdf2PasswordHasher.Default;

        var hash = hasher.HashPassword("test-password-123");
        hash.Should().NotBeNullOrEmpty();
        hash.Should().StartWith("$legacy-pbkdf2$",
            because: "the hash format prefix identifies the legacy PBKDF2 format");

        var verifyResult = hasher.VerifyPassword("test-password-123", hash);
        verifyResult.Should().Be(PasswordVerificationResult.Success,
            because: "hash verification must still work after the algorithm property fix");
    }
}
