// Copyright © Erickson Lopez. MIT License.
// Regression tests for AUTH-010: RecoveryCodeGenerator.HashCode and VerifyCode

namespace EricksonLopez.Security.Mfa.Tests;

using System;
using AwesomeAssertions;
using Xunit;

/// <summary>
/// Regression tests for AUTH-010: Recovery codes must be hashed before storage,
/// and verified in constant time to prevent timing oracles.
/// </summary>
public sealed class RecoveryCodeHashingTests
{
    private readonly RecoveryCodeGenerator _generator = new();

    // ── AUTH-010 REGRESSION TESTS ───────────────────────────────────────────────

    [Fact]
    public void HashCode_ReturnsExactly64LowercaseHexChars()
    {
        // SHA-256 produces 32 bytes = 64 hex chars. This is the expected hash length
        // used in storage, and must match the length used for constant-time comparison.
        var code = "ABCD-EFGH-IJ";
        var hash = RecoveryCodeGenerator.HashCode(code);

        hash.Length.Should().Be(64, because: "SHA-256 digest encoded as hex is always 64 lowercase characters");
        hash.Should().MatchRegex("^[0-9a-f]{64}$", because: "hash must be lowercase hex");
    }

    [Fact]
    public void HashCode_SameCode_ProducesSameHash()
    {
        // Hashing must be deterministic for the same input so lookups work
        const string code = "2345-6789-AB";
        var hash1 = RecoveryCodeGenerator.HashCode(code);
        var hash2 = RecoveryCodeGenerator.HashCode(code);

        hash1.Should().Be(hash2, because: "the same recovery code must always produce the same hash");
    }

    [Fact]
    public void HashCode_NormalizesFormattingDashes()
    {
        // "ABCDEFGHIJ" and "ABCD-EFGH-IJ" should hash identically
        var withDashes = RecoveryCodeGenerator.HashCode("ABCD-EFGH-IJ");
        var withoutDashes = RecoveryCodeGenerator.HashCode("ABCDEFGHIJ");

        withDashes.Should().Be(withoutDashes,
            because: "formatting dashes should be stripped before hashing for consistent verification");
    }

    [Fact]
    public void HashCode_DifferentCodes_ProduceDifferentHashes()
    {
        // Collision resistance: different codes must produce different hashes
        var hash1 = RecoveryCodeGenerator.HashCode("ABCD-EFGH-IJ");
        var hash2 = RecoveryCodeGenerator.HashCode("ABCD-EFGH-KL");

        hash1.Should().NotBe(hash2, because: "different recovery codes must produce different hashes");
    }

    [Fact]
    public void HashCode_NullOrWhitespace_ThrowsArgumentException()
    {
        Assert.Throws<ArgumentException>("plaintextCode", () => RecoveryCodeGenerator.HashCode(null!));
        Assert.Throws<ArgumentException>("plaintextCode", () => RecoveryCodeGenerator.HashCode(""));
        Assert.Throws<ArgumentException>("plaintextCode", () => RecoveryCodeGenerator.HashCode("   "));
    }

    [Fact]
    public void VerifyCode_CorrectCode_ReturnsTrue()
    {
        const string plaintextCode = "2345-6789-AB";
        var storedHash = RecoveryCodeGenerator.HashCode(plaintextCode);

        var result = RecoveryCodeGenerator.VerifyCode(plaintextCode, storedHash);

        result.Should().BeTrue(because: "a valid recovery code must verify against its stored hash");
    }

    [Fact]
    public void VerifyCode_IncorrectCode_ReturnsFalse()
    {
        const string plaintextCode = "2345-6789-AB";
        var storedHash = RecoveryCodeGenerator.HashCode(plaintextCode);

        var result = RecoveryCodeGenerator.VerifyCode("AAAA-AAAA-AA", storedHash);

        result.Should().BeFalse(because: "a different code must not verify against the original code's hash");
    }

    [Fact]
    public void VerifyCode_NullOrEmpty_ReturnsFalse()
    {
        // Empty/null inputs should not throw; return false for safety
        RecoveryCodeGenerator.VerifyCode(null!, "somehash").Should().BeFalse();
        RecoveryCodeGenerator.VerifyCode("", "somehash").Should().BeFalse();
        RecoveryCodeGenerator.VerifyCode("2345-6789-AB", null!).Should().BeFalse();
        RecoveryCodeGenerator.VerifyCode("2345-6789-AB", "").Should().BeFalse();
    }

    [Fact]
    public void VerifyCode_CaseInsensitiveDashNormalization()
    {
        // User might type the code with lowercase or extra dashes — should still match
        const string storedPlaintext = "ABCD-EFGH-IJ";
        var storedHash = RecoveryCodeGenerator.HashCode(storedPlaintext);

        // Same code, different formatting
        RecoveryCodeGenerator.VerifyCode("ABCDEFGHIJ", storedHash).Should().BeTrue();
        RecoveryCodeGenerator.VerifyCode("abcd-efgh-ij", storedHash).Should().BeTrue(
            because: "verification should normalize case to uppercase before comparing");
    }

    [Fact]
    public void VerifyCode_GeneratedCodeRoundtrip()
    {
        // Generate codes → hash all → verify each works → verify others don't cross-match
        var codes = _generator.GenerateCodes(5, 10);
        var hashes = Array.ConvertAll(codes, RecoveryCodeGenerator.HashCode);

        for (var i = 0; i < codes.Length; i++)
        {
            // Each code verifies against its own hash
            RecoveryCodeGenerator.VerifyCode(codes[i], hashes[i]).Should().BeTrue(
                because: $"code[{i}] must verify against hash[{i}]");

            // No code verifies against a different code's hash (collision check)
            for (var j = 0; j < codes.Length; j++)
            {
                if (i != j)
                {
                    RecoveryCodeGenerator.VerifyCode(codes[i], hashes[j]).Should().BeFalse(
                        because: $"code[{i}] must not verify against hash[{j}]");
                }
            }
        }
    }
}
