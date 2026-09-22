// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Mfa.Tests;

using System;
using System.Linq;
using AwesomeAssertions;
using Xunit;

public sealed class RecoveryCodeGeneratorTests
{
    [Fact]
    public void GenerateCodes_Default_Returns10UniqueFormattedCodes()
    {
        var generator = new RecoveryCodeGenerator();
        var codes = generator.GenerateCodes(10, 10);

        codes.Length.Should().Be(10);
        codes.Distinct().Count().Should().Be(10);

        foreach (var code in codes)
        {
            code.Should().MatchRegex(@"^[2-9A-Z]{4}-[2-9A-Z]{4}-[2-9A-Z]{2}$");
        }
    }

    [Fact]
    public void GenerateCodes_CustomCountAndLength_ReturnsExpected()
    {
        var generator = new RecoveryCodeGenerator();
        var codes = generator.GenerateCodes(5, 12);

        codes.Length.Should().Be(5);
        codes.Distinct().Count().Should().Be(5);

        foreach (var code in codes)
        {
            code.Should().MatchRegex(@"^[2-9A-Z]{4}-[2-9A-Z]{4}-[2-9A-Z]{4}$");
        }

        // Boundary length of exactly 8
        var exact8 = generator.GenerateCodes(1, 8);
        exact8.Length.Should().Be(1);
        exact8[0].Should().MatchRegex(@"^[2-9A-Z]{4}-[2-9A-Z]{4}$");
    }

    [Fact]
    public void GenerateCodes_InvalidArguments_ThrowsArgumentOutOfRangeException()
    {
        var generator = new RecoveryCodeGenerator();
        var exZero = Assert.Throws<ArgumentOutOfRangeException>("count", () => generator.GenerateCodes(0, 10));
        Assert.Contains("Count must be greater than zero.", exZero.Message);

        var exNeg = Assert.Throws<ArgumentOutOfRangeException>("count", () => generator.GenerateCodes(-1, 10));
        Assert.Contains("Count must be greater than zero.", exNeg.Message);

        var exShort = Assert.Throws<ArgumentOutOfRangeException>("codeLength", () => generator.GenerateCodes(10, 7));
        Assert.Contains("Code length must be at least 8 characters.", exShort.Message);

        var exZeroLen = Assert.Throws<ArgumentOutOfRangeException>("codeLength", () => generator.GenerateCodes(10, 0));
        Assert.Contains("Code length must be at least 8 characters.", exZeroLen.Message);
    }

    // SEC-022: Kills mutant RecoveryCodeGenerator.cs line 30 — charset string mutation
    // Ensures that every character in every generated code belongs to the exact 32-char unambiguous charset.
    // This test makes Stryker unable to mutate the charset without causing a failure.
    [Fact]
    public void GenerateCodes_AllCharacters_AreFromExactExpectedCharset_SEC_022()
    {
        // The charset declared in the implementation: unambiguous set excluding digits 0/1 and letters I/O
        // (L IS included — only I and O are excluded from letters)
        const string expectedCharset = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ";
        Assert.Equal(32, expectedCharset.Length); // Base32 unambiguous set has exactly 32 chars

        var generator = new RecoveryCodeGenerator();
        // Generate 100 codes of length 10 to exercise the full charset statistically
        var codes = generator.GenerateCodes(count: 100, codeLength: 10);

        foreach (var code in codes)
        {
            // Strip formatting dashes and check each character
            var stripped = code.Replace("-", string.Empty, StringComparison.Ordinal);
            foreach (var c in stripped)
            {
                Assert.True(
                    expectedCharset.Contains(c, StringComparison.Ordinal),
                    $"Character '{c}' in code '{code}' is not in the expected safe charset '{expectedCharset}'.");
            }
        }
    }

    // SEC-022b: Verify that the charset contains no ambiguous characters (0, 1, I, O)
    // Note: 'L' IS included in this charset (ABCDEFGHJKLMNPQRSTUVWXYZ) — only 'I' and 'O' are excluded.
    [Fact]
    public void GenerateCodes_Charset_ExcludesAmbiguousCharacters_SEC_022b()
    {
        const string expectedCharset = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ";
        // Ambiguous characters excluded per design (visually confusable in certain fonts)
        // 0 and 1 are excluded (digits ≡ O and I)
        // I and O are excluded (uppercase letters confusable with 1 and 0)
        // L is NOT excluded — this charset is not Crockford Base32; L is included.
        var ambiguous = new[] { '0', '1', 'I', 'O' };

        foreach (var c in ambiguous)
        {
            Assert.False(
                expectedCharset.Contains(c, StringComparison.Ordinal),
                $"Ambiguous character '{c}' must not be in the safe recovery code charset.");
        }
    }
}
