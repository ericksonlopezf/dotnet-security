// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Mfa.Tests;

using System;
using System.Text;
using AwesomeAssertions;
using Xunit;

public sealed class Base32EncodingTests
{
    [Theory]
    [InlineData("", "")]
    [InlineData("f", "MY")]
    [InlineData("fo", "MZXQ")]
    [InlineData("foo", "MZXW6")]
    [InlineData("foob", "MZXW6YQ")]
    [InlineData("fooba", "MZXW6YTB")]
    [InlineData("foobar", "MZXW6YTBOI")]
    public void Base32_Rfc4648TestVectors_EncodeAndDecodeMatch(string raw, string expectedBase32)
    {
        var rawBytes = Encoding.ASCII.GetBytes(raw);

        var encoded = Base32Encoding.ToBase32String(rawBytes);
        encoded.Should().Be(expectedBase32);

        var decodedBytes = Base32Encoding.FromBase32String(encoded);
        var decodedString = Encoding.ASCII.GetString(decodedBytes);
        decodedString.Should().Be(raw);
    }

    [Fact]
    public void Base32_EmptyInput_HandlesEmptyEdgeCases()
    {
        Base32Encoding.ToBase32String(Array.Empty<byte>()).Should().Be(string.Empty);
        Assert.Same(Array.Empty<byte>(), Base32Encoding.FromBase32String(""));
        Assert.Same(Array.Empty<byte>(), Base32Encoding.FromBase32String("   "));
        Assert.Same(Array.Empty<byte>(), Base32Encoding.FromBase32String("==="));
    }

    [Fact]
    public void Base32_ArgumentValidation_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => Base32Encoding.ToBase32String(null!));
        Assert.Throws<ArgumentNullException>(() => Base32Encoding.FromBase32String(null!));
    }

    [Fact]
    public void Base32_InvalidCharacters_ThrowsFormatException()
    {
        var ex1 = Assert.Throws<FormatException>(() => Base32Encoding.FromBase32String("MZXW61")); // '1' is invalid
        Assert.Contains("Invalid Base32 character", ex1.Message);

        var ex8 = Assert.Throws<FormatException>(() => Base32Encoding.FromBase32String("MZXW68")); // '8' is invalid
        Assert.Contains("Invalid Base32 character", ex8.Message);

        Assert.Throws<FormatException>(() => Base32Encoding.FromBase32String("MZXW69")); // '9' is invalid
        Assert.Throws<FormatException>(() => Base32Encoding.FromBase32String("MZXW60")); // '0' is invalid
        Assert.Throws<FormatException>(() => Base32Encoding.FromBase32String("MZXW6?")); // '?' is invalid
    }

    [Fact]
    public void Base32_WithPaddingAndWhitespace_DecodesCorrectly()
    {
        var decoded = Base32Encoding.FromBase32String("  MZXW6===  ");
        Encoding.ASCII.GetString(decoded).Should().Be("foo");
    }

    [Fact]
    public void Base32_ExactBitBoundaries_EncodeAndDecode()
    {
        // Test exact bit leftovers (1, 2, 3, 4 bytes)
        byte[] b1 = [0b11111000]; // 5 bits 1s, 3 bits 0s
        byte[] b2 = [0xAA, 0x55];
        byte[] b3 = [0x12, 0x34, 0x56];
        byte[] b4 = [0xFF, 0x00, 0xAA, 0x55];
        byte[] b5 = [0x01, 0x02, 0x03, 0x04, 0x05]; // Exact 40 bits = 8 Base32 chars

        Base32Encoding.FromBase32String(Base32Encoding.ToBase32String(b1)).Should().BeEquivalentTo(b1);
        Base32Encoding.FromBase32String(Base32Encoding.ToBase32String(b2)).Should().BeEquivalentTo(b2);
        Base32Encoding.FromBase32String(Base32Encoding.ToBase32String(b3)).Should().BeEquivalentTo(b3);
        Base32Encoding.FromBase32String(Base32Encoding.ToBase32String(b4)).Should().BeEquivalentTo(b4);
        Base32Encoding.FromBase32String(Base32Encoding.ToBase32String(b5)).Should().BeEquivalentTo(b5);
    }

    [Fact]
    public void Base32_Roundtrip_VariousByteLengths()
    {
        for (var len = 1; len <= 40; len++)
        {
            var bytes = new byte[len];
            for (var i = 0; i < len; i++)
            {
                bytes[i] = (byte)((i * 37 + 13) & 0xFF);
            }

            var encoded = Base32Encoding.ToBase32String(bytes);
            var expectedLen = (int)Math.Ceiling(len * 8.0 / 5.0);
            encoded.Length.Should().Be(expectedLen);

            var decoded = Base32Encoding.FromBase32String(encoded);

            decoded.Should().BeEquivalentTo(bytes);
        }
    }

    [Fact]
    public void Base32_ExactFiveByteMultiple_HasNoTrailingLeftoverChars()
    {
        // 5 bytes (40 bits) = exactly 8 Base32 chars, 10 bytes = exactly 16 chars
        byte[] fiveBytes = [1, 2, 3, 4, 5];
        var encoded5 = Base32Encoding.ToBase32String(fiveBytes);
        encoded5.Length.Should().Be(8);

        byte[] tenBytes = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        var encoded10 = Base32Encoding.ToBase32String(tenBytes);
        encoded10.Length.Should().Be(16);
    }

    // P3.3 (resolved): Regression test for the length guard in FromBase32String.
    // Strings exceeding 2048 characters must be rejected before the decode loop (DoS prevention).
    [Fact]
    public void Base32_OverlongInput_ThrowsArgumentException()
    {
        // 2049 characters — one over the limit
        var overlongInput = new string('A', 2049);
        var ex = Assert.Throws<ArgumentException>(() => Base32Encoding.FromBase32String(overlongInput));
        Assert.Contains("maximum allowed length", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Base32_ExactlyAtLengthLimit_DoesNotThrow()
    {
        // 2048 valid Base32 chars: length is exact boundary, must not throw ArgumentException
        // 2048 = 256 × 8, so remainder mod 8 = 0 → valid quantum length
        var atLimit = new string('A', 2048);
        // Should not throw ArgumentException (may throw FormatException if content has non-zero padding bits)
        // but the length guard must not trigger
        try
        {
            Base32Encoding.FromBase32String(atLimit);
        }
        catch (FormatException)
        {
            // FormatException for padding bits is acceptable — the length guard did not trigger
        }
        catch (ArgumentException ex) when (ex.Message.Contains("maximum allowed length"))
        {
            Assert.Fail("Length guard must not trigger for exactly 2048 characters.");
        }
    }
}
