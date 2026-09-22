// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Cryptography.Tests.Randomness;

using System;
using EricksonLopez.Security.Cryptography.Randomness;
using AwesomeAssertions;
using Xunit;

public sealed class ConstantTimeComparerTests
{
    private readonly ConstantTimeComparer _sut = new();

    [Fact]
    public void FixedTimeEquals_ByteSpans_ReturnsExpected()
    {
        byte[] a = [1, 2, 3, 4, 5];
        byte[] b = [1, 2, 3, 4, 5];
        byte[] c = [1, 2, 3, 4, 6];
        byte[] d = [1, 2, 3, 4];

        _sut.FixedTimeEquals(a, b).Should().BeTrue();
        _sut.FixedTimeEquals(a, c).Should().BeFalse();
        _sut.FixedTimeEquals(a, d).Should().BeFalse();
        _sut.FixedTimeEquals(ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty).Should().BeTrue();
    }

    [Fact]
    public void FixedTimeEquals_CharSpans_ReturnsExpected()
    {
        var s1 = "SuperSecretPassword".AsSpan();
        var s2 = "SuperSecretPassword".AsSpan();
        var s3 = "SuperSecretPasswore".AsSpan();
        var s4 = "SuperSecret".AsSpan();
        var s5 = "ab".AsSpan();
        var s6 = "ba".AsSpan();

        _sut.FixedTimeEquals(s1, s2).Should().BeTrue();
        _sut.FixedTimeEquals(s1, s3).Should().BeFalse();
        _sut.FixedTimeEquals(s1, s4).Should().BeFalse();
        _sut.FixedTimeEquals(s5, s6).Should().BeFalse();
        _sut.FixedTimeEquals(ReadOnlySpan<char>.Empty, ReadOnlySpan<char>.Empty).Should().BeTrue();
    }
}
