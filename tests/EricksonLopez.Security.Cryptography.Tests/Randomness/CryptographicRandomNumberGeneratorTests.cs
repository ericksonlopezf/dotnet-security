// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Cryptography.Tests.Randomness;

using System;
using EricksonLopez.Security.Cryptography.Randomness;
using AwesomeAssertions;
using Xunit;

public sealed class CryptographicRandomNumberGeneratorTests
{
    private readonly CryptographicRandomNumberGenerator _sut = new();

    [Fact]
    public void Fill_PopulatesDestinationWithRandomBytes()
    {
        Span<byte> buffer1 = stackalloc byte[32];
        Span<byte> buffer2 = stackalloc byte[32];

        _sut.Fill(buffer1);
        _sut.Fill(buffer2);

        buffer1.ToArray().Should().NotBeEquivalentTo(new byte[32]);
        buffer1.ToArray().Should().NotBeEquivalentTo(buffer2.ToArray());
    }

    [Fact]
    public void GetInt32_GeneratesIntegersWithinRange()
    {
        for (var i = 0; i < 50; i++)
        {
            var val = _sut.GetInt32(10, 50);
            val.Should().BeInRange(10, 49);
        }
    }

    [Fact]
    public void GetBytes_ReturnsRequestedByteCount()
    {
        var bytes = _sut.GetBytes(16);
        bytes.Should().HaveCount(16);
        bytes.Should().NotBeEquivalentTo(new byte[16]);

        _sut.GetBytes(0).Should().BeEmpty();
        var ex = Assert.Throws<ArgumentOutOfRangeException>(() => _sut.GetBytes(-1));
        ex.StackTrace.Should().NotContain("System.Security.Cryptography.RandomNumberGenerator.GetBytes");
    }
}
