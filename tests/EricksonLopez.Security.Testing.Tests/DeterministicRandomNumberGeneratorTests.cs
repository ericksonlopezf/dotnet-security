// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Testing.Tests;

using System;
using AwesomeAssertions;
using EricksonLopez.Security.Testing.Fakes;
using Xunit;

public sealed class DeterministicRandomNumberGeneratorTests
{
    [Fact]
    public void Seed_ProducesDeterministicByteSequence()
    {
        var rng1 = new DeterministicRandomNumberGenerator(12345);
        var rng2 = new DeterministicRandomNumberGenerator(12345);

        var bytes1 = rng1.GetBytes(32);
        var bytes2 = rng2.GetBytes(32);

        bytes1.Should().Equal(bytes2);
        bytes1.Length.Should().Be(32);
        bytes1.Should().Contain(b => b != 0);
    }

    [Fact]
    public void GetBytes_WithZeroOrNegativeCount_ReturnsEmptyArray()
    {
        var rng = new DeterministicRandomNumberGenerator();

        rng.GetBytes(0).Should().BeSameAs(Array.Empty<byte>());
        rng.GetBytes(-5).Should().BeSameAs(Array.Empty<byte>());
    }

    [Fact]
    public void Fill_FillsDestinationSpanDeterministically()
    {
        var rng1 = new DeterministicRandomNumberGenerator(999);
        var rng2 = new DeterministicRandomNumberGenerator(999);

        Span<byte> span1 = stackalloc byte[16];
        Span<byte> span2 = stackalloc byte[16];

        rng1.Fill(span1);
        rng2.Fill(span2);

        span1.SequenceEqual(span2).Should().BeTrue();
    }

    [Fact]
    public void GetInt32_ReturnsValuesWithinSpecifiedBounds()
    {
        var rng = new DeterministicRandomNumberGenerator(42);

        for (int i = 0; i < 50; i++)
        {
            var value = rng.GetInt32(10, 20);
            value.Should().BeInRange(10, 19);
        }
    }
}
