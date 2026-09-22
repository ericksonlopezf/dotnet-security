// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Tests.Randomness;

using System;
using EricksonLopez.Security.Randomness;
using Xunit;

public sealed class CryptographicRandomTests
{
    [Fact]
    public void Fill_PopulatesSpanWithRandomBytes()
    {
        Span<byte> destination = stackalloc byte[32];
        CryptographicRandom.Shared.Fill(destination);

        Assert.False(destination.SequenceEqual(new byte[32]));
    }

    [Fact]
    public void GetInt32_GeneratesValuesWithinBounds()
    {
        for (int i = 0; i < 50; i++)
        {
            int val = CryptographicRandom.Shared.GetInt32(10, 20);
            Assert.InRange(val, 10, 19);
        }
    }

    [Fact]
    public void GetBytes_ValidatesAndGeneratesBytes()
    {
        var ex = Assert.Throws<ArgumentOutOfRangeException>(() => CryptographicRandom.Shared.GetBytes(-1));
        Assert.Equal("count", ex.ParamName);
        Assert.DoesNotContain("System.Security.Cryptography.RandomNumberGenerator.GetBytes", ex.StackTrace);

        var empty = CryptographicRandom.Shared.GetBytes(0);
        Assert.Empty(empty);

        var bytes32 = CryptographicRandom.Shared.GetBytes(32);
        Assert.Equal(32, bytes32.Length);
        Assert.False(bytes32.AsSpan().SequenceEqual(new byte[32]));
    }

    [Fact]
    public void GetUrlSafeString_ValidatesArguments()
    {
        var exZero = Assert.Throws<ArgumentOutOfRangeException>(() => CryptographicRandom.Shared.GetUrlSafeString(0));
        Assert.Equal("byteLength", exZero.ParamName);
        Assert.Contains("Byte length must be greater than zero.", exZero.Message);

        var exNegative = Assert.Throws<ArgumentOutOfRangeException>(() => CryptographicRandom.Shared.GetUrlSafeString(-10));
        Assert.Equal("byteLength", exNegative.ParamName);
        Assert.Contains("Byte length must be greater than zero.", exNegative.Message);
    }

    [Fact]
    public void GetUrlSafeString_StackallocAndRentedPool_BranchesCovered()
    {
        // Small (<= 128) -> stackalloc branch
        var smallToken = CryptographicRandom.Shared.GetUrlSafeString(16);
        Assert.False(string.IsNullOrWhiteSpace(smallToken));
        Assert.DoesNotContain("+", smallToken);
        Assert.DoesNotContain("/", smallToken);
        Assert.DoesNotContain("=", smallToken);

        // Boundary (128) -> stackalloc max branch
        var boundaryToken = CryptographicRandom.Shared.GetUrlSafeString(128);
        Assert.False(string.IsNullOrWhiteSpace(boundaryToken));
        Assert.DoesNotContain("+", boundaryToken);
        Assert.DoesNotContain("/", boundaryToken);
        Assert.DoesNotContain("=", boundaryToken);

        // Immediate next boundary (129) -> array pool rented branch
        var boundaryToken129 = CryptographicRandom.Shared.GetUrlSafeString(129);
        Assert.False(string.IsNullOrWhiteSpace(boundaryToken129));

        // Large (> 128) -> array pool rented branch
        var largeToken = CryptographicRandom.Shared.GetUrlSafeString(256);
        Assert.False(string.IsNullOrWhiteSpace(largeToken));
        Assert.DoesNotContain("+", largeToken);
        Assert.DoesNotContain("/", largeToken);
        Assert.DoesNotContain("=", largeToken);
    }

    [Fact]
    public void GetHexString_ValidatesArguments()
    {
        var exZero = Assert.Throws<ArgumentOutOfRangeException>(() => CryptographicRandom.Shared.GetHexString(0));
        Assert.Equal("byteLength", exZero.ParamName);
        Assert.Contains("Byte length must be greater than zero.", exZero.Message);

        var exNegative = Assert.Throws<ArgumentOutOfRangeException>(() => CryptographicRandom.Shared.GetHexString(-5));
        Assert.Equal("byteLength", exNegative.ParamName);
        Assert.Contains("Byte length must be greater than zero.", exNegative.Message);
    }

    [Fact]
    public void GetHexString_StackallocAndRentedPool_BranchesCovered()
    {
        // Small (<= 128)
        var hex16 = CryptographicRandom.Shared.GetHexString(16);
        Assert.Equal(32, hex16.Length); // 16 bytes = 32 hex chars
        Assert.Matches("^[0-9a-f]{32}$", hex16);

        // Boundary (128)
        var hex128 = CryptographicRandom.Shared.GetHexString(128);
        Assert.Equal(256, hex128.Length); // 128 bytes = 256 hex chars
        Assert.Matches("^[0-9a-f]{256}$", hex128);

        // Immediate next boundary (129)
        var hex129 = CryptographicRandom.Shared.GetHexString(129);
        Assert.Equal(258, hex129.Length);
        Assert.Matches("^[0-9a-f]{258}$", hex129);

        // Large (> 128) -> array pool rented branch
        var hex256 = CryptographicRandom.Shared.GetHexString(256);
        Assert.Equal(512, hex256.Length); // 256 bytes = 512 hex chars
        Assert.Matches("^[0-9a-f]{512}$", hex256);
    }

    [Fact]
    public void TryGetUrlSafeString_ValidatesArguments()
    {
        char[] dest = new char[64];
        var exZero = Assert.Throws<ArgumentOutOfRangeException>(() => CryptographicRandom.Shared.TryGetUrlSafeString(dest, 0, out _));
        Assert.Equal("byteLength", exZero.ParamName);
        Assert.Contains("Byte length must be greater than zero.", exZero.Message);

        var exNegative = Assert.Throws<ArgumentOutOfRangeException>(() => CryptographicRandom.Shared.TryGetUrlSafeString(dest, -5, out _));
        Assert.Equal("byteLength", exNegative.ParamName);
        Assert.Contains("Byte length must be greater than zero.", exNegative.Message);
    }
}
