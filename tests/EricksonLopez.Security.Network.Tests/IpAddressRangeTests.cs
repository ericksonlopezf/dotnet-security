// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Network.Tests;

using System;
using System.Net;
using System.Net.Sockets;
using AwesomeAssertions;
using Xunit;

public sealed class IpAddressRangeTests
{
    [Theory]
    [InlineData("10.0.0.0/8", "10.0.0.1", true)]
    [InlineData("10.0.0.0/8", "10.255.255.255", true)]
    [InlineData("10.0.0.0/8", "11.0.0.1", false)]
    [InlineData("192.168.1.0/24", "192.168.1.254", true)]
    [InlineData("192.168.1.0/24", "192.168.2.1", false)]
    [InlineData("127.0.0.0/8", "127.0.0.1", true)]
    [InlineData("169.254.0.0/16", "169.254.169.254", true)]
    [InlineData("0.0.0.0/0", "123.45.67.89", true)] // All IPv4
    [InlineData("127.0.0.0/8", "::ffff:127.0.0.1", true)] // IPv4-mapped IPv6 loopback
    [InlineData("169.254.0.0/16", "::ffff:169.254.169.254", true)] // IPv4-mapped IPv6 cloud metadata
    [InlineData("10.0.0.0/8", "::ffff:10.0.0.1", true)] // IPv4-mapped IPv6 private network
    [InlineData("192.168.1.0/24", "::ffff:192.168.1.50", true)] // IPv4-mapped IPv6 subnet
    [InlineData("192.168.1.0/24", "::ffff:192.168.2.1", false)] // IPv4-mapped IPv6 out of range
    public void Contains_IPv4Ranges_EvaluatesCorrectly(string cidr, string ipStr, bool expected)
    {
        var range = IpAddressRange.Parse(cidr);
        var ip = IPAddress.Parse(ipStr);

        range.Contains(ip).Should().Be(expected);
    }

    [Theory]
    [InlineData("::1/128", "::1", true)]
    [InlineData("::1/128", "::2", false)]
    [InlineData("fe80::/10", "fe80::1", true)]
    [InlineData("fe80::/10", "fec0::1", false)]
    [InlineData("::/0", "2001:db8::1", true)] // All IPv6
    public void Contains_IPv6Ranges_EvaluatesCorrectly(string cidr, string ipStr, bool expected)
    {
        var range = IpAddressRange.Parse(cidr);
        var ip = IPAddress.Parse(ipStr);

        range.Contains(ip).Should().Be(expected);
    }

    [Fact]
    public void Contains_EdgeCases_ReturnsFalse()
    {
        var rangeV4 = IpAddressRange.Parse("192.168.1.0/24");
        var rangeV6 = IpAddressRange.Parse("fe80::/10");

        // Null address
        rangeV4.Contains(null!).Should().BeFalse();

        // AddressFamily mismatch
        rangeV4.Contains(IPAddress.IPv6Loopback).Should().BeFalse();
        rangeV6.Contains(IPAddress.Loopback).Should().BeFalse();
    }

    [Fact]
    public void Constructor_Validation_ThrowsExpectedExceptions()
    {
        Assert.Throws<ArgumentNullException>(() => new IpAddressRange(null!, 24));
        var ex4Low = Assert.Throws<ArgumentOutOfRangeException>(() => new IpAddressRange(IPAddress.Parse("192.168.1.1"), -1));
        ex4Low.Message.Should().Contain("Prefix length must be between 0 and 32 for InterNetwork.");
        var ex4High = Assert.Throws<ArgumentOutOfRangeException>(() => new IpAddressRange(IPAddress.Parse("192.168.1.1"), 33));
        ex4High.Message.Should().Contain("Prefix length must be between 0 and 32 for InterNetwork.");
        var ex6Low = Assert.Throws<ArgumentOutOfRangeException>(() => new IpAddressRange(IPAddress.IPv6Loopback, -1));
        ex6Low.Message.Should().Contain("Prefix length must be between 0 and 128 for InterNetworkV6.");
        var ex6High = Assert.Throws<ArgumentOutOfRangeException>(() => new IpAddressRange(IPAddress.IPv6Loopback, 129));
        ex6High.Message.Should().Contain("Prefix length must be between 0 and 128 for InterNetworkV6.");
    }

    [Fact]
    public void Contains_Ipv4RangeWithPureIpv6AddressEndingInMatchingBytes_ReturnsFalse()
    {
        var rangeV4 = IpAddressRange.Parse("192.168.1.0/24");
        var pureIpv6WithMatchingSuffix = IPAddress.Parse("2001:db8::c0a8:0101");
        rangeV4.Contains(pureIpv6WithMatchingSuffix).Should().BeFalse();
    }

    [Fact]
    public void Contains_Ipv6RangeCoveringMappedIpv4_ReturnsTrue()
    {
        var rangeV6 = IpAddressRange.Parse("::ffff:0:0/96");
        var mappedIpv4 = IPAddress.Parse("::ffff:192.168.1.1");
        rangeV6.Contains(mappedIpv4).Should().BeTrue();
    }

    [Fact]
    public void Parse_SingleAddressWithoutSlash_ParsesWithFullMask()
    {
        var rangeV4 = IpAddressRange.Parse("192.168.1.1");
        rangeV4.Contains(IPAddress.Parse("192.168.1.1")).Should().BeTrue();
        rangeV4.Contains(IPAddress.Parse("192.168.1.2")).Should().BeFalse();

        var rangeV6 = IpAddressRange.Parse("fe80::1");
        rangeV6.Contains(IPAddress.Parse("fe80::1")).Should().BeTrue();
        rangeV6.Contains(IPAddress.Parse("fe80::2")).Should().BeFalse();

        Assert.Throws<ArgumentNullException>(() => IpAddressRange.Parse(null!));
    }

    [Fact]
    public void Equality_And_Operators_WorkCorrectly()
    {
        var range1 = IpAddressRange.Parse("10.0.0.0/8");
        var range2 = IpAddressRange.Parse("10.0.0.0/8");
        var range3 = IpAddressRange.Parse("10.0.0.0/16");
        var rangeV6 = IpAddressRange.Parse("::1/128");

        range1.Equals(range2).Should().BeTrue();
        range1.Equals((object)range2).Should().BeTrue();
        (range1 == range2).Should().BeTrue();
        (range1 != range2).Should().BeFalse();

        range1.Equals(range3).Should().BeFalse();
        (range1 == range3).Should().BeFalse();
        (range1 != range3).Should().BeTrue();

        range1.Equals(rangeV6).Should().BeFalse();
        range1.Equals(null).Should().BeFalse();
        range1.Equals("not a range").Should().BeFalse();
        range1.Equals(IpAddressRange.Parse("192.168.0.0/16")).Should().BeFalse();

        range1.GetHashCode().Should().Be(range2.GetHashCode());

        // Default struct equality and null network bytes branch
        var def1 = default(IpAddressRange);
        var def2 = default(IpAddressRange);
        def1.Equals(def2).Should().BeTrue();
        (def1 == def2).Should().BeTrue();
        def1.Equals(range1).Should().BeFalse();
        range1.Equals(def1).Should().BeFalse();
        def1.GetHashCode().Should().Be(def2.GetHashCode());

        // Non-standard prefix lengths (e.g. /19, /27, /0, /32)
        var range19 = IpAddressRange.Parse("10.0.0.0/19");
        range19.Contains(IPAddress.Parse("10.0.31.255")).Should().BeTrue();
        range19.Contains(IPAddress.Parse("10.0.32.0")).Should().BeFalse();

        var range27 = IpAddressRange.Parse("192.168.1.0/27");
        range27.Contains(IPAddress.Parse("192.168.1.31")).Should().BeTrue();
        range27.Contains(IPAddress.Parse("192.168.1.32")).Should().BeFalse();
    }
}
