// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Network.Tests;

using System.Linq;
using System.Net;
using AwesomeAssertions;
using Xunit;

public sealed class SsrfProtectionOptionsTests
{
    [Fact]
    public void SsrfProtectionOptions_Defaults_AreSecure()
    {
        var options = new SsrfProtectionOptions();

        options.RequireHttps.Should().BeTrue();
        options.MaxRedirects.Should().Be(5);
        options.BlockCloudMetadata.Should().BeTrue();

        options.BlockedRanges.Should().NotBeEmpty();
        options.AllowedRanges.Should().BeEmpty();
        options.AllowedHostnames.Should().BeEmpty();

        // Check key prohibited ranges
        SsrfProtectionOptions.DefaultBlockedRanges.Any(r => r.Contains(IPAddress.Loopback)).Should().BeTrue();
        SsrfProtectionOptions.DefaultBlockedRanges.Any(r => r.Contains(IPAddress.IPv6Loopback)).Should().BeTrue();
        SsrfProtectionOptions.DefaultBlockedRanges.Any(r => r.Contains(IPAddress.Parse("10.0.0.1"))).Should().BeTrue();
        SsrfProtectionOptions.DefaultBlockedRanges.Any(r => r.Contains(IPAddress.Parse("192.168.1.1"))).Should().BeTrue();
        SsrfProtectionOptions.DefaultBlockedRanges.Any(r => r.Contains(IPAddress.Parse("172.16.0.1"))).Should().BeTrue();
        SsrfProtectionOptions.DefaultBlockedRanges.Any(r => r.Contains(IPAddress.Parse("169.254.169.254"))).Should().BeTrue();
    }

    [Fact]
    public void SsrfProtectionOptions_Properties_CanBeModified()
    {
        var options = new SsrfProtectionOptions
        {
            RequireHttps = false,
            MaxRedirects = 10,
            BlockCloudMetadata = false
        };

        options.RequireHttps.Should().BeFalse();
        options.MaxRedirects.Should().Be(10);
        options.BlockCloudMetadata.Should().BeFalse();
    }
}
