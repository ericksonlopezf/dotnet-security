// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Network.Tests;

using System;
using System.Net;
using System.Threading.Tasks;
using AwesomeAssertions;
using Xunit;

public sealed class SafeDnsResolverTests
{
    private static Task<IPAddress[]> MockDnsLookup(string host, System.Threading.CancellationToken ct)
    {
        if (host == "localhost")
        {
            return Task.FromResult(new[] { IPAddress.Loopback });
        }
        if (host == "valid-host.example.com")
        {
            return Task.FromResult(new[] { IPAddress.Parse("93.184.216.34") });
        }
        throw new System.Net.Sockets.SocketException((int)System.Net.Sockets.SocketError.HostNotFound);
    }

    private readonly SafeDnsResolver _resolver = new(null, MockDnsLookup);

    [Theory]
    [InlineData("127.0.0.1")]
    [InlineData("10.0.0.1")]
    [InlineData("192.168.1.1")]
    [InlineData("172.16.0.5")]
    [InlineData("169.254.1.1")]
    [InlineData("::1")]
    [InlineData("fe80::1")]
    [InlineData("fc00::1")]
    [InlineData("100.64.0.1")] // CGNAT
    [InlineData("0.0.0.0")]
    public async Task ResolveAndValidateAsync_ProhibitedIps_ReturnsForbiddenError(string ip)
    {
        var result = await _resolver.ResolveAndValidateAsync(ip);

        result.IsFailure.Should().BeTrue();
        result.Error.Code.Should().Be("SafeDnsResolver.ProhibitedIpRange");
    }

    [Theory]
    [InlineData("metadata.google.internal")]
    [InlineData("metadata.tencentyun.com")]
    [InlineData("instance-data")]
    [InlineData("169.254.169.254")]
    public async Task ResolveAndValidateAsync_CloudMetadataHostnames_ReturnsForbiddenError(string metadataHost)
    {
        var result = await _resolver.ResolveAndValidateAsync(metadataHost);

        result.IsFailure.Should().BeTrue();
        result.Error.Code.Should().Be("SafeDnsResolver.CloudMetadataBlocked");

        // When BlockCloudMetadata is false, it falls back to IP range validation
        var opt = new SsrfProtectionOptions { BlockCloudMetadata = false };
        var customResolver = new SafeDnsResolver(opt);
        var resNoBlock = await customResolver.ResolveAndValidateAsync(metadataHost);
        resNoBlock.IsFailure.Should().BeTrue(); // Still blocked by IP range or HostNotFound
    }

    [Theory]
    [InlineData("8.8.8.8")]
    [InlineData("1.1.1.1")]
    [InlineData("9.9.9.9")]
    public async Task ResolveAndValidateAsync_PublicIps_ReturnsSuccess(string publicIp)
    {
        var result = await _resolver.ResolveAndValidateAsync(publicIp);

        result.IsSuccess.Should().BeTrue();
        result.Value.Should().Contain(IPAddress.Parse(publicIp));
    }

    [Fact]
    public async Task ResolveAndValidateAsync_ValidHostname_ResolvesAndPassesValidation()
    {
        var result = await _resolver.ResolveAndValidateAsync("valid-host.example.com");

        result.IsSuccess.Should().BeTrue();
        result.Value.Should().Contain(IPAddress.Parse("93.184.216.34"));
    }

    [Fact]
    public async Task ResolveAndValidateAsync_Validation_HandlesEdgeCases()
    {
        // Empty / whitespace
        var res1 = await _resolver.ResolveAndValidateAsync("");
        res1.IsFailure.Should().BeTrue();
        res1.Error.Code.Should().Be("SafeDnsResolver.EmptyHost");

        var res2 = await _resolver.ResolveAndValidateAsync("   ");
        res2.IsFailure.Should().BeTrue();
        res2.Error.Code.Should().Be("SafeDnsResolver.EmptyHost");

        var res3 = await _resolver.ResolveAndValidateAsync(null!);
        res3.IsFailure.Should().BeTrue();
        res3.Error.Code.Should().Be("SafeDnsResolver.EmptyHost");

        // Non-existent hostname
        var resNotFound = await _resolver.ResolveAndValidateAsync("non-existent-domain-123456789.invalid");
        resNotFound.IsFailure.Should().BeTrue();
        resNotFound.Error.Code.Should().Be("SafeDnsResolver.HostNotFound");
    }

    [Fact]
    public async Task ResolveAndValidateAsync_AllowedRanges_OverridesBlockedRanges()
    {
        var options = new SsrfProtectionOptions();
        options.AllowedRanges.Add(IpAddressRange.Parse("10.50.0.0/16"));

        var resolver = new SafeDnsResolver(options);

        // Allowed range succeeds
        var resAllowed = await resolver.ResolveAndValidateAsync("10.50.1.1");
        resAllowed.IsSuccess.Should().BeTrue();
        resAllowed.Value.Should().Contain(IPAddress.Parse("10.50.1.1"));

        // Other blocked range in 10.0.0.0/8 fails
        var resBlocked = await resolver.ResolveAndValidateAsync("10.10.1.1");
        resBlocked.IsFailure.Should().BeTrue();
        resBlocked.Error.Code.Should().Be("SafeDnsResolver.ProhibitedIpRange");
    }

    [Fact]
    public async Task ResolveAndValidateAsync_AllowedHostnames_ValidatesResolvedIps_SEC_003()
    {
        var options = new SsrfProtectionOptions();
        options.AllowedHostnames.Add("valid-host.example.com");
        options.AllowedHostnames.Add("localhost");
        options.AllowedHostnames.Add("invalid-allowed-host.example.invalid");

        var resolver = new SafeDnsResolver(options, MockDnsLookup);

        // valid-host is allowlisted and resolves to public IP -> succeeds
        var resValid = await resolver.ResolveAndValidateAsync("valid-host.example.com");
        resValid.IsSuccess.Should().BeTrue();
        resValid.Value.Should().Contain(IPAddress.Parse("93.184.216.34"));

        // localhost is allowlisted but resolves to loopback (prohibited) -> blocked (SEC-003 DNS rebinding fix)
        var resLocalhost = await resolver.ResolveAndValidateAsync("localhost");
        resLocalhost.IsFailure.Should().BeTrue();
        resLocalhost.Error.Code.Should().Be("SafeDnsResolver.ProhibitedIpRange");

        // When loopback is explicitly allowlisted in AllowedRanges as well -> succeeds
        options.AllowedRanges.Add(IpAddressRange.Parse("127.0.0.0/8"));
        var resLocalhostWithRange = await resolver.ResolveAndValidateAsync("localhost");
        resLocalhostWithRange.IsSuccess.Should().BeTrue();

        // invalid host fails DNS
        var resInvalid = await resolver.ResolveAndValidateAsync("invalid-allowed-host.example.invalid");
        resInvalid.IsFailure.Should().BeTrue();
        resInvalid.Error.Code.Should().Be("SafeDnsResolver.DnsResolutionFailed");
    }

    [Fact]
    public async Task ResolveAndValidateAsync_NoAddressesResolved_ReturnsFailure()
    {
        var emptyResolver = new SafeDnsResolver(null, (h, ct) => Task.FromResult(Array.Empty<IPAddress>()));
        var result = await emptyResolver.ResolveAndValidateAsync("empty-dns.example.com");
        result.IsFailure.Should().BeTrue();
        result.Error.Code.Should().Be("SafeDnsResolver.NoAddressesResolved");
    }

    [Fact]
    public async Task ResolveAndValidateAsync_DnsRebindingAttack_BlocksRequestWhenAnyResolvedIpIsPrivate()
    {
        // Rebinding simulation: DNS responds with a dual-stack or multiple A records
        // where one is a legitimate public IP, and the second is an internal RFC 1918 private address
        var rebindingResolver = new SafeDnsResolver(null, (h, ct) =>
            Task.FromResult(new[] { IPAddress.Parse("93.184.216.34"), IPAddress.Parse("10.0.0.1") }));

        var result = await rebindingResolver.ResolveAndValidateAsync("rebinding-dual-record.attacker.com");

        result.IsFailure.Should().BeTrue();
        result.Error.Code.Should().Be("SafeDnsResolver.ProhibitedIpRange");
    }

    [Fact]
    public async Task ResolveAndValidateAsync_IdnPunycodeHostname_ValidatesCorrectly()
    {
        var idnResolver = new SafeDnsResolver(null, (host, ct) =>
        {
            if (host.StartsWith("xn--", StringComparison.OrdinalIgnoreCase))
            {
                return Task.FromResult(new[] { IPAddress.Parse("192.168.1.100") });
            }
            return Task.FromResult(new[] { IPAddress.Parse("93.184.216.34") });
        });

        // Prohibited IP under Punycode host
        var resBlocked = await idnResolver.ResolveAndValidateAsync("xn--e1afmkfd.xn--p1ai");
        resBlocked.IsFailure.Should().BeTrue();
        resBlocked.Error.Code.Should().Be("SafeDnsResolver.ProhibitedIpRange");

        // Public IP under standard host
        var resPublic = await idnResolver.ResolveAndValidateAsync("legitimate-host.com");
        resPublic.IsSuccess.Should().BeTrue();
    }

    // ── T-017: NET-006 — IPv4-mapped IPv6 SSRF Bypass Prevention ────────────────

    /// <summary>
    /// T-017 (NET-006): IPv4-mapped IPv6 addresses (::ffff:x.x.x.x syntax) must be blocked
    /// when the underlying IPv4 address falls in a prohibited private/reserved range.
    /// Without normalization, an SSRF attacker could bypass IPv4 block lists by encoding
    /// private addresses as IPv6 (e.g., ::ffff:10.0.0.1 to bypass the 10.0.0.0/8 block).
    /// </summary>
    [Theory]
    [InlineData("::ffff:10.0.0.1")]       // RFC 1918 Class A — 10.0.0.0/8
    [InlineData("::ffff:192.168.1.1")]    // RFC 1918 Class C — 192.168.0.0/16
    [InlineData("::ffff:172.16.0.1")]     // RFC 1918 Class B — 172.16.0.0/12
    [InlineData("::ffff:127.0.0.1")]      // Loopback — 127.0.0.0/8
    [InlineData("::ffff:169.254.0.1")]    // Link-local — 169.254.0.0/16 (cloud metadata range)
    [InlineData("::ffff:100.64.0.1")]     // CGNAT — 100.64.0.0/10
    public async Task ResolveAndValidateAsync_IPv4MappedIPv6PrivateAddresses_AreBlocked_NET006(string ipv4MappedAddress)
    {
        // NET-006 fix: SafeDnsResolver.ValidateAddress() normalizes IPv4-mapped IPv6 via
        // IPAddress.MapToIPv4() before range checking, so private addresses cannot bypass
        // SSRF protection by encoding as ::ffff:x.x.x.x
        var result = await _resolver.ResolveAndValidateAsync(ipv4MappedAddress);

        result.IsFailure.Should().BeTrue(
            because: $"IPv4-mapped IPv6 address {ipv4MappedAddress} maps to a private IPv4 address that must be blocked");
        result.Error.Code.Should().Be("SafeDnsResolver.ProhibitedIpRange",
            because: "private IPv4-mapped IPv6 addresses fall in the same prohibited ranges as their IPv4 equivalents");
    }

    /// <summary>
    /// T-017 (NET-006): IPv4-mapped IPv6 addresses pointing to public IPs must be allowed.
    /// This ensures that the IPv4-mapped normalization only blocks private ranges
    /// and does not break legitimate public IPv6 requests.
    /// </summary>
    [Theory]
    [InlineData("::ffff:8.8.8.8")]        // Google DNS — public IP
    [InlineData("::ffff:1.1.1.1")]        // Cloudflare DNS — public IP
    [InlineData("::ffff:93.184.216.34")]  // example.com — public IP
    public async Task ResolveAndValidateAsync_IPv4MappedIPv6PublicAddresses_AreAllowed_NET006(string ipv4MappedAddress)
    {
        var result = await _resolver.ResolveAndValidateAsync(ipv4MappedAddress);

        result.IsSuccess.Should().BeTrue(
            because: $"IPv4-mapped IPv6 address {ipv4MappedAddress} maps to a public IP that should be allowed");
    }

    /// <summary>
    /// T-017 (NET-006): DNS resolver that returns an IPv4-mapped IPv6 private address must block the request.
    /// Verifies that the normalization occurs post-DNS-resolution, not just at the input validation stage.
    /// </summary>
    [Fact]
    public async Task ResolveAndValidateAsync_DnsReturnsIPv4MappedPrivateAddress_IsBlocked_NET006()
    {
        // Simulate a DNS resolver returning ::ffff:10.0.0.1 (IPv4-mapped IPv6 for 10.0.0.1)
        var ipv4MappedPrivate = IPAddress.Parse("::ffff:10.0.0.1");
        var dnsReturnsIPv4MappedPrivate = new SafeDnsResolver(null,
            (h, ct) => Task.FromResult(new[] { ipv4MappedPrivate }));

        var result = await dnsReturnsIPv4MappedPrivate.ResolveAndValidateAsync("attacker-controlled-host.com");

        result.IsFailure.Should().BeTrue(
            because: "DNS returning an IPv4-mapped IPv6 private address should be blocked after normalization");
        result.Error.Code.Should().Be("SafeDnsResolver.ProhibitedIpRange");
    }

    // NET-005: Expanded cloud metadata hostname blocklist
    [Theory]
    [InlineData("metadata.azure.com")]
    [InlineData("azure-metadata.azure.com")]
    [InlineData("metadata.packet.net")]
    [InlineData("metadata.hetzner.cloud")]
    [InlineData("169.254.170.2")]   // AWS ECS task metadata
    [InlineData("100.100.100.200")] // Alibaba Cloud IMDS
    public async Task ResolveAndValidateAsync_ExtendedCloudMetadataHostnames_Blocked_NET005(string metadataHost)
    {
        var result = await _resolver.ResolveAndValidateAsync(metadataHost);

        result.IsFailure.Should().BeTrue(
            because: $"Cloud metadata host '{metadataHost}' must be blocked (NET-005)");
        result.Error.Code.Should().Be("SafeDnsResolver.CloudMetadataBlocked");
    }

    // NET-002: AllowedHostnames without RestrictToAllowedHostnames=true must still restrict
    [Fact]
    public async Task ResolveAndValidateAsync_AllowedHostnamesPopulated_BlocksUnlistedHost_NET002()
    {
        // Configure AllowedHostnames WITHOUT explicitly setting RestrictToAllowedHostnames=true
        // Before the fix, this would NOT restrict anything — the allowlist had no effect.
        // After the fix, populating AllowedHostnames implicitly enables restriction.
        var options = new SsrfProtectionOptions();
        options.AllowedHostnames.Add("valid-host.example.com");
        // RestrictToAllowedHostnames is intentionally NOT set (stays false)

        var resolver = new SafeDnsResolver(options, MockDnsLookup);

        // This host is NOT in AllowedHostnames
        var result = await resolver.ResolveAndValidateAsync("other-host.example.com");

        result.IsFailure.Should().BeTrue(
            because: "NET-002: A host not in AllowedHostnames must be blocked when the allowlist is populated");
        result.Error.Code.Should().Be("SafeDnsResolver.HostNotAllowed");
    }

    [Fact]
    public async Task ResolveAndValidateAsync_AllowedHostnamesPopulated_AllowsListedHost_NET002()
    {
        var options = new SsrfProtectionOptions();
        options.AllowedHostnames.Add("valid-host.example.com");

        var resolver = new SafeDnsResolver(options, MockDnsLookup);

        // This host IS in AllowedHostnames
        var result = await resolver.ResolveAndValidateAsync("valid-host.example.com");

        result.IsSuccess.Should().BeTrue(
            because: "NET-002: A host present in AllowedHostnames must be allowed through.");
    }

    [Theory]
    [InlineData("0177.0.0.1")]
    [InlineData("127.000.000.001")]
    [InlineData("0127.0.0.1")]
    [InlineData("010.0.0.1")]
    [InlineData("192.168.001.001")]
    public async Task ResolveAndValidateAsync_AmbiguousNumericIPv4Formats_ReturnsAmbiguousIpFormatError_FINDING_WEB_01(string ambiguousIp)
    {
        var result = await _resolver.ResolveAndValidateAsync(ambiguousIp);

        result.IsFailure.Should().BeTrue();
        result.Error.Code.Should().Be("SafeDnsResolver.AmbiguousIpFormat");
    }
}


