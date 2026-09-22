// Copyright © Erickson Lopez. MIT License.
using System.Collections.Generic;
using System.Net;

namespace EricksonLopez.Security.Network;

/// <summary>
/// Specifies configuration options for Server-Side Request Forgery (SSRF) prevention.
/// </summary>
public sealed class SsrfProtectionOptions
{
    /// <summary>
    /// Gets the list of default prohibited IP address ranges (RFC 1918, loopbacks, link-local, cloud metadata).
    /// </summary>
    public static readonly IReadOnlyList<IpAddressRange> DefaultBlockedRanges = new List<IpAddressRange>
    {
        // IPv4 Loopback & Unspecified
        IpAddressRange.Parse("127.0.0.0/8"),
        IpAddressRange.Parse("0.0.0.0/8"),

        // IPv4 Private Networks (RFC 1918)
        IpAddressRange.Parse("10.0.0.0/8"),
        IpAddressRange.Parse("172.16.0.0/12"),
        IpAddressRange.Parse("192.168.0.0/16"),

        // IPv4 Link-Local & Cloud Metadata (169.254.169.254)
        IpAddressRange.Parse("169.254.0.0/16"),

        // IPv4 Carrier-grade NAT (RFC 6598) & Benchmark
        IpAddressRange.Parse("100.64.0.0/10"),
        IpAddressRange.Parse("198.18.0.0/15"),

        // IPv6 Loopback & Unspecified
        IpAddressRange.Parse("::1/128"),
        IpAddressRange.Parse("::/128"),

        // IPv6 Unique Local (fc00::/7) & Link-Local (fe80::/10)
        IpAddressRange.Parse("fc00::/7"),
        IpAddressRange.Parse("fe80::/10")
    }.AsReadOnly();

    /// <summary>
    /// Gets the list of custom prohibited IP address ranges in addition to defaults.
    /// </summary>
    public IList<IpAddressRange> BlockedRanges { get; } = new List<IpAddressRange>(DefaultBlockedRanges);

    /// <summary>
    /// Gets the list of explicitly allowed IP address ranges that override blocked ranges.
    /// </summary>
    public IList<IpAddressRange> AllowedRanges { get; } = new List<IpAddressRange>();

    /// <summary>
    /// Gets the set of allowed hostnames (e.g., "api.partner.com").
    /// </summary>
    public ISet<string> AllowedHostnames { get; } = new HashSet<string>(System.StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Gets or sets a value indicating whether requests must be strictly restricted to <see cref="AllowedHostnames"/>
    /// when the set contains entries. When <see langword="true"/>, unlisted hosts and direct IPs are rejected.
    /// </summary>
    public bool RestrictToAllowedHostnames { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether HTTPS is required for all outgoing requests.
    /// Default is <see langword="true"/>.
    /// </summary>
    public bool RequireHttps { get; set; } = true;

    /// <summary>
    /// Gets or sets the maximum number of automatic redirects allowed.
    /// Each redirect target is validated against SSRF rules. Default is 5.
    /// </summary>
    public int MaxRedirects { get; set; } = 5;

    /// <summary>
    /// Gets or sets a value indicating whether to block well-known cloud metadata hostnames and IPs.
    /// Default is <see langword="true"/>.
    /// </summary>
    public bool BlockCloudMetadata { get; set; } = true;
}
