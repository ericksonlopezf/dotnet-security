// Copyright © Erickson Lopez. MIT License.
using System;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using EricksonLopez.Result;

namespace EricksonLopez.Security.Network;

/// <summary>
/// Provides DNS resolution with validation against prohibited private network ranges and cloud metadata services.
/// </summary>
public sealed class SafeDnsResolver : ISafeDnsResolver
{
    // NET-005 fix: expanded cloud metadata hostname blocklist.
    // Note: IP-based metadata services (e.g., 169.254.169.254, 100.100.100.200) are also
    // covered by CIDR ranges in SsrfProtectionOptions.DefaultBlockedRanges, but hostname-based
    // requests that resolve to non-CIDR IPs must be explicitly blocked here.
    private static readonly string[] s_cloudMetadataHosts =
    [
        // GCP
        "metadata.google.internal",

        // Tencent Cloud
        "metadata.tencentyun.com",

        // Generic/legacy internal metadata hostname
        "instance-data",

        // Universal IMDS IP (hostname form — IP form is blocked by 169.254.0.0/16 CIDR)
        "169.254.169.254",

        // AWS ECS task metadata (distinct from IMDS)
        "169.254.170.2",

        // Alibaba Cloud metadata (100.100.100.200 — blocked by 100.64.0.0/10 CGNAT CIDR)
        "100.100.100.200",

        // Azure IMDS hostname variants
        "metadata.azure.com",
        "azure-metadata.azure.com",

        // Equinix Metal (formerly Packet.net)
        "metadata.packet.net",

        // Hetzner Cloud
        "metadata.hetzner.cloud",

        // Oracle Cloud Infrastructure (169.254.169.254 — already listed above and covered by 169.254.0.0/16 CIDR)
    ];

    private readonly SsrfProtectionOptions _options;
    private readonly Func<string, CancellationToken, Task<IPAddress[]>> _dnsLookup;

    /// <summary>
    /// Initializes a new instance of the <see cref="SafeDnsResolver"/> class.
    /// </summary>
    /// <param name="options">SSRF protection options.</param>
    /// <param name="dnsLookup">Optional DNS lookup delegate for testing and simulation.</param>
    public SafeDnsResolver(
        SsrfProtectionOptions? options = null,
        Func<string, CancellationToken, Task<IPAddress[]>>? dnsLookup = null)
    {
        _options = options ?? new SsrfProtectionOptions();
        _dnsLookup = dnsLookup ?? ((h, ct) => Dns.GetHostAddressesAsync(h, ct));
    }

    /// <inheritdoc />
    public async Task<Result<IPAddress[]>> ResolveAndValidateAsync(
        string host,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(host))
        {
            return Error.Validation("SafeDnsResolver.EmptyHost", "Target host cannot be null or whitespace.");
        }

        var normalizedHost = host.Trim().TrimEnd('.');

        // NET-007 / FINDING-WEB-01 fix: reject ambiguous numeric IPv4 formats (such as octal with leading zeros)
        // that could be used for SSRF bypass evasion.
        if (HasAmbiguousNumericFormat(normalizedHost))
        {
            return Error.Forbidden(
                "SafeDnsResolver.AmbiguousIpFormat",
                $"Host '{normalizedHost}' uses ambiguous numeric formatting with leading zeros.");
        }

        // 1. Cloud metadata host check
        if (_options.BlockCloudMetadata && s_cloudMetadataHosts.Contains(normalizedHost, StringComparer.OrdinalIgnoreCase))
        {
            return Error.Forbidden(
                "SafeDnsResolver.CloudMetadataBlocked",
                $"Access to cloud metadata host '{normalizedHost}' is strictly prohibited.");
        }

        // 2. Allowlisted hostnames resolution with IP address validation
        if (_options.AllowedHostnames.Contains(normalizedHost))
        {
            try
            {
                var allowedIps = await _dnsLookup(normalizedHost, cancellationToken).ConfigureAwait(false);
                if (allowedIps.Length == 0)
                {
                    return Error.Failure("SafeDnsResolver.NoAddressesResolved", $"No IP addresses resolved for allowlisted host '{normalizedHost}'.");
                }

                foreach (var ip in allowedIps)
                {
                    var validationError = ValidateAddress(ip);
                    if (validationError != null)
                    {
                        return validationError;
                    }
                }

                return Result<IPAddress[]>.Success(allowedIps);
            }
            catch (Exception ex)
            {
                return Error.Failure("SafeDnsResolver.DnsResolutionFailed", $"DNS resolution failed for allowlisted host '{normalizedHost}': {ex.Message}");
            }
        }

        // NET-002 fix: activate the allowlist restriction automatically when AllowedHostnames has entries.
        // Previously, AllowedHostnames entries had no restrictive effect unless RestrictToAllowedHostnames=true
        // was also set — a silent misconfiguration that could provide false confidence in SSRF protection.
        // Now: having any entries in AllowedHostnames implies the intent to restrict; the flag
        // RestrictToAllowedHostnames=true can additionally block all unresolved hosts even with an empty list.
        var hostsAreRestricted = _options.RestrictToAllowedHostnames || _options.AllowedHostnames.Count > 0;
        if (hostsAreRestricted)
        {
            return Error.Forbidden(
                "SafeDnsResolver.HostNotAllowed",
                $"Target host '{normalizedHost}' is not present in the allowed hostnames list.");
        }

        // 3. Check if host is directly an IP literal
        if (IPAddress.TryParse(normalizedHost, out var directIp))
        {
            var validationError = ValidateAddress(directIp);
            if (validationError != null)
            {
                return validationError;
            }

            return Result<IPAddress[]>.Success([directIp]);
        }

        // 4. Resolve host to IP addresses via DNS
        IPAddress[] addresses;
        try
        {
            addresses = await _dnsLookup(normalizedHost, cancellationToken).ConfigureAwait(false);
        }
        catch (SocketException ex)
        {
            return Error.Failure(
                "SafeDnsResolver.HostNotFound",
                $"DNS resolution failed for host '{normalizedHost}': {ex.Message}");
        }

        if (addresses.Length == 0)
        {
            return Error.Failure(
                "SafeDnsResolver.NoAddressesResolved",
                $"DNS resolution for host '{normalizedHost}' returned no IP addresses.");
        }

        // 5. Validate EVERY resolved IP address to prevent DNS rebinding attacks
        foreach (var address in addresses)
        {
            var error = ValidateAddress(address);
            if (error != null)
            {
                return error;
            }
        }

        return Result<IPAddress[]>.Success(addresses);
    }

    private Error? ValidateAddress(IPAddress address)
    {
        // NET-006 fix: normalize IPv4-mapped IPv6 addresses (::ffff:10.0.0.1 → 10.0.0.1) before
        // range validation. IpAddressRange.Contains() already handles this mapping internally, but
        // we normalize here for consistent error messages and to simplify allowed/blocked range logic.
        var normalizedAddress = address.IsIPv4MappedToIPv6
            ? address.MapToIPv4()
            : address;

        // Allowed ranges override blocked ranges
        foreach (var allowed in _options.AllowedRanges)
        {
            if (allowed.Contains(normalizedAddress))
            {
                return null;
            }
        }

        // Check blocked ranges
        foreach (var blocked in _options.BlockedRanges)
        {
            if (blocked.Contains(normalizedAddress))
            {
                return Error.Forbidden(
                    "SafeDnsResolver.ProhibitedIpRange",
                    $"Resolved IP address '{normalizedAddress}' falls within prohibited network range.");
            }
        }

        return null;
    }

    private static bool HasAmbiguousNumericFormat(string host)
    {
        var parts = host.Split('.');
        if (parts.Length == 4)
        {
            bool allNumeric = true;
            bool hasLeadingZero = false;
            foreach (var part in parts)
            {
                if (part.Length == 0 || !IsAllDigits(part))
                {
                    allNumeric = false;
                    break;
                }

                if (part.Length > 1 && part[0] == '0')
                {
                    hasLeadingZero = true;
                }
            }

            return allNumeric && hasLeadingZero;
        }

        return false;
    }

    private static bool IsAllDigits(string str)
    {
        foreach (char c in str)
        {
            if (c < '0' || c > '9')
            {
                return false;
            }
        }
        return true;
    }
}
