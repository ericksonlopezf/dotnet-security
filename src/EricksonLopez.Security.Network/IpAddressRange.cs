// Copyright © Erickson Lopez. MIT License.
using System;
using System.Net;
using System.Net.Sockets;

namespace EricksonLopez.Security.Network;

/// <summary>
/// Represents a contiguous range of IP addresses defined by an IP network prefix and CIDR mask.
/// </summary>
public readonly struct IpAddressRange : IEquatable<IpAddressRange>
{
    private readonly byte[] _networkBytes;
    private readonly byte[] _maskBytes;
    private readonly AddressFamily _addressFamily;

    /// <summary>
    /// Initializes a new instance of the <see cref="IpAddressRange"/> struct from an IP address and CIDR prefix length.
    /// </summary>
    /// <param name="baseAddress">The base IP address of the network.</param>
    /// <param name="prefixLength">The CIDR prefix length (0-32 for IPv4, 0-128 for IPv6).</param>
    /// <exception cref="ArgumentNullException"><paramref name="baseAddress"/> is <see langword="null"/></exception>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="prefixLength"/> is invalid for the address family</exception>
    public IpAddressRange(IPAddress baseAddress, int prefixLength)
    {
        ArgumentNullException.ThrowIfNull(baseAddress);

        _addressFamily = baseAddress.AddressFamily;
        var addressBytes = baseAddress.GetAddressBytes();
        var maxPrefix = addressBytes.Length * 8;

        if (prefixLength < 0 || prefixLength > maxPrefix)
        {
            throw new ArgumentOutOfRangeException(
                nameof(prefixLength),
                $"Prefix length must be between 0 and {maxPrefix} for {_addressFamily}.");
        }

        _maskBytes = CreateMask(addressBytes.Length, prefixLength);
        _networkBytes = ApplyMask(addressBytes, _maskBytes);
    }

    /// <summary>
    /// Parses a CIDR string (e.g., "10.0.0.0/8" or "192.168.1.1") into an <see cref="IpAddressRange"/>.
    /// </summary>
    /// <param name="cidrOrAddress">The CIDR or single IP address string.</param>
    /// <returns>The parsed <see cref="IpAddressRange"/>.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="cidrOrAddress"/> is <see langword="null"/></exception>
    /// <exception cref="FormatException">The format of the string is invalid</exception>
    public static IpAddressRange Parse(string cidrOrAddress)
    {
        ArgumentNullException.ThrowIfNull(cidrOrAddress);

        var slashIndex = cidrOrAddress.IndexOf('/', StringComparison.Ordinal);
        if (slashIndex == -1)
        {
            var singleAddress = IPAddress.Parse(cidrOrAddress);
            var bits = singleAddress.AddressFamily == AddressFamily.InterNetwork ? 32 : 128;
            return new IpAddressRange(singleAddress, bits);
        }

        var ipPart = cidrOrAddress.Substring(0, slashIndex);
        var prefixPart = cidrOrAddress.Substring(slashIndex + 1);

        var ip = IPAddress.Parse(ipPart);
        var prefix = int.Parse(prefixPart, System.Globalization.CultureInfo.InvariantCulture);

        return new IpAddressRange(ip, prefix);
    }

    /// <summary>
    /// Determines whether the specified <see cref="IPAddress"/> falls within this network range.
    /// </summary>
    /// <param name="address">The IP address to evaluate.</param>
    /// <returns><see langword="true"/> if the address is contained in this range; otherwise, <see langword="false"/>.</returns>
    public bool Contains(IPAddress address)
    {
        if (address is null)
        {
            return false;
        }

        var targetAddress = address;
        if (_addressFamily == AddressFamily.InterNetwork && targetAddress.IsIPv4MappedToIPv6)
        {
            targetAddress = targetAddress.MapToIPv4();
        }

        if (targetAddress.AddressFamily != _addressFamily)
        {
            return false;
        }

        var addressBytes = targetAddress.GetAddressBytes();
        for (var i = 0; i < addressBytes.Length; i++)
        {
            if ((addressBytes[i] & _maskBytes[i]) != _networkBytes[i])
            {
                return false;
            }
        }

        return true;
    }

    private static byte[] CreateMask(int length, int prefixLength)
    {
        var mask = new byte[length];
        var fullBytes = prefixLength / 8;
        var remainingBits = prefixLength % 8;

        for (var i = 0; i < fullBytes; i++)
        {
            mask[i] = 0xFF;
        }

        if (remainingBits > 0)
        {
            mask[fullBytes] = (byte)(0xFF << (8 - remainingBits));
        }

        return mask;
    }

    private static byte[] ApplyMask(byte[] addressBytes, byte[] maskBytes)
    {
        var result = new byte[addressBytes.Length];
        for (var i = 0; i < addressBytes.Length; i++)
        {
            result[i] = (byte)(addressBytes[i] & maskBytes[i]);
        }
        return result;
    }

    /// <inheritdoc />
    public bool Equals(IpAddressRange other)
    {
        if (_addressFamily != other._addressFamily)
        {
            return false;
        }

        return _networkBytes.AsSpan().SequenceEqual(other._networkBytes.AsSpan()) &&
               _maskBytes.AsSpan().SequenceEqual(other._maskBytes.AsSpan());
    }

    /// <inheritdoc />
    public override bool Equals(object? obj) => obj is IpAddressRange other && Equals(other);

    /// <inheritdoc />
    public override int GetHashCode() => HashCode.Combine(_addressFamily, _networkBytes?.Length);

    /// <summary>
    /// Determines whether two <see cref="IpAddressRange"/> instances represent the same network range.
    /// </summary>
    /// <param name="left">The first network range to compare.</param>
    /// <param name="right">The second network range to compare.</param>
    /// <returns><see langword="true"/> if both instances represent the same network range; otherwise, <see langword="false"/>.</returns>
    public static bool operator ==(IpAddressRange left, IpAddressRange right) => left.Equals(right);

    /// <summary>
    /// Determines whether two <see cref="IpAddressRange"/> instances represent different network ranges.
    /// </summary>
    /// <param name="left">The first network range to compare.</param>
    /// <param name="right">The second network range to compare.</param>
    /// <returns><see langword="true"/> if both instances represent different network ranges; otherwise, <see langword="false"/>.</returns>
    public static bool operator !=(IpAddressRange left, IpAddressRange right) => !left.Equals(right);
}
