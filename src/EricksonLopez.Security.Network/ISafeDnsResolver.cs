// Copyright © Erickson Lopez. MIT License.
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using EricksonLopez.Result;

namespace EricksonLopez.Security.Network;

/// <summary>
/// Defines a DNS resolver that validates resolved IP addresses against SSRF policies.
/// </summary>
public interface ISafeDnsResolver
{
    /// <summary>
    /// Resolves the host name to IP addresses and validates that all addresses comply with SSRF protection policies.
    /// </summary>
    /// <param name="host">The host name or IP string to resolve and validate.</param>
    /// <param name="cancellationToken">A token that can be used to cancel the asynchronous operation.</param>
    /// <returns>A task representing the asynchronous operation. The task result contains a successful result with the valid IP addresses, or an error describing the SSRF violation.</returns>
    Task<Result<IPAddress[]>> ResolveAndValidateAsync(string host, CancellationToken cancellationToken = default);
}
