// Copyright © Erickson Lopez. MIT License.
using System;
using System.Net.Http;

namespace EricksonLopez.Security.Network;

/// <summary>
/// Provides factory methods for creating pre-configured, SSRF-safe <see cref="HttpClient"/> instances.
/// </summary>
public static class SafeHttpClientFactory
{
    /// <summary>
    /// Creates a new <see cref="HttpClient"/> instance configured with strict SSRF protections.
    /// </summary>
    /// <param name="configure">Optional delegate to configure SSRF protection options.</param>
    /// <returns>A configured <see cref="HttpClient"/> instance.</returns>
    public static HttpClient CreateClient(Action<SsrfProtectionOptions>? configure = null)
    {
        var options = new SsrfProtectionOptions();
        configure?.Invoke(options);

        var resolver = new SafeDnsResolver(options);
        var handler = new SafeSocketsHttpHandler(resolver, options);

        return new HttpClient(handler);
    }
}
