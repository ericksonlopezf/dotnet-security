// Copyright © Erickson Lopez. MIT License.
using System;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Threading;
using System.Threading.Tasks;

namespace EricksonLopez.Security.Network;

/// <summary>
/// Provides a high-performance <see cref="HttpMessageHandler"/> that enforces strict SSRF protections,
/// prevents DNS rebinding, and blocks outgoing connections to private networks and cloud metadata.
/// </summary>
public sealed class SafeSocketsHttpHandler : HttpMessageHandler
{
    private readonly HttpMessageHandler _innerHandler;
    private readonly ISafeDnsResolver _resolver;
    private readonly SsrfProtectionOptions _options;

    // Gets or sets an optional custom stream connector delegate for testing socket transport behaviors.
    internal Func<IPAddress, int, CancellationToken, ValueTask<Stream>>? StreamConnector { get; set; }

    internal HttpMessageHandler InnerHandler => _innerHandler;

    /// <summary>
    /// Initializes a new instance of the <see cref="SafeSocketsHttpHandler"/> class.
    /// </summary>
    /// <param name="resolver">Optional custom safe DNS resolver.</param>
    /// <param name="options">Optional SSRF protection options.</param>
    public SafeSocketsHttpHandler(
        ISafeDnsResolver? resolver = null,
        SsrfProtectionOptions? options = null)
        : this(resolver, options, null)
    {
    }

    internal SafeSocketsHttpHandler(
        ISafeDnsResolver? resolver,
        SsrfProtectionOptions? options,
        HttpMessageHandler? innerHandler)
    {
        _options = options ?? new SsrfProtectionOptions();
        _resolver = resolver ?? new SafeDnsResolver(_options);
        _innerHandler = innerHandler ?? new SocketsHttpHandler
        {
            AllowAutoRedirect = false, // Handle redirects explicitly or enforce redirect validation
            UseProxy = false,          // FORCED to prevent SSRF bypass via proxy DNS resolution
            ConnectCallback = ConnectCallbackAsync
        };
    }

    private async ValueTask<Stream> ConnectCallbackAsync(
        SocketsHttpConnectionContext context,
        CancellationToken cancellationToken)
    {
        var host = context.DnsEndPoint.Host;
        var port = context.DnsEndPoint.Port;

        var resolutionResult = await _resolver.ResolveAndValidateAsync(host, cancellationToken).ConfigureAwait(false);
        if (resolutionResult.IsFailure)
        {
            throw new HttpRequestException(
                $"SSRF Protection Blocked Request to '{host}:{port}': {resolutionResult.Error.Description}",
                null,
                HttpStatusCode.Forbidden);
        }

        var addresses = resolutionResult.Value;
        if (addresses.Length == 0)
        {
            throw new HttpRequestException(
                $"No valid IP addresses available for host '{host}'.",
                null,
                HttpStatusCode.BadGateway);
        }

        // Attempt connection to resolved and validated IP addresses
        Exception? lastException = null;

        Stream? stream = null;
        foreach (var address in addresses)
        {
            try
            {
                stream = StreamConnector is not null
                    ? await StreamConnector(address, port, cancellationToken).ConfigureAwait(false)
                    : await ConnectSocketCoreAsync(address, port, cancellationToken).ConfigureAwait(false);
                break;
            }
            catch (Exception ex)
            {
                lastException = ex;
            }
        }

        if (stream is null)
        {
            throw new HttpRequestException(
                $"Unable to connect to any resolved IP address for '{host}:{port}'.",
                lastException,
                HttpStatusCode.BadGateway);
        }

        return stream;
    }

    /// <inheritdoc />
    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        if (_options.RequireHttps && request.RequestUri != null && !request.RequestUri.Scheme.Equals("https", StringComparison.OrdinalIgnoreCase))
        {
            throw new HttpRequestException(
                $"Insecure scheme '{request.RequestUri.Scheme}' is prohibited by SSRF security policy. HTTPS is required.",
                null,
                HttpStatusCode.Forbidden);
        }

        // Execute initial request with manual redirect validation
        var currentRequest = request;
        var redirectCount = 0;

        while (true)
        {
            HttpResponseMessage response;
            using (var invoker = new HttpMessageInvoker(_innerHandler, disposeHandler: false))
            {
                response = await invoker.SendAsync(currentRequest, cancellationToken).ConfigureAwait(false);
            }

            if (IsRedirect(response.StatusCode) && response.Headers.Location != null)
            {
                if (redirectCount >= _options.MaxRedirects)
                {
                    throw new HttpRequestException(
                        $"Maximum redirect limit of {_options.MaxRedirects} exceeded.",
                        null,
                        HttpStatusCode.Redirect);
                }

                redirectCount++;
                var targetUri = new Uri(currentRequest.RequestUri!, response.Headers.Location);

                if (_options.RequireHttps && !targetUri.Scheme.Equals("https", StringComparison.OrdinalIgnoreCase))
                {
                    throw new HttpRequestException(
                        $"Redirect to insecure scheme '{targetUri.Scheme}' is prohibited by SSRF security policy.",
                        null,
                        HttpStatusCode.Forbidden);
                }

                response.Dispose();

                // Preserve method and content for 307 and 308 redirects
                bool preserveMethod = response.StatusCode is HttpStatusCode.TemporaryRedirect or HttpStatusCode.PermanentRedirect;
                var redirectMethod = preserveMethod ? currentRequest.Method : HttpMethod.Get;

                var redirectRequest = new HttpRequestMessage(redirectMethod, targetUri);

                // Copy original non-sensitive headers (RFC 6454 origin: Scheme, Host, Port)
                bool isCrossOrigin = !string.Equals(currentRequest.RequestUri!.Scheme, targetUri.Scheme, StringComparison.OrdinalIgnoreCase) ||
                                     !string.Equals(currentRequest.RequestUri!.Host, targetUri.Host, StringComparison.OrdinalIgnoreCase) ||
                                     currentRequest.RequestUri!.Port != targetUri.Port;

                if (preserveMethod && currentRequest.Content != null)
                {
                    if (isCrossOrigin)
                    {
                        // SEC-004 / FINDING-NEW-05: Prohibit silent cross-origin payload exfiltration on 307/308 redirects
                        throw new HttpRequestException(
                            $"Cross-origin redirect ({(int)response.StatusCode}) for HTTP method '{currentRequest.Method}' with payload content is prohibited to prevent credential and body exfiltration.",
                            null,
                            HttpStatusCode.Redirect);
                    }

                    redirectRequest.Content = currentRequest.Content;
                }

                foreach (var header in currentRequest.Headers)
                {
                    if (isCrossOrigin && IsSensitiveCredentialHeader(header.Key))
                    {
                        continue; // SEC-004 / FINDING-NEW-02: Strip Authorization, Cookies, and API keys on cross-origin redirects
                    }
                    redirectRequest.Headers.TryAddWithoutValidation(header.Key, header.Value);
                }

                currentRequest = redirectRequest;
                continue;
            }

            return response;
        }
    }

    private static bool IsSensitiveCredentialHeader(string headerName) =>
        string.Equals(headerName, "Authorization", StringComparison.OrdinalIgnoreCase) ||
        string.Equals(headerName, "Cookie", StringComparison.OrdinalIgnoreCase) ||
        string.Equals(headerName, "Cookie2", StringComparison.OrdinalIgnoreCase) ||
        string.Equals(headerName, "X-Api-Key", StringComparison.OrdinalIgnoreCase) ||
        string.Equals(headerName, "X-Auth-Token", StringComparison.OrdinalIgnoreCase) ||
        string.Equals(headerName, "Proxy-Authorization", StringComparison.OrdinalIgnoreCase) ||
        string.Equals(headerName, "Sec-WebSocket-Key", StringComparison.OrdinalIgnoreCase);

    private static bool IsRedirect(HttpStatusCode statusCode) =>
        statusCode is HttpStatusCode.MovedPermanently or
                      HttpStatusCode.Found or
                      HttpStatusCode.SeeOther or
                      HttpStatusCode.TemporaryRedirect or
                      HttpStatusCode.PermanentRedirect;

    /// <inheritdoc />
    [ExcludeFromCodeCoverage(
        Justification = "CA2215 requires calling base.Dispose(bool) which is an empty method in HttpMessageHandler in .NET runtime.")]
    protected override void Dispose(bool disposing)
    {
        _innerHandler.Dispose();
        base.Dispose(disposing);
    }

    [ExcludeFromCodeCoverage(
        Justification = "Direct native operating system TCP socket connection to external non-deterministic network endpoints during tests.")]
    private static async ValueTask<Stream> ConnectSocketCoreAsync(IPAddress address, int port, CancellationToken cancellationToken)
    {
        var socket = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp)
        {
            NoDelay = true
        };

        try
        {
            await socket.ConnectAsync(new IPEndPoint(address, port), cancellationToken).ConfigureAwait(false);
            return new NetworkStream(socket, ownsSocket: true);
        }
        catch
        {
            socket.Dispose();
            throw;
        }
    }
}
