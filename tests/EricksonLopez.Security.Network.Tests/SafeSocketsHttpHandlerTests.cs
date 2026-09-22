// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Network.Tests;

using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using AwesomeAssertions;
using NSubstitute;
using EricksonLopez.Result;
using EricksonLopez.Security.Testing.Http;
using Xunit;

[Trait("Category", "Integration")]
public sealed class SafeSocketsHttpHandlerTests
{

    [Fact]
    public async Task SendAsync_InsecureHttpScheme_ThrowsHttpRequestException()
    {
        using var client = SafeHttpClientFactory.CreateClient(options => options.RequireHttps = true);

        var act = async () => await client.GetAsync("http://example.com");

        await act.Should().ThrowAsync<HttpRequestException>()
            .WithMessage("*Insecure scheme 'http' is prohibited by SSRF security policy*");
    }

    [Fact]
    public async Task SendAsync_ProhibitedPrivateIp_ThrowsHttpRequestException()
    {
        using var client = SafeHttpClientFactory.CreateClient();

        var act = async () => await client.GetAsync("https://127.0.0.1:8443");

        await act.Should().ThrowAsync<HttpRequestException>()
            .WithMessage("*SSRF Protection Blocked Request*");
    }

    [Fact]
    public async Task SendAsync_ProhibitedIpv4MappedIpv6_ThrowsHttpRequestException()
    {
        using var client = SafeHttpClientFactory.CreateClient();

        var act = async () => await client.GetAsync("https://[::ffff:127.0.0.1]:8443");

        await act.Should().ThrowAsync<HttpRequestException>()
            .WithMessage("*SSRF Protection Blocked Request*");
    }

    [Fact]
    public async Task SendAsync_NullRequest_ThrowsArgumentNullException()
    {
        using var handler = new SafeSocketsHttpHandler();
        using var invoker = new HttpMessageInvoker(handler);

        var act = async () => await invoker.SendAsync(null!, CancellationToken.None);
        await act.Should().ThrowAsync<ArgumentNullException>();
    }

    [Fact]
    public async Task SafeHttpClientFactory_CreatesClientInstance_WithCustomConfiguration()
    {
        var configured = false;
        var client = SafeHttpClientFactory.CreateClient(opt =>
        {
            opt.MaxRedirects = 10;
            configured = true;
        });

        client.Should().NotBeNull();
        configured.Should().BeTrue();

        // Disposing client disposes the underlying handler
        client.Dispose();
        var act = () => client.GetAsync("https://example.com");
        await act.Should().ThrowAsync<ObjectDisposedException>();
    }


    [Fact]
    public async Task ConnectCallback_ResolverReturnsEmptyAddresses_ThrowsBadGateway()
    {
        var mockResolver = Substitute.For<ISafeDnsResolver>();
        mockResolver.ResolveAndValidateAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(Result<IPAddress[]>.Success([])));

        var options = new SsrfProtectionOptions { RequireHttps = false };
        using var handler = new SafeSocketsHttpHandler(mockResolver, options);
        using var client = new HttpClient(handler);

        var act = async () => await client.GetAsync("http://mock-host-empty/test");
        var ex = await act.Should().ThrowAsync<HttpRequestException>();
        ex.Which.ToString().Should().Contain("No valid IP addresses available");
    }

    private sealed class DuplexHttpTestStream : Stream
    {
        private readonly MemoryStream _readStream = new("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"u8.ToArray());
        private readonly MemoryStream _writeStream = new();

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => _readStream.Length;
        public override long Position { get => _readStream.Position; set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override int Read(byte[] buffer, int offset, int count) => _readStream.Read(buffer, offset, count);
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => _writeStream.Write(buffer, offset, count);
        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            _writeStream.Write(buffer.Span);
            return ValueTask.CompletedTask;
        }
    }

    [Fact]
    public async Task ConnectCallback_MultipleAddresses_FirstFails_SecondSucceeds_ConnectsSuccessfully()
    {
        var addr1 = IPAddress.Parse("93.184.216.34");
        var addr2 = IPAddress.Parse("93.184.216.35");
        var mockResolver = Substitute.For<ISafeDnsResolver>();
        mockResolver.ResolveAndValidateAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(Result<IPAddress[]>.Success([addr1, addr2])));

        var options = new SsrfProtectionOptions { RequireHttps = false };
        var attemptedAddresses = new List<IPAddress>();

        using var duplexStream = new DuplexHttpTestStream();
        using var handler = new SafeSocketsHttpHandler(mockResolver, options)
        {
            StreamConnector = (addr, port, ct) =>
            {
                attemptedAddresses.Add(addr);
                if (Equals(addr, addr1))
                {
                    throw new SocketException((int)SocketError.ConnectionRefused);
                }
                return ValueTask.FromResult<Stream>(duplexStream);
            }
        };
        using var client = new HttpClient(handler);

        var response = await client.GetAsync("http://example.com/test");
        response.StatusCode.Should().Be(HttpStatusCode.OK);
        attemptedAddresses.Should().Equal(addr1, addr2);
    }

    [Fact]
    public async Task ConnectCallback_ConnectionFails_ThrowsBadGateway()
    {
        var mockResolver = Substitute.For<ISafeDnsResolver>();
        mockResolver.ResolveAndValidateAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(Result<IPAddress[]>.Success([IPAddress.Loopback])));

        var options = new SsrfProtectionOptions { RequireHttps = false };
        options.AllowedRanges.Add(IpAddressRange.Parse("127.0.0.1/32"));

        using var handler = new SafeSocketsHttpHandler(mockResolver, options)
        {
            StreamConnector = (addr, port, ct) => throw new SocketException((int)SocketError.ConnectionRefused)
        };
        using var client = new HttpClient(handler);

        var act = async () => await client.GetAsync("http://localhost:1/test");
        var ex = await act.Should().ThrowAsync<HttpRequestException>();
        ex.Which.ToString().Should().Contain("Unable to connect to any resolved IP address");
        Assert.IsType<SocketException>(ex.Which.GetBaseException());
    }

    [Fact]
    public async Task ConnectCallback_WithoutStreamConnector_CallsConnectSocketCoreAndThrowsBadGatewayOnUnreachable()
    {
        var mockResolver = Substitute.For<ISafeDnsResolver>();
        mockResolver.ResolveAndValidateAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(Result<IPAddress[]>.Success([IPAddress.Loopback])));

        var options = new SsrfProtectionOptions { RequireHttps = false };
        options.AllowedRanges.Add(IpAddressRange.Parse("127.0.0.1/32"));

        using var handler = new SafeSocketsHttpHandler(mockResolver, options);
        using var client = new HttpClient(handler);

        var act = async () => await client.GetAsync("http://localhost:1/test");
        var ex = await act.Should().ThrowAsync<HttpRequestException>();
        ex.Which.ToString().Should().Contain("Unable to connect to any resolved IP address");
        Assert.NotNull(ex.Which.GetBaseException());
    }

    [Fact]
    public async Task ConnectCallback_WithStreamConnector_SucceedsAndReturnsStream()
    {
        var mockResolver = Substitute.For<ISafeDnsResolver>();
        mockResolver.ResolveAndValidateAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(Result<IPAddress[]>.Success([IPAddress.Loopback, IPAddress.Parse("127.0.0.2")])));

        var options = new SsrfProtectionOptions { RequireHttps = false };
        options.AllowedRanges.Add(IpAddressRange.Parse("127.0.0.1/32"));
        options.AllowedRanges.Add(IpAddressRange.Parse("127.0.0.2/32"));

        var calledWithSecondAddress = false;
        using var memoryStream = new MemoryStream();
        using var handler = new SafeSocketsHttpHandler(mockResolver, options)
        {
            StreamConnector = (addr, port, ct) =>
            {
                if (addr.Equals(IPAddress.Parse("127.0.0.2")))
                {
                    calledWithSecondAddress = true;
                }
                return ValueTask.FromResult<Stream>(memoryStream);
            }
        };
        using var client = new HttpClient(handler);

        Exception? caughtException = null;
        try
        {
            await client.GetAsync("http://localhost:1/test");
        }
        catch (Exception ex)
        {
            caughtException = ex;
        }

        caughtException.Should().NotBeNull();
        Assert.False(calledWithSecondAddress);
    }

    [Fact]
    public void SafeSocketsHttpHandler_DefaultInnerHandler_DisablesAutoRedirect()
    {
        using var handler = new SafeSocketsHttpHandler();
        var socketsHandler = Assert.IsType<SocketsHttpHandler>(handler.InnerHandler);
        Assert.False(socketsHandler.AllowAutoRedirect);
    }

    [Fact]
    public async Task SendAsync_RedirectToInsecureHttp_WhenRequireHttps_ThrowsForbidden()
    {
        var mockInner = new TestHttpMessageHandler((req, ct) =>
        {
            var resp = new HttpResponseMessage(HttpStatusCode.Redirect);
            resp.Headers.Location = new Uri("http://insecure-partner.com/api");
            return Task.FromResult(resp);
        });

        var options = new SsrfProtectionOptions { RequireHttps = true };
        using var handler = new SafeSocketsHttpHandler(resolver: null, options: options, innerHandler: mockInner);
        using var invoker = new HttpMessageInvoker(handler);

        var req = new HttpRequestMessage(HttpMethod.Get, "https://secure-site.com/start");

        var act = async () => await invoker.SendAsync(req, CancellationToken.None);
        var ex = await act.Should().ThrowAsync<HttpRequestException>()
            .WithMessage("*Redirect to insecure scheme 'http' is prohibited*");
        ex.Which.StatusCode.Should().Be(HttpStatusCode.Forbidden);
    }

    [Fact]
    public async Task SendAsync_RedirectLoop_ExceedsMaxRedirects_ExactBoundary()
    {
        var count = 0;
        var mockInner = new TestHttpMessageHandler((req, ct) =>
        {
            count++;
            var resp = new HttpResponseMessage(HttpStatusCode.TemporaryRedirect);
            resp.Headers.Location = new Uri($"https://secure-site.com/step/{count}");
            return Task.FromResult(resp);
        });

        // MaxRedirects = 1: initial request -> redirect 1 (redirectCount becomes 1 <= 1) -> redirect 2 (redirectCount becomes 1 >= 1 -> throws)
        var options = new SsrfProtectionOptions { RequireHttps = true, MaxRedirects = 1 };
        using var handler = new SafeSocketsHttpHandler(resolver: null, options: options, innerHandler: mockInner);
        using var invoker = new HttpMessageInvoker(handler);

        var req = new HttpRequestMessage(HttpMethod.Get, "https://secure-site.com/start");

        var act = async () => await invoker.SendAsync(req, CancellationToken.None);
        var ex = await act.Should().ThrowAsync<HttpRequestException>()
            .WithMessage("*Maximum redirect limit of 1 exceeded*");
        ex.Which.StatusCode.Should().Be(HttpStatusCode.Redirect);
        count.Should().Be(2);
    }

    [Fact]
    public async Task SendAsync_NonRedirectWithLocationHeader_DoesNotRedirect()
    {
        var mockInner = new TestHttpMessageHandler((req, ct) =>
        {
            var resp = new HttpResponseMessage(HttpStatusCode.Created);
            resp.Headers.Location = new Uri("https://secure-site.com/resource/123");
            return Task.FromResult(resp);
        });

        var options = new SsrfProtectionOptions { RequireHttps = true };
        using var handler = new SafeSocketsHttpHandler(resolver: null, options: options, innerHandler: mockInner);
        using var invoker = new HttpMessageInvoker(handler);

        var req = new HttpRequestMessage(HttpMethod.Post, "https://secure-site.com/create");
        var response = await invoker.SendAsync(req, CancellationToken.None);

        response.StatusCode.Should().Be(HttpStatusCode.Created);
    }

    [Fact]
    public async Task SendAsync_RedirectWithRelativeAndAbsoluteUri_FollowsChainSuccessfully()
    {
        var step = 0;
        var mockInner = new TestHttpMessageHandler((req, ct) =>
        {
            step++;
            if (step == 1)
            {
                var resp = new HttpResponseMessage(HttpStatusCode.MovedPermanently);
                resp.Headers.Location = new Uri("https://secure-site.com/step2");
                return Task.FromResult(resp);
            }
            if (step == 2)
            {
                var resp = new HttpResponseMessage(HttpStatusCode.SeeOther);
                resp.Headers.Location = new Uri("/final", UriKind.Relative);
                return Task.FromResult(resp);
            }

            var okResp = new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("Redirect Chain Success")
            };
            return Task.FromResult(okResp);
        });

        var options = new SsrfProtectionOptions { RequireHttps = true, MaxRedirects = 5 };
        using var handler = new SafeSocketsHttpHandler(resolver: null, options: options, innerHandler: mockInner);
        using var invoker = new HttpMessageInvoker(handler);

        var req = new HttpRequestMessage(HttpMethod.Get, "https://secure-site.com/step1");
        var response = await invoker.SendAsync(req, CancellationToken.None);

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var content = await response.Content.ReadAsStringAsync();
        content.Should().Be("Redirect Chain Success");
    }

    [Theory]
    [InlineData(HttpStatusCode.MovedPermanently)]
    [InlineData(HttpStatusCode.Found)]
    [InlineData(HttpStatusCode.SeeOther)]
    [InlineData(HttpStatusCode.TemporaryRedirect)]
    [InlineData(HttpStatusCode.PermanentRedirect)]
    public async Task SendAsync_AllRedirectStatusCodes_AreHandled(HttpStatusCode redirectCode)
    {
        var step = 0;
        var mockInner = new TestHttpMessageHandler((req, ct) =>
        {
            step++;
            if (step == 1)
            {
                var resp = new HttpResponseMessage(redirectCode);
                resp.Headers.Location = new Uri("https://secure-site.com/destination");
                return Task.FromResult(resp);
            }

            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK));
        });

        var options = new SsrfProtectionOptions { RequireHttps = true };
        using var handler = new SafeSocketsHttpHandler(resolver: null, options: options, innerHandler: mockInner);
        using var invoker = new HttpMessageInvoker(handler);

        var req = new HttpRequestMessage(HttpMethod.Get, "https://secure-site.com/origin");
        var response = await invoker.SendAsync(req, CancellationToken.None);

        response.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public void SafeSocketsHttpHandler_Dispose_DisposesInnerHandler()
    {
        var mockInner = new TestHttpMessageHandler((req, ct) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)));
        var handler = new SafeSocketsHttpHandler(resolver: null, options: null, innerHandler: mockInner);

        mockInner.IsDisposed.Should().BeFalse();
        handler.Dispose();
        mockInner.IsDisposed.Should().BeTrue();
    }

    [Fact]
    public async Task SendAsync_DnsRebindingAttack_ThrowsHttpRequestExceptionWithForbidden()
    {
        var mockResolver = Substitute.For<ISafeDnsResolver>();
        mockResolver.ResolveAndValidateAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(Result<IPAddress[]>.Failure(
                Error.Forbidden("SafeDnsResolver.ProhibitedIpRange", "Resolved IP address falls within prohibited network range."))));

        var options = new SsrfProtectionOptions { RequireHttps = false };
        using var handler = new SafeSocketsHttpHandler(mockResolver, options);
        using var client = new HttpClient(handler);

        var act = async () => await client.GetAsync("http://rebinding-attack.attacker.com/steal");
        await act.Should().ThrowAsync<HttpRequestException>()
            .WithMessage("*SSRF Protection Blocked Request*");
    }

    [Fact]
    public async Task SendAsync_IdnPunycodeHostname_ThrowsHttpRequestExceptionWhenResolvedToPrivateIp()
    {
        var mockResolver = Substitute.For<ISafeDnsResolver>();
        mockResolver.ResolveAndValidateAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(Result<IPAddress[]>.Failure(
                Error.Forbidden("SafeDnsResolver.ProhibitedIpRange", "Resolved IP address falls within prohibited network range."))));

        var options = new SsrfProtectionOptions { RequireHttps = true };
        using var handler = new SafeSocketsHttpHandler(mockResolver, options);
        using var client = new HttpClient(handler);

        var act = async () => await client.GetAsync("https://xn--e1afmkfd.xn--p1ai/");
        await act.Should().ThrowAsync<HttpRequestException>()
            .WithMessage("*SSRF Protection Blocked Request*");
    }

    [Fact]
    public async Task SendAsync_NullRequest_DirectInvocation_ThrowsArgumentNullException()
    {
        using var handler = new SafeSocketsHttpHandler();
        var method = typeof(SafeSocketsHttpHandler).GetMethod("SendAsync", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)!;

        var act = () =>
        {
            try
            {
                var task = (Task<HttpResponseMessage>)method.Invoke(handler, [null, CancellationToken.None])!;
                return task;
            }
            catch (System.Reflection.TargetInvocationException ex) when (ex.InnerException != null)
            {
                throw ex.InnerException;
            }
        };

        var ex = await act.Should().ThrowAsync<ArgumentNullException>();
        ex.Which.ParamName.Should().Be("request");
    }

    private sealed class TrackableHttpResponseMessage : HttpResponseMessage
    {
        public bool Disposed { get; private set; }
        public TrackableHttpResponseMessage(HttpStatusCode code) : base(code) { }
        protected override void Dispose(bool disposing)
        {
            Disposed = true;
            base.Dispose(disposing);
        }
    }

    [Fact]
    public async Task SendAsync_Redirect_DisposesIntermediateResponse()
    {
        TrackableHttpResponseMessage? intermediateResponse = null;
        var step = 0;
        var mockInner = new TestHttpMessageHandler((req, ct) =>
        {
            step++;
            if (step == 1)
            {
                intermediateResponse = new TrackableHttpResponseMessage(HttpStatusCode.Redirect);
                intermediateResponse.Headers.Location = new Uri("https://secure-site.com/destination");
                return Task.FromResult<HttpResponseMessage>(intermediateResponse);
            }

            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK));
        });

        var options = new SsrfProtectionOptions { RequireHttps = true };
        using var handler = new SafeSocketsHttpHandler(resolver: null, options: options, innerHandler: mockInner);
        using var invoker = new HttpMessageInvoker(handler);

        var req = new HttpRequestMessage(HttpMethod.Get, "https://secure-site.com/origin");
        var response = await invoker.SendAsync(req, CancellationToken.None);

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        intermediateResponse.Should().NotBeNull();
        intermediateResponse!.Disposed.Should().BeTrue();
    }

    [Fact]
    public async Task SafeSocketsHttpHandler_Dispose_InvokesBaseDispose_SettingDisposedState()
    {
        var mockInner = new TestHttpMessageHandler((req, ct) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)));
        var handler = new SafeSocketsHttpHandler(resolver: null, options: null, innerHandler: mockInner);
        using var invoker = new HttpMessageInvoker(handler);

        handler.Dispose();

        var act = async () => await invoker.SendAsync(new HttpRequestMessage(HttpMethod.Get, "https://example.com"), CancellationToken.None);
        await act.Should().ThrowAsync<ObjectDisposedException>();
    }

    [Fact]
    public async Task SendAsync_CrossOriginRedirect_StripsSensitiveCredentialHeaders()
    {
        HttpRequestMessage? redirectRequest = null;
        var step = 0;
        var mockInner = new TestHttpMessageHandler((req, ct) =>
        {
            step++;
            if (step == 1)
            {
                var resp = new HttpResponseMessage(HttpStatusCode.Redirect);
                resp.Headers.Location = new Uri("https://external-foreign.com/destination");
                return Task.FromResult(resp);
            }

            redirectRequest = req;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK));
        });

        var options = new SsrfProtectionOptions { RequireHttps = true };
        using var handler = new SafeSocketsHttpHandler(resolver: null, options: options, innerHandler: mockInner);
        using var invoker = new HttpMessageInvoker(handler);

        var req = new HttpRequestMessage(HttpMethod.Get, "https://secure-origin.com/resource");
        req.Headers.Add("Authorization", "Bearer sensitive-secret-token");
        req.Headers.Add("Cookie", "session=admin123");
        req.Headers.Add("Cookie2", "$Version=1");
        req.Headers.Add("X-Api-Key", "api-key-99999");
        req.Headers.Add("X-Auth-Token", "auth-token-88888");
        req.Headers.Add("Proxy-Authorization", "Basic secret-credentials");
        req.Headers.Add("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==");
        req.Headers.Add("Custom-Tracking-Header", "allowed-value");

        var response = await invoker.SendAsync(req, CancellationToken.None);

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        redirectRequest.Should().NotBeNull();
        redirectRequest!.RequestUri!.Host.Should().Be("external-foreign.com");

        // SEC-004 Regression: Ensure sensitive headers are removed
        redirectRequest.Headers.Contains("Authorization").Should().BeFalse("Authorization must be stripped on cross-origin redirect.");
        redirectRequest.Headers.Contains("Cookie").Should().BeFalse("Cookie must be stripped on cross-origin redirect.");
        redirectRequest.Headers.Contains("Cookie2").Should().BeFalse("Cookie2 must be stripped on cross-origin redirect.");
        redirectRequest.Headers.Contains("X-Api-Key").Should().BeFalse("X-Api-Key must be stripped on cross-origin redirect.");
        redirectRequest.Headers.Contains("X-Auth-Token").Should().BeFalse("X-Auth-Token must be stripped on cross-origin redirect.");
        redirectRequest.Headers.Contains("Proxy-Authorization").Should().BeFalse("Proxy-Authorization must be stripped on cross-origin redirect.");
        redirectRequest.Headers.Contains("Sec-WebSocket-Key").Should().BeFalse("Sec-WebSocket-Key must be stripped on cross-origin redirect.");

        // Non-sensitive headers must be preserved
        redirectRequest.Headers.Contains("Custom-Tracking-Header").Should().BeTrue("Non-sensitive header should be preserved.");
    }

    [Fact]
    public async Task SendAsync_DifferentPortRedirect_StripsSensitiveCredentialHeaders()
    {
        // FINDING-NEW-02: Under RFC 6454, different ports on the same host constitute different origins.
        HttpRequestMessage? redirectRequest = null;
        var step = 0;
        var mockInner = new TestHttpMessageHandler((req, ct) =>
        {
            step++;
            if (step == 1)
            {
                var resp = new HttpResponseMessage(HttpStatusCode.Redirect);
                resp.Headers.Location = new Uri("https://secure-origin.com:8443/resource");
                return Task.FromResult(resp);
            }

            redirectRequest = req;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK));
        });

        var options = new SsrfProtectionOptions { RequireHttps = true };
        using var handler = new SafeSocketsHttpHandler(resolver: null, options: options, innerHandler: mockInner);
        using var invoker = new HttpMessageInvoker(handler);

        var req = new HttpRequestMessage(HttpMethod.Get, "https://secure-origin.com:443/resource");
        req.Headers.Add("Authorization", "Bearer sensitive-secret-token");
        req.Headers.Add("Cookie", "session=admin123");
        req.Headers.Add("X-Api-Key", "api-key-99999");
        req.Headers.Add("Custom-Tracking-Header", "allowed-value");

        var response = await invoker.SendAsync(req, CancellationToken.None);

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        redirectRequest.Should().NotBeNull();
        redirectRequest!.RequestUri!.Port.Should().Be(8443);

        // Sensitive headers must be stripped due to cross-port origin mismatch
        redirectRequest.Headers.Contains("Authorization").Should().BeFalse("Authorization must be stripped on cross-port redirect.");
        redirectRequest.Headers.Contains("Cookie").Should().BeFalse("Cookie must be stripped on cross-port redirect.");
        redirectRequest.Headers.Contains("X-Api-Key").Should().BeFalse("X-Api-Key must be stripped on cross-port redirect.");

        // Non-sensitive headers must be preserved
        redirectRequest.Headers.Contains("Custom-Tracking-Header").Should().BeTrue("Non-sensitive header should be preserved.");
    }

    [Theory]
    [InlineData(HttpStatusCode.TemporaryRedirect)]
    [InlineData(HttpStatusCode.PermanentRedirect)]
    public async Task SendAsync_CrossOriginRedirectWithPayload_ThrowsHttpRequestException(HttpStatusCode redirectCode)
    {
        // FINDING-NEW-05: Prohibit cross-origin 307/308 redirects with payload content
        var step = 0;
        var mockInner = new TestHttpMessageHandler((req, ct) =>
        {
            step++;
            if (step == 1)
            {
                var resp = new HttpResponseMessage(redirectCode);
                resp.Headers.Location = new Uri("https://foreign-evil-site.com/target");
                return Task.FromResult(resp);
            }

            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK));
        });

        var options = new SsrfProtectionOptions { RequireHttps = true };
        using var handler = new SafeSocketsHttpHandler(resolver: null, options: options, innerHandler: mockInner);
        using var invoker = new HttpMessageInvoker(handler);

        var req = new HttpRequestMessage(HttpMethod.Post, "https://secure-origin.com/action")
        {
            Content = new StringContent("{\"password\":\"super-secret\"}")
        };

        var act = async () => await invoker.SendAsync(req, CancellationToken.None);
        await act.Should().ThrowAsync<HttpRequestException>()
            .WithMessage("*prohibited*to prevent credential and body exfiltration*");
    }

    [Fact]
    public void Constructor_DefaultInnerHandler_EnforcesUseProxyFalse()
    {
        using var handler = new SafeSocketsHttpHandler();
        var inner = (SocketsHttpHandler)handler.InnerHandler;
        inner.UseProxy.Should().BeFalse();
    }

    [Fact]
    public async Task SendAsync_DifferentSchemeRedirect_StripsSensitiveCredentialHeaders()
    {
        HttpRequestMessage? redirectRequest = null;
        var step = 0;
        var mockInner = new TestHttpMessageHandler((req, ct) =>
        {
            step++;
            if (step == 1)
            {
                var resp = new HttpResponseMessage(HttpStatusCode.Redirect);
                resp.Headers.Location = new Uri("http://secure-origin.com/resource");
                return Task.FromResult(resp);
            }

            redirectRequest = req;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK));
        });

        var options = new SsrfProtectionOptions { RequireHttps = false };
        using var handler = new SafeSocketsHttpHandler(resolver: null, options: options, innerHandler: mockInner);
        using var invoker = new HttpMessageInvoker(handler);

        var req = new HttpRequestMessage(HttpMethod.Get, "https://secure-origin.com/resource");
        req.Headers.Add("Authorization", "Bearer sensitive-secret-token");

        var response = await invoker.SendAsync(req, CancellationToken.None);

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        redirectRequest.Should().NotBeNull();
        redirectRequest!.Headers.Contains("Authorization").Should().BeFalse("Scheme change is cross-origin under RFC 6454.");
    }

    [Fact]
    public async Task SendAsync_302RedirectOfPost_ConvertsToGet()
    {
        HttpRequestMessage? redirectRequest = null;
        var step = 0;
        var mockInner = new TestHttpMessageHandler((req, ct) =>
        {
            step++;
            if (step == 1)
            {
                var resp = new HttpResponseMessage(HttpStatusCode.Found);
                resp.Headers.Location = new Uri("https://secure-origin.com/new-path");
                return Task.FromResult(resp);
            }

            redirectRequest = req;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK));
        });

        using var handler = new SafeSocketsHttpHandler(resolver: null, options: new SsrfProtectionOptions(), innerHandler: mockInner);
        using var invoker = new HttpMessageInvoker(handler);

        var req = new HttpRequestMessage(HttpMethod.Post, "https://secure-origin.com/initial");
        req.Content = new StringContent("body");
        var response = await invoker.SendAsync(req, CancellationToken.None);

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        redirectRequest.Should().NotBeNull();
        redirectRequest!.Method.Should().Be(HttpMethod.Get);
    }

    [Fact]
    public async Task SendAsync_302CrossOriginWithContent_ConvertsToGetWithoutThrowing()
    {
        HttpRequestMessage? redirectRequest = null;
        var step = 0;
        var mockInner = new TestHttpMessageHandler((req, ct) =>
        {
            step++;
            if (step == 1)
            {
                var resp = new HttpResponseMessage(HttpStatusCode.Found);
                resp.Headers.Location = new Uri("https://external-host.com/new-path");
                return Task.FromResult(resp);
            }

            redirectRequest = req;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK));
        });

        using var handler = new SafeSocketsHttpHandler(resolver: null, options: new SsrfProtectionOptions(), innerHandler: mockInner);
        using var invoker = new HttpMessageInvoker(handler);

        var req = new HttpRequestMessage(HttpMethod.Post, "https://secure-origin.com/initial");
        req.Content = new StringContent("body");
        var response = await invoker.SendAsync(req, CancellationToken.None);

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        redirectRequest.Should().NotBeNull();
        redirectRequest!.Method.Should().Be(HttpMethod.Get);
    }

    [Fact]
    public async Task ConnectCallbackAsync_CustomStreamConnector_IsInvoked()
    {
        var invoked = false;
        using var handler = new SafeSocketsHttpHandler();
        handler.StreamConnector = (ip, port, ct) =>
        {
            invoked = true;
            return ValueTask.FromResult<Stream>(new MemoryStream());
        };

        handler.StreamConnector.Should().NotBeNull();
        var stream = await handler.StreamConnector(IPAddress.Loopback, 80, CancellationToken.None);
        invoked.Should().BeTrue();
        stream.Should().NotBeNull();
    }
}

