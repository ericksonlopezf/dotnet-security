// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.AspNetCore.Tests;

using System;
using System.Threading.Tasks;
using AwesomeAssertions;
using EricksonLopez.Security.AspNetCore.Headers;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using Xunit;

[Trait("Category", "Integration")]
public sealed class SecurityHeadersMiddlewareTests
{
    [Fact]
    public void Constructor_NullNext_ThrowsArgumentNullException()
    {
        var options = Options.Create(new SecurityHeadersOptions());
        Assert.Throws<ArgumentNullException>(() => new SecurityHeadersMiddleware(null!, options));
    }

    [Fact]
    public void Constructor_NullOptions_UsesDefaultOptions()
    {
        var middleware = new SecurityHeadersMiddleware(_ => Task.CompletedTask, null!);
        middleware.Should().NotBeNull();
    }

    [Fact]
    public async Task InvokeAsync_NullContext_ThrowsArgumentNullException()
    {
        var options = Options.Create(new SecurityHeadersOptions());
        var middleware = new SecurityHeadersMiddleware(_ => Task.CompletedTask, options);

        await Assert.ThrowsAsync<ArgumentNullException>(() => middleware.InvokeAsync(null!));
    }

    [Fact]
    public async Task SecurityHeadersMiddleware_InjectsExpectedHeaders_OnHttps()
    {
        var options = Options.Create(new SecurityHeadersOptions());
        var context = new DefaultHttpContext();
        context.Request.Scheme = "https";

        var middleware = new SecurityHeadersMiddleware(ctx =>
        {
            ctx.Response.StatusCode = 200;
            return Task.CompletedTask;
        }, options);

        await middleware.InvokeAsync(context);

        context.Response.Headers.ContainsKey("Content-Security-Policy").Should().BeTrue();
        context.Response.Headers.ContainsKey("Strict-Transport-Security").Should().BeTrue();
        context.Response.Headers.ContainsKey("X-Content-Type-Options").Should().BeTrue();
        context.Response.Headers.ContainsKey("X-Frame-Options").Should().BeTrue();
        context.Response.Headers.ContainsKey("Referrer-Policy").Should().BeTrue();
        context.Response.Headers.ContainsKey("Permissions-Policy").Should().BeTrue();
        context.Response.Headers.ContainsKey("X-Permitted-Cross-Domain-Policies").Should().BeTrue();
        context.Response.Headers["X-Permitted-Cross-Domain-Policies"].ToString().Should().Be("none");
    }

    [Fact]
    public async Task SecurityHeadersMiddleware_NonHttps_DoesNotInjectHsts()
    {
        var options = Options.Create(new SecurityHeadersOptions());
        var context = new DefaultHttpContext();
        context.Request.Scheme = "http";

        var middleware = new SecurityHeadersMiddleware(ctx =>
        {
            ctx.Response.StatusCode = 200;
            return Task.CompletedTask;
        }, options);

        await middleware.InvokeAsync(context);

        context.Response.Headers.ContainsKey("Content-Security-Policy").Should().BeTrue();
        context.Response.Headers.ContainsKey("Strict-Transport-Security").Should().BeFalse();
    }

    [Fact]
    public async Task SecurityHeadersMiddleware_ExistingHeaders_AreNotOverwritten()
    {
        var options = Options.Create(new SecurityHeadersOptions());
        var context = new DefaultHttpContext();
        context.Request.Scheme = "https";
        context.Response.Headers["X-Frame-Options"] = "SAMEORIGIN";

        var middleware = new SecurityHeadersMiddleware(ctx => Task.CompletedTask, options);
        await middleware.InvokeAsync(context);

        context.Response.Headers["X-Frame-Options"].ToString().Should().Be("SAMEORIGIN");
    }

    [Fact]
    public async Task SecurityHeadersMiddleware_AllExistingHeaders_ArePreservedWithoutOverwriting()
    {
        var options = Options.Create(new SecurityHeadersOptions());
        var context = new DefaultHttpContext();
        context.Request.Scheme = "https";
        context.Response.Headers["Content-Security-Policy"] = "custom-csp";
        context.Response.Headers["Strict-Transport-Security"] = "custom-hsts";
        context.Response.Headers["X-Content-Type-Options"] = "custom-nosniff";
        context.Response.Headers["X-Frame-Options"] = "SAMEORIGIN";
        context.Response.Headers["Referrer-Policy"] = "custom-referrer";
        context.Response.Headers["Permissions-Policy"] = "custom-permissions";
        context.Response.Headers["X-Permitted-Cross-Domain-Policies"] = "custom-cross-domain";

        var middleware = new SecurityHeadersMiddleware(ctx => Task.CompletedTask, options);
        await middleware.InvokeAsync(context);

        context.Response.Headers["Content-Security-Policy"].ToString().Should().Be("custom-csp");
        context.Response.Headers["Strict-Transport-Security"].ToString().Should().Be("custom-hsts");
        context.Response.Headers["X-Content-Type-Options"].ToString().Should().Be("custom-nosniff");
        context.Response.Headers["X-Frame-Options"].ToString().Should().Be("SAMEORIGIN");
        context.Response.Headers["Referrer-Policy"].ToString().Should().Be("custom-referrer");
        context.Response.Headers["Permissions-Policy"].ToString().Should().Be("custom-permissions");
        context.Response.Headers["X-Permitted-Cross-Domain-Policies"].ToString().Should().Be("custom-cross-domain");
    }

    [Fact]
    public void SecurityHeadersOptions_DefaultAndCustomValues()
    {
        var options = new SecurityHeadersOptions();
        options.ContentSecurityPolicy.Should().Contain("default-src 'self'");
        options.StrictTransportSecurity.Should().Contain("max-age=31536000");
        options.XContentTypeOptions.Should().Be("nosniff");
        options.XFrameOptions.Should().Be("DENY");
        options.ReferrerPolicy.Should().Be("strict-origin-when-cross-origin");
        options.PermissionsPolicy.Should().Contain("camera=()");
        options.XPermittedCrossDomainPolicies.Should().Be("none");

        options.ContentSecurityPolicy = "default-src 'none'";
        options.StrictTransportSecurity = "max-age=60";
        options.XContentTypeOptions = "";
        options.XFrameOptions = "SAMEORIGIN";
        options.ReferrerPolicy = "no-referrer";
        options.PermissionsPolicy = "";
        options.XPermittedCrossDomainPolicies = "master-only";

        options.ContentSecurityPolicy.Should().Be("default-src 'none'");
        options.StrictTransportSecurity.Should().Be("max-age=60");
        options.XContentTypeOptions.Should().Be("");
        options.XFrameOptions.Should().Be("SAMEORIGIN");
        options.ReferrerPolicy.Should().Be("no-referrer");
        options.PermissionsPolicy.Should().Be("");
        options.XPermittedCrossDomainPolicies.Should().Be("master-only");
    }

    [Fact]
    public async Task SecurityHeadersMiddleware_EmptyOptionStrings_DoesNotInjectHeaders()
    {
        var options = Options.Create(new SecurityHeadersOptions
        {
            ContentSecurityPolicy = "",
            StrictTransportSecurity = "",
            XContentTypeOptions = "",
            XFrameOptions = "",
            ReferrerPolicy = "",
            PermissionsPolicy = "",
            XPermittedCrossDomainPolicies = ""
        });

        var context = new DefaultHttpContext();
        context.Request.Scheme = "https";

        var middleware = new SecurityHeadersMiddleware(ctx => Task.CompletedTask, options);
        await middleware.InvokeAsync(context);

        context.Response.Headers.Should().BeEmpty();
    }

    [Fact]
    public async Task SecurityHeadersMiddleware_AppliesHeadersBeforeDownstreamMiddlewareExecutes()
    {
        var options = Options.Create(new SecurityHeadersOptions());
        var context = new DefaultHttpContext();
        bool headersPresentDownstream = false;

        var middleware = new SecurityHeadersMiddleware(ctx =>
        {
            headersPresentDownstream = ctx.Response.Headers.ContainsKey("X-Content-Type-Options");
            return Task.CompletedTask;
        }, options);

        await middleware.InvokeAsync(context);

        headersPresentDownstream.Should().BeTrue("headers must be applied before downstream middleware executes");
    }

    [Fact]
    public async Task SecurityHeadersMiddleware_DownstreamClearsHeaders_OnStartingRestoresHeaders()
    {
        var options = Options.Create(new SecurityHeadersOptions());
        var context = new DefaultHttpContext();
        var feature = new CustomResponseFeature();
        context.Features.Set<Microsoft.AspNetCore.Http.Features.IHttpResponseFeature>(feature);
        context.Request.Scheme = "https";

        var middleware = new SecurityHeadersMiddleware(async ctx =>
        {
            // Simulate downstream clearing headers
            ctx.Response.Headers.Clear();
            // Start response using the feature, triggering OnStarting and marking HasStarted = true
            await feature.StartResponseAsync();
        }, options);

        await middleware.InvokeAsync(context);

        // HasStarted is true, so finally block did not run; headers were restored solely by OnStarting callback!
        feature.HasStarted.Should().BeTrue();
        context.Response.Headers.ContainsKey("Content-Security-Policy").Should().BeTrue();
        context.Response.Headers.ContainsKey("Strict-Transport-Security").Should().BeTrue();
        context.Response.Headers.ContainsKey("X-Content-Type-Options").Should().BeTrue();
        context.Response.Headers.ContainsKey("X-Frame-Options").Should().BeTrue();
        context.Response.Headers.ContainsKey("Referrer-Policy").Should().BeTrue();
        context.Response.Headers.ContainsKey("Permissions-Policy").Should().BeTrue();
        context.Response.Headers.ContainsKey("X-Permitted-Cross-Domain-Policies").Should().BeTrue();
    }

    private sealed class CustomResponseFeature : Microsoft.AspNetCore.Http.Features.IHttpResponseFeature
    {
        public int StatusCode { get; set; } = 200;
        public string? ReasonPhrase { get; set; }
        public IHeaderDictionary Headers { get; set; } = new HeaderDictionary();
        public System.IO.Stream Body { get; set; } = new System.IO.MemoryStream();
        public bool HasStarted { get; set; }

        private readonly System.Collections.Generic.List<(Func<object, Task> Callback, object State)> _callbacks = new();

        public void OnStarting(Func<object, Task> callback, object state) => _callbacks.Add((callback, state));
        public void OnCompleted(Func<object, Task> callback, object state) { }

        public async Task StartResponseAsync()
        {
            HasStarted = true;
            foreach (var (callback, state) in _callbacks)
            {
                await callback(state);
            }
        }
    }
}
