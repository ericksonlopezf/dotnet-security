// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.AspNetCore.Tests;

using System;
using System.Linq;
using AwesomeAssertions;
using EricksonLopez.Security.AspNetCore.Authentication;
using EricksonLopez.Security.AspNetCore.Context;
using EricksonLopez.Security.AspNetCore.Headers;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Xunit;

public sealed class AspNetCoreSecurityExtensionsTests
{
    [Fact]
    public void AddSecurityAspNetCore_NullServices_ThrowsArgumentNullException()
    {
        IServiceCollection services = null!;
        Assert.Throws<ArgumentNullException>(() => services.AddSecurityAspNetCore());
    }

    [Fact]
    public void AddSecurityAspNetCore_WithoutOptions_RegistersDefaults()
    {
        var services = new ServiceCollection();
        services.AddSecurityAspNetCore();

        var provider = services.BuildServiceProvider();
        var headersOptions = provider.GetRequiredService<IOptions<SecurityHeadersOptions>>().Value;
        var apiKeyOptions = provider.GetRequiredService<IOptions<ApiKeyAuthenticationOptions>>().Value;
        var httpContextAccessor = provider.GetService<IHttpContextAccessor>();
        var requestSecurityContext = provider.GetService<IRequestSecurityContext>();

        headersOptions.Should().NotBeNull();
        apiKeyOptions.Should().NotBeNull();
        httpContextAccessor.Should().NotBeNull();
        requestSecurityContext.Should().NotBeNull();
    }

    [Fact]
    public void AddSecurityAspNetCore_WithOptionsConfigured_AppliesCustomOptions()
    {
        var services = new ServiceCollection();
        services.AddSecurityAspNetCore(
            headers => headers.XFrameOptions = "SAMEORIGIN",
            apiKey => apiKey.HeaderName = "X-Custom-Key");

        var provider = services.BuildServiceProvider();
        var headersOptions = provider.GetRequiredService<IOptions<SecurityHeadersOptions>>().Value;
        var apiKeyOptions = provider.GetRequiredService<IOptions<ApiKeyAuthenticationOptions>>().Value;

        headersOptions.XFrameOptions.Should().Be("SAMEORIGIN");
        apiKeyOptions.HeaderName.Should().Be("X-Custom-Key");
    }

    [Fact]
    public void UseSecurityHeaders_NullApp_ThrowsArgumentNullException()
    {
        IApplicationBuilder app = null!;
        Assert.Throws<ArgumentNullException>(() => app.UseSecurityHeaders());
    }

    [Fact]
    public void UseApiKeyAuthentication_NullApp_ThrowsArgumentNullException()
    {
        IApplicationBuilder app = null!;
        Assert.Throws<ArgumentNullException>(() => app.UseApiKeyAuthentication());
    }

    [Fact]
    public void UseSecurityHeadersAndUseApiKeyAuthentication_AddsMiddleware()
    {
        var services = new ServiceCollection();
        services.AddSecurityAspNetCore();
        var app = new ApplicationBuilder(services.BuildServiceProvider());

        app.UseSecurityHeaders();
        app.UseApiKeyAuthentication();

        var pipeline = app.Build();
        pipeline.Should().NotBeNull();
    }
}
