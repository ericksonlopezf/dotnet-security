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
        var ex = Assert.Throws<ArgumentNullException>(() => services.AddSecurityAspNetCore());
        ex.ParamName.Should().Be("services");
        ex.StackTrace.Should().NotContain("HttpContextAccessor");
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

    [Fact]
    public void AddEricksonLopezIdentityPasswordHasher_NullServices_ThrowsArgumentNullException()
    {
        IServiceCollection services = null!;
        var ex = Assert.Throws<ArgumentNullException>(() => services.AddEricksonLopezIdentityPasswordHasher<object>());
        ex.ParamName.Should().Be("services");
        ex.StackTrace.Should().NotContain("ServiceCollectionServiceExtensions");
    }

    [Fact]
    public void AddEricksonLopezIdentityPasswordHasher_RegistersPasswordHasher()
    {
        var services = new ServiceCollection();
        services.AddSingleton<EricksonLopez.Security.Abstractions.Passwords.IPasswordHasher, StubPasswordHasher>();
        services.AddEricksonLopezIdentityPasswordHasher<object>();
        using var provider = services.BuildServiceProvider();
        var hasher = provider.GetService<Microsoft.AspNetCore.Identity.IPasswordHasher<object>>();
        hasher.Should().NotBeNull();
    }

    private sealed class StubPasswordHasher : EricksonLopez.Security.Abstractions.Passwords.IPasswordHasher
    {
        public EricksonLopez.Security.Abstractions.Passwords.PasswordHashAlgorithm Algorithm => EricksonLopez.Security.Abstractions.Passwords.PasswordHashAlgorithm.Argon2id;
        public string HashPassword(ReadOnlySpan<char> password) => "dummy";
        public EricksonLopez.Security.Abstractions.Passwords.PasswordVerificationResult VerifyPassword(ReadOnlySpan<char> password, string hashedPassword) => EricksonLopez.Security.Abstractions.Passwords.PasswordVerificationResult.Success;
        public bool NeedsRehash(string hashedPassword) => false;
    }
}
