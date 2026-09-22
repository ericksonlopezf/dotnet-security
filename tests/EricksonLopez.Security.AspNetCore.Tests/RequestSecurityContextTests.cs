// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.AspNetCore.Tests;

using System;
using System.Collections.Generic;
using System.Security.Claims;
using AwesomeAssertions;
using EricksonLopez.Security.Abstractions.Primitives;
using EricksonLopez.Security.AspNetCore.Authentication;
using EricksonLopez.Security.AspNetCore.Context;
using Microsoft.AspNetCore.Http;
using NSubstitute;
using Xunit;

public sealed class RequestSecurityContextTests
{
    [Fact]
    public void Constructor_NullAccessor_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => new RequestSecurityContext(null!));
    }

    [Fact]
    public void RequestSecurityContext_NullHttpContext_ReturnsDefaults()
    {
        var accessor = new HttpContextAccessor { HttpContext = null };
        var securityContext = new RequestSecurityContext(accessor);

        securityContext.IsAuthenticated.Should().BeFalse();
        securityContext.ActorId.Should().BeNull();
        securityContext.ApiKey.Should().BeNull();
        securityContext.Principal.Should().BeNull();
        securityContext.HasScope("read").Should().BeFalse();
    }

    [Fact]
    public void RequestSecurityContext_UnauthenticatedUser_IsAuthenticatedIsFalse()
    {
        var context = new DefaultHttpContext();
        var accessor = new HttpContextAccessor { HttpContext = context };
        var securityContext = new RequestSecurityContext(accessor);

        securityContext.IsAuthenticated.Should().BeFalse();
        securityContext.ActorId.Should().BeNull();
    }

    [Fact]
    public void RequestSecurityContext_ResolvesAuthenticatedProperties()
    {
        var context = new DefaultHttpContext();
        var identity = new ClaimsIdentity(
            [
                new Claim(ClaimTypes.NameIdentifier, "usr-999"),
                new Claim("scope", "admin:access")
            ],
            "ApiKey");

        context.User = new ClaimsPrincipal(identity);

        var apiKey = new ApiKey(
            Id: new ApiKeyId("ek_live_123"),
            OwnerId: "usr-999",
            Name: "Admin Key",
            DisplayPrefix: "ek_live_***",
            HashedSecret: "hash",
            CreatedAtUtc: DateTimeOffset.UtcNow,
            Scopes: new HashSet<string> { "admin:access", "audit:log" });

        context.Items[ApiKeyAuthenticationMiddleware.HttpContextApiKeyItemKey] = apiKey;

        var accessor = new HttpContextAccessor { HttpContext = context };
        var securityContext = new RequestSecurityContext(accessor);

        securityContext.IsAuthenticated.Should().BeTrue();
        securityContext.ActorId.Should().Be("usr-999");
        securityContext.ApiKey.Should().NotBeNull();
        securityContext.Principal.Should().NotBeNull();
        securityContext.HasScope("admin:access").Should().BeTrue();
        securityContext.HasScope("audit:log").Should().BeTrue();
        securityContext.HasScope("superadmin").Should().BeFalse();
        securityContext.HasScope("").Should().BeFalse();
        securityContext.HasScope("   ").Should().BeFalse();
    }

    [Fact]
    public void RequestSecurityContext_HasScopeFromClaimsPrincipalWhenApiKeyIsNull()
    {
        var context = new DefaultHttpContext();
        var identity = new ClaimsIdentity(
            [
                new Claim(ClaimTypes.NameIdentifier, "usr-claims"),
                new Claim("scope", "claims:read")
            ],
            "Bearer");

        context.User = new ClaimsPrincipal(identity);
        var accessor = new HttpContextAccessor { HttpContext = context };
        var securityContext = new RequestSecurityContext(accessor);

        securityContext.IsAuthenticated.Should().BeTrue();
        securityContext.ApiKey.Should().BeNull();
        securityContext.HasScope("claims:read").Should().BeTrue();
        securityContext.HasScope("claims:write").Should().BeFalse();
    }

    [Fact]
    public void RequestSecurityContext_NullUser_ReturnsDefaults()
    {
        var mockContext = Substitute.For<HttpContext>();
        mockContext.User.Returns((ClaimsPrincipal)null!);
        var mockAccessor = Substitute.For<IHttpContextAccessor>();
        mockAccessor.HttpContext.Returns(mockContext);

        var securityContext = new RequestSecurityContext(mockAccessor);

        securityContext.IsAuthenticated.Should().BeFalse();
        securityContext.ActorId.Should().BeNull();
        securityContext.Principal.Should().BeNull();
        securityContext.HasScope("test").Should().BeFalse();
    }

    [Fact]
    public void RequestSecurityContext_EmptyClaimsPrincipal_ReturnsDefaults()
    {
        var context = new DefaultHttpContext { User = new ClaimsPrincipal() };
        var accessor = new HttpContextAccessor { HttpContext = context };
        var securityContext = new RequestSecurityContext(accessor);

        securityContext.IsAuthenticated.Should().BeFalse();
        securityContext.ActorId.Should().BeNull();
        securityContext.Principal.Should().NotBeNull();
        securityContext.HasScope("test").Should().BeFalse();
    }
}
