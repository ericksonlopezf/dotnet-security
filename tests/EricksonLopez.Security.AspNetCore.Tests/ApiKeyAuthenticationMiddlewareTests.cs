// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.AspNetCore.Tests;

using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using AwesomeAssertions;
using EricksonLopez.Result;
using EricksonLopez.Security.Abstractions.Errors;
using EricksonLopez.Security.Abstractions.Primitives;
using EricksonLopez.Security.Abstractions.Tokens;
using EricksonLopez.Security.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using Xunit;

public sealed class ApiKeyAuthenticationMiddlewareTests
{
    private sealed class FakeApiKeyValidator : IApiKeyValidator
    {
        public bool ShouldSucceed { get; set; } = true;

        public ValueTask<Result<ApiKey>> ValidateApiKeyAsync(string plaintextApiKey, CancellationToken cancellationToken = default)
        {
            if (ShouldSucceed && plaintextApiKey == "valid_key_123")
            {
                var apiKey = new ApiKey(
                    Id: new ApiKeyId("ek_live_9f8a"),
                    OwnerId: "user-123",
                    Name: "Test Service",
                    DisplayPrefix: "ek_live_***",
                    HashedSecret: "hashed-val",
                    CreatedAtUtc: DateTimeOffset.UtcNow,
                    Scopes: new HashSet<string> { "read:data", "write:data" });

                return ValueTask.FromResult<Result<ApiKey>>(apiKey);
            }

            return ValueTask.FromResult<Result<ApiKey>>(SecurityError.InvalidToken("Invalid key."));
        }
    }

    [Fact]
    public void Constructor_NullNext_ThrowsArgumentNullException()
    {
        var options = Options.Create(new ApiKeyAuthenticationOptions());
        Assert.Throws<ArgumentNullException>(() => new ApiKeyAuthenticationMiddleware(null!, options));
    }

    [Fact]
    public void Constructor_NullOptions_UsesDefaultOptions()
    {
        var middleware = new ApiKeyAuthenticationMiddleware(_ => Task.CompletedTask, null!);
        middleware.Should().NotBeNull();
    }

    [Fact]
    public async Task InvokeAsync_NullContextOrValidator_ThrowsArgumentNullException()
    {
        var options = Options.Create(new ApiKeyAuthenticationOptions());
        var middleware = new ApiKeyAuthenticationMiddleware(_ => Task.CompletedTask, options);
        var validator = new FakeApiKeyValidator();
        var context = new DefaultHttpContext();

        await Assert.ThrowsAsync<ArgumentNullException>(() => middleware.InvokeAsync(null!, validator));
        await Assert.ThrowsAsync<ArgumentNullException>(() => middleware.InvokeAsync(context, null!));
    }

    [Fact]
    public async Task InvokeAsync_ValidHeaderKey_SetsClaimsPrincipalAndHttpContextItem()
    {
        var options = Options.Create(new ApiKeyAuthenticationOptions());
        var validator = new FakeApiKeyValidator { ShouldSucceed = true };

        var context = new DefaultHttpContext();
        context.Request.Headers["X-Api-Key"] = "valid_key_123";

        bool nextCalled = false;
        var middleware = new ApiKeyAuthenticationMiddleware(_ =>
        {
            nextCalled = true;
            return Task.CompletedTask;
        }, options);

        await middleware.InvokeAsync(context, validator);

        nextCalled.Should().BeTrue();
        context.User.Identity?.IsAuthenticated.Should().BeTrue();
        context.User.Identity?.AuthenticationType.Should().Be("ApiKey");
        context.User.Claims.Should().HaveCount(5);
        context.User.FindFirst(ClaimTypes.NameIdentifier).Should().NotBeNull();
        context.User.FindFirst(ClaimTypes.Name).Should().NotBeNull();
        context.User.FindFirst("api_key_id").Should().NotBeNull();
        context.User.FindFirst(ClaimTypes.NameIdentifier)!.Value.Should().Be("user-123");
        context.User.FindFirst(ClaimTypes.Name)!.Value.Should().Be("Test Service");
        context.User.FindFirst("api_key_id")!.Value.Should().Be("ek_live_9f8a");
        context.User.FindAll("scope").Should().HaveCount(2);
        context.Items[ApiKeyAuthenticationMiddleware.HttpContextApiKeyItemKey].Should().NotBeNull();
    }

    [Fact]
    public async Task InvokeAsync_AuthorizationHeaderApiKey_Authenticates()
    {
        var options = Options.Create(new ApiKeyAuthenticationOptions { HeaderName = "" });
        var validator = new FakeApiKeyValidator { ShouldSucceed = true };

        var context = new DefaultHttpContext();
        context.Request.Headers["Authorization"] = "ApiKey valid_key_123";

        bool nextCalled = false;
        var middleware = new ApiKeyAuthenticationMiddleware(_ =>
        {
            nextCalled = true;
            return Task.CompletedTask;
        }, options);

        await middleware.InvokeAsync(context, validator);

        nextCalled.Should().BeTrue();
        context.User.Identity?.IsAuthenticated.Should().BeTrue();
        context.User.Claims.Should().HaveCount(5);
        context.User.FindFirst(ClaimTypes.NameIdentifier).Should().NotBeNull();
    }

    [Fact]
    public async Task InvokeAsync_EmptyHeaderKeyWithValidAuthorizationHeader_FallsBackToAuthorizationHeader()
    {
        var options = Options.Create(new ApiKeyAuthenticationOptions());
        var validator = new FakeApiKeyValidator { ShouldSucceed = true };

        var context = new DefaultHttpContext();
        context.Request.Headers["X-Api-Key"] = "";
        context.Request.Headers["Authorization"] = "ApiKey valid_key_123";

        bool nextCalled = false;
        var middleware = new ApiKeyAuthenticationMiddleware(_ =>
        {
            nextCalled = true;
            return Task.CompletedTask;
        }, options);

        await middleware.InvokeAsync(context, validator);

        nextCalled.Should().BeTrue();
        context.User.Identity?.IsAuthenticated.Should().BeTrue();
    }

    [Fact]
    public async Task InvokeAsync_NonApiKeyAuthorizationHeader_DoesNotAuthenticate()
    {
        var options = Options.Create(new ApiKeyAuthenticationOptions { HeaderName = "", RequireApiKey = true });
        var validator = new FakeApiKeyValidator { ShouldSucceed = true };

        var context = new DefaultHttpContext();
        context.Request.Headers["Authorization"] = "Bearer valid_key_123";

        bool nextCalled = false;
        var middleware = new ApiKeyAuthenticationMiddleware(_ =>
        {
            nextCalled = true;
            return Task.CompletedTask;
        }, options);

        await middleware.InvokeAsync(context, validator);

        nextCalled.Should().BeFalse();
        context.Response.StatusCode.Should().Be(StatusCodes.Status401Unauthorized);
    }

    [Fact]
    public async Task InvokeAsync_NoKey_RequireApiKeyFalse_PassesToNext()
    {
        var options = Options.Create(new ApiKeyAuthenticationOptions { RequireApiKey = false });
        var validator = new FakeApiKeyValidator();

        var context = new DefaultHttpContext();
        bool nextCalled = false;
        var middleware = new ApiKeyAuthenticationMiddleware(_ =>
        {
            nextCalled = true;
            return Task.CompletedTask;
        }, options);

        await middleware.InvokeAsync(context, validator);

        nextCalled.Should().BeTrue();
        context.Response.StatusCode.Should().Be(StatusCodes.Status200OK);
    }

    [Fact]
    public async Task InvokeAsync_NoKey_RequireApiKeyTrue_Returns401()
    {
        var options = Options.Create(new ApiKeyAuthenticationOptions { RequireApiKey = true });
        var validator = new FakeApiKeyValidator();

        var context = new DefaultHttpContext();
        context.Response.Body = new MemoryStream();
        bool nextCalled = false;
        var middleware = new ApiKeyAuthenticationMiddleware(_ =>
        {
            nextCalled = true;
            return Task.CompletedTask;
        }, options);

        await middleware.InvokeAsync(context, validator);

        nextCalled.Should().BeFalse();
        context.Response.StatusCode.Should().Be(StatusCodes.Status401Unauthorized);
    }

    [Fact]
    public async Task InvokeAsync_InvalidKey_Returns401Unauthorized()
    {
        var options = Options.Create(new ApiKeyAuthenticationOptions());
        var validator = new FakeApiKeyValidator { ShouldSucceed = false };

        var context = new DefaultHttpContext();
        context.Response.Body = new MemoryStream();
        context.Request.Headers["X-Api-Key"] = "invalid_key_999";

        bool nextCalled = false;
        var middleware = new ApiKeyAuthenticationMiddleware(_ =>
        {
            nextCalled = true;
            return Task.CompletedTask;
        }, options);

        await middleware.InvokeAsync(context, validator);

        nextCalled.Should().BeFalse();
        context.Response.StatusCode.Should().Be(StatusCodes.Status401Unauthorized);
    }

    [Fact]
    public void ApiKeyAuthenticationOptions_DefaultAndCustomValues()
    {
        var options = new ApiKeyAuthenticationOptions();
        options.HeaderName.Should().Be("X-Api-Key");
        options.RequireApiKey.Should().BeTrue();
        options.AuthenticationScheme.Should().Be("ApiKey");

        options.HeaderName = "X-Custom-Key";
        options.RequireApiKey = false;
        options.AuthenticationScheme = "CustomApiKey";

        options.HeaderName.Should().Be("X-Custom-Key");
        options.RequireApiKey.Should().BeFalse();

        options.AuthenticationScheme.Should().Be("CustomApiKey");
    }

    [Fact]
    public async Task InvokeAsync_DuplicateApiKeyHeaders_RejectsWith401Unauthorized()
    {
        var options = Options.Create(new ApiKeyAuthenticationOptions());
        var validator = new FakeApiKeyValidator { ShouldSucceed = false };

        var context = new DefaultHttpContext();
        context.Response.Body = new MemoryStream();
        context.Request.Headers["X-Api-Key"] = new Microsoft.Extensions.Primitives.StringValues(["valid_key_123", "duplicate_attack_key"]);

        bool nextCalled = false;
        var middleware = new ApiKeyAuthenticationMiddleware(_ =>
        {
            nextCalled = true;
            return Task.CompletedTask;
        }, options);

        await middleware.InvokeAsync(context, validator);

        nextCalled.Should().BeFalse();
        context.Response.StatusCode.Should().Be(StatusCodes.Status401Unauthorized);
    }

    /// <summary>EC-003: 401 on missing key must include WWW-Authenticate header per RFC 7235 §4.1.</summary>
    [Fact]
    public async Task InvokeAsync_NoKey_RequireApiKeyTrue_Returns401WithWwwAuthenticateHeader()
    {
        var options = Options.Create(new ApiKeyAuthenticationOptions { RequireApiKey = true });
        var validator = new FakeApiKeyValidator();

        var context = new DefaultHttpContext();
        context.Response.Body = new MemoryStream();
        var middleware = new ApiKeyAuthenticationMiddleware(_ => Task.CompletedTask, options);

        await middleware.InvokeAsync(context, validator);

        context.Response.StatusCode.Should().Be(StatusCodes.Status401Unauthorized);
        // EC-003: WWW-Authenticate header must be present so clients can discover the auth scheme.
        context.Response.Headers.ContainsKey("WWW-Authenticate").Should().BeTrue();
        var wwwAuth = context.Response.Headers["WWW-Authenticate"].ToString();
        wwwAuth.Should().Contain("ApiKey");
        wwwAuth.Should().Contain("X-Api-Key"); // default header name
    }

    /// <summary>EC-003: 401 on invalid key must include WWW-Authenticate header per RFC 7235 §4.1.</summary>
    [Fact]
    public async Task InvokeAsync_InvalidKey_Returns401WithWwwAuthenticateHeader()
    {
        var options = Options.Create(new ApiKeyAuthenticationOptions());
        var validator = new FakeApiKeyValidator { ShouldSucceed = false };

        var context = new DefaultHttpContext();
        context.Response.Body = new MemoryStream();
        context.Request.Headers["X-Api-Key"] = "totally_wrong_key";
        var middleware = new ApiKeyAuthenticationMiddleware(_ => Task.CompletedTask, options);

        await middleware.InvokeAsync(context, validator);

        context.Response.StatusCode.Should().Be(StatusCodes.Status401Unauthorized);
        // EC-003: WWW-Authenticate header must be present on all 401 responses.
        context.Response.Headers.ContainsKey("WWW-Authenticate").Should().BeTrue();
        context.Response.Headers["WWW-Authenticate"].ToString().Should().Contain("ApiKey");
    }

    /// <summary>EC-003: Custom HeaderName must be reflected in WWW-Authenticate header.</summary>
    [Fact]
    public async Task InvokeAsync_CustomHeaderName_WwwAuthenticateReflectsCustomHeader()
    {
        var options = Options.Create(new ApiKeyAuthenticationOptions
        {
            HeaderName = "X-Custom-Auth-Key",
            RequireApiKey = true
        });
        var validator = new FakeApiKeyValidator();

        var context = new DefaultHttpContext();
        context.Response.Body = new MemoryStream();
        var middleware = new ApiKeyAuthenticationMiddleware(_ => Task.CompletedTask, options);

        await middleware.InvokeAsync(context, validator);

        context.Response.StatusCode.Should().Be(StatusCodes.Status401Unauthorized);
        var wwwAuth = context.Response.Headers["WWW-Authenticate"].ToString();
        wwwAuth.Should().Contain("X-Custom-Auth-Key");
    }
}
