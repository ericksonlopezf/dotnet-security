// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.AspNetCore.Tests;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Threading;
using System.Threading.Tasks;
using AwesomeAssertions;
using EricksonLopez.Result;
using EricksonLopez.Security.Abstractions.Errors;
using EricksonLopez.Security.Abstractions.Primitives;
using EricksonLopez.Security.Abstractions.Tokens;
using EricksonLopez.Security.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Xunit;

public sealed class ApiKeyAuthenticationHandlerTests
{
    private sealed class FakeApiKeyValidator : IApiKeyValidator
    {
        public bool ShouldSucceed { get; set; } = true;
        public IReadOnlySet<string>? ScopesToReturn { get; set; } = new HashSet<string> { "read:reports", "write:reports" };

        public ValueTask<Result<ApiKey>> ValidateApiKeyAsync(string plaintextApiKey, CancellationToken cancellationToken = default)
        {
            if (ShouldSucceed && plaintextApiKey == "secret_key_123")
            {
                var apiKey = new ApiKey(
                    Id: new ApiKeyId("key_id_456"),
                    OwnerId: "tenant-999",
                    Name: "Analytics Client",
                    DisplayPrefix: "secret_***",
                    HashedSecret: "hashed_val",
                    CreatedAtUtc: DateTimeOffset.UtcNow,
                    Scopes: ScopesToReturn);

                return ValueTask.FromResult<Result<ApiKey>>(apiKey);
            }

            return ValueTask.FromResult<Result<ApiKey>>(SecurityError.InvalidToken("Validation failed."));
        }
    }

    private sealed class TestOptionsMonitor<T> : IOptionsMonitor<T>
    {
        public TestOptionsMonitor(T currentValue) => CurrentValue = currentValue;
        public T CurrentValue { get; set; }
        public T Get(string? name) => CurrentValue;
        public IDisposable OnChange(Action<T, string?> listener) => null!;
    }

    [Fact]
    public void Constructor_NullValidator_ThrowsArgumentNullException()
    {
        var optionsMonitor = new TestOptionsMonitor<ApiKeyAuthenticationOptions>(new ApiKeyAuthenticationOptions());
        Assert.Throws<ArgumentNullException>("validator", () =>
            new ApiKeyAuthenticationHandler(optionsMonitor, NullLoggerFactory.Instance, UrlEncoder.Default, null!));
    }

    [Fact]
    public async Task HandleAuthenticateAsync_ValidKeyInConfiguredHeader_SucceedsWithClaimsAndContextItem()
    {
        var options = new ApiKeyAuthenticationOptions { HeaderName = "X-Api-Key" };
        var monitor = new TestOptionsMonitor<ApiKeyAuthenticationOptions>(options);
        var validator = new FakeApiKeyValidator { ShouldSucceed = true };
        var handler = new ApiKeyAuthenticationHandler(monitor, NullLoggerFactory.Instance, UrlEncoder.Default, validator);

        var context = new DefaultHttpContext();
        context.Request.Headers["X-Api-Key"] = "secret_key_123";

        var scheme = new AuthenticationScheme("ApiKey", "ApiKey", typeof(ApiKeyAuthenticationHandler));
        await handler.InitializeAsync(scheme, context);

        var result = await handler.AuthenticateAsync();

        result.Succeeded.Should().BeTrue();
        result.Principal.Should().NotBeNull();
        result.Ticket.Should().NotBeNull();
        result.Ticket!.AuthenticationScheme.Should().Be("ApiKey");

        var claims = result.Principal!.Claims.ToList();
        claims.Should().Contain(c => c.Type == ClaimTypes.NameIdentifier && c.Value == "tenant-999");
        claims.Should().Contain(c => c.Type == ClaimTypes.Name && c.Value == "Analytics Client");
        claims.Should().Contain(c => c.Type == "api_key_id" && c.Value == "key_id_456");
        claims.Should().Contain(c => c.Type == "scope" && c.Value == "read:reports");
        claims.Should().Contain(c => c.Type == "scope" && c.Value == "write:reports");

        context.Items[ApiKeyAuthenticationHandler.HttpContextApiKeyItemKey].Should().NotBeNull();
        var itemApiKey = context.Items[ApiKeyAuthenticationHandler.HttpContextApiKeyItemKey] as ApiKey;
        itemApiKey!.OwnerId.Should().Be("tenant-999");
    }

    [Fact]
    public async Task HandleAuthenticateAsync_ValidKeyInAuthorizationHeader_Succeeds()
    {
        var options = new ApiKeyAuthenticationOptions { HeaderName = "X-Unused-Header" };
        var monitor = new TestOptionsMonitor<ApiKeyAuthenticationOptions>(options);
        var validator = new FakeApiKeyValidator { ShouldSucceed = true };
        var handler = new ApiKeyAuthenticationHandler(monitor, NullLoggerFactory.Instance, UrlEncoder.Default, validator);

        var context = new DefaultHttpContext();
        context.Request.Headers["Authorization"] = "ApiKey secret_key_123";

        var scheme = new AuthenticationScheme("ApiKey", "ApiKey", typeof(ApiKeyAuthenticationHandler));
        await handler.InitializeAsync(scheme, context);

        var result = await handler.AuthenticateAsync();

        result.Succeeded.Should().BeTrue();
        result.Principal!.Identity!.Name.Should().Be("Analytics Client");
    }

    [Fact]
    public async Task HandleAuthenticateAsync_AuthorizationHeaderCaseInsensitiveAndTrimmed()
    {
        var options = new ApiKeyAuthenticationOptions { HeaderName = "" };
        var monitor = new TestOptionsMonitor<ApiKeyAuthenticationOptions>(options);
        var validator = new FakeApiKeyValidator { ShouldSucceed = true };
        var handler = new ApiKeyAuthenticationHandler(monitor, NullLoggerFactory.Instance, UrlEncoder.Default, validator);

        var context = new DefaultHttpContext();
        context.Request.Headers["Authorization"] = "apikey   secret_key_123   ";

        var scheme = new AuthenticationScheme("ApiKey", "ApiKey", typeof(ApiKeyAuthenticationHandler));
        await handler.InitializeAsync(scheme, context);

        var result = await handler.AuthenticateAsync();

        result.Succeeded.Should().BeTrue();
    }

    [Fact]
    public async Task HandleAuthenticateAsync_BearerAuthHeader_ReturnsNoResult()
    {
        var options = new ApiKeyAuthenticationOptions { HeaderName = "X-Api-Key" };
        var monitor = new TestOptionsMonitor<ApiKeyAuthenticationOptions>(options);
        var validator = new FakeApiKeyValidator();
        var handler = new ApiKeyAuthenticationHandler(monitor, NullLoggerFactory.Instance, UrlEncoder.Default, validator);

        var context = new DefaultHttpContext();
        context.Request.Headers["Authorization"] = "Bearer some_jwt_token";

        var scheme = new AuthenticationScheme("ApiKey", "ApiKey", typeof(ApiKeyAuthenticationHandler));
        await handler.InitializeAsync(scheme, context);

        var result = await handler.AuthenticateAsync();

        result.None.Should().BeTrue();
    }

    [Fact]
    public async Task HandleAuthenticateAsync_MissingKey_ReturnsNoResult()
    {
        var options = new ApiKeyAuthenticationOptions { HeaderName = "X-Api-Key" };
        var monitor = new TestOptionsMonitor<ApiKeyAuthenticationOptions>(options);
        var validator = new FakeApiKeyValidator();
        var handler = new ApiKeyAuthenticationHandler(monitor, NullLoggerFactory.Instance, UrlEncoder.Default, validator);

        var context = new DefaultHttpContext();
        var scheme = new AuthenticationScheme("ApiKey", "ApiKey", typeof(ApiKeyAuthenticationHandler));
        await handler.InitializeAsync(scheme, context);

        var result = await handler.AuthenticateAsync();

        result.None.Should().BeTrue();
    }

    [Fact]
    public async Task HandleAuthenticateAsync_EmptyOrWhitespaceKey_ReturnsNoResult()
    {
        var options = new ApiKeyAuthenticationOptions { HeaderName = "X-Api-Key" };
        var monitor = new TestOptionsMonitor<ApiKeyAuthenticationOptions>(options);
        var validator = new FakeApiKeyValidator();
        var handler = new ApiKeyAuthenticationHandler(monitor, NullLoggerFactory.Instance, UrlEncoder.Default, validator);

        var context = new DefaultHttpContext();
        context.Request.Headers["X-Api-Key"] = "   ";

        var scheme = new AuthenticationScheme("ApiKey", "ApiKey", typeof(ApiKeyAuthenticationHandler));
        await handler.InitializeAsync(scheme, context);

        var result = await handler.AuthenticateAsync();

        result.None.Should().BeTrue();
    }

    [Fact]
    public async Task HandleAuthenticateAsync_InvalidKey_ReturnsFailure()
    {
        var options = new ApiKeyAuthenticationOptions { HeaderName = "X-Api-Key" };
        var monitor = new TestOptionsMonitor<ApiKeyAuthenticationOptions>(options);
        var validator = new FakeApiKeyValidator { ShouldSucceed = false };
        var handler = new ApiKeyAuthenticationHandler(monitor, NullLoggerFactory.Instance, UrlEncoder.Default, validator);

        var context = new DefaultHttpContext();
        context.Request.Headers["X-Api-Key"] = "invalid_secret";

        var scheme = new AuthenticationScheme("ApiKey", "ApiKey", typeof(ApiKeyAuthenticationHandler));
        await handler.InitializeAsync(scheme, context);

        var result = await handler.AuthenticateAsync();

        result.Failure.Should().NotBeNull();
        result.Failure!.Message.Should().Be("Invalid API Key");
    }

    [Fact]
    public async Task HandleAuthenticateAsync_NullScopes_SucceedsWithoutScopeClaims()
    {
        var options = new ApiKeyAuthenticationOptions { HeaderName = "X-Api-Key" };
        var monitor = new TestOptionsMonitor<ApiKeyAuthenticationOptions>(options);
        var validator = new FakeApiKeyValidator { ShouldSucceed = true, ScopesToReturn = null };
        var handler = new ApiKeyAuthenticationHandler(monitor, NullLoggerFactory.Instance, UrlEncoder.Default, validator);

        var context = new DefaultHttpContext();
        context.Request.Headers["X-Api-Key"] = "secret_key_123";

        var scheme = new AuthenticationScheme("ApiKey", "ApiKey", typeof(ApiKeyAuthenticationHandler));
        await handler.InitializeAsync(scheme, context);

        var result = await handler.AuthenticateAsync();

        result.Succeeded.Should().BeTrue();
        result.Principal!.Claims.Should().NotContain(c => c.Type == "scope");
    }

    [Fact]
    public async Task HandleChallengeAsync_SetsWwwAuthenticateHeaderWithHeaderName()
    {
        var options = new ApiKeyAuthenticationOptions { HeaderName = "X-Custom-Key" };
        var monitor = new TestOptionsMonitor<ApiKeyAuthenticationOptions>(options);
        var validator = new FakeApiKeyValidator();
        var handler = new ApiKeyAuthenticationHandler(monitor, NullLoggerFactory.Instance, UrlEncoder.Default, validator);

        var context = new DefaultHttpContext();
        var scheme = new AuthenticationScheme("ApiKey", "ApiKey", typeof(ApiKeyAuthenticationHandler));
        await handler.InitializeAsync(scheme, context);

        await handler.ChallengeAsync(new AuthenticationProperties());

        context.Response.Headers["WWW-Authenticate"].ToString().Should().Be("ApiKey realm=\"API\", header=\"X-Custom-Key\"");
    }
}
