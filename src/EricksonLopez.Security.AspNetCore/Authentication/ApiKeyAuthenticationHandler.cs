// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.AspNetCore.Authentication;

using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using EricksonLopez.Security.Abstractions.Tokens;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

/// <summary>
/// Provides a native ASP.NET Core AuthenticationHandler for API Keys.
/// </summary>
public sealed class ApiKeyAuthenticationHandler : AuthenticationHandler<ApiKeyAuthenticationOptions>
{
    private readonly IApiKeyValidator _validator;

    /// <summary>
    /// Specifies the <see cref="Microsoft.AspNetCore.Http.HttpContext.Items"/> key that stores the authenticated API key entity.
    /// </summary>
    public const string HttpContextApiKeyItemKey = "EricksonLopez.Security.ApiKey";

    /// <summary>
    /// Initializes a new instance of the <see cref="ApiKeyAuthenticationHandler"/> class.
    /// </summary>
    /// <param name="options">The monitor for the options instance.</param>
    /// <param name="logger">The factory used to create loggers.</param>
    /// <param name="encoder">The URL encoder.</param>
    /// <param name="validator">The API key validator service.</param>
    /// <exception cref="ArgumentNullException"><paramref name="validator"/> is <see langword="null"/></exception>
    public ApiKeyAuthenticationHandler(
        IOptionsMonitor<ApiKeyAuthenticationOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder,
        IApiKeyValidator validator)
        : base(options, logger, encoder)
    {
        _validator = validator ?? throw new ArgumentNullException(nameof(validator));
    }

    /// <inheritdoc />
    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        string? presentedKey = null;

        if (!string.IsNullOrEmpty(Options.HeaderName) && Request.Headers.TryGetValue(Options.HeaderName, out var headerValues))
        {
            presentedKey = headerValues.ToString();
        }

        if (string.IsNullOrEmpty(presentedKey) && Request.Headers.TryGetValue("Authorization", out var authHeaderValues))
        {
            var authHeader = authHeaderValues.ToString();
            if (authHeader.StartsWith("ApiKey ", StringComparison.OrdinalIgnoreCase))
            {
                presentedKey = authHeader[7..].Trim();
            }
        }

        if (string.IsNullOrWhiteSpace(presentedKey))
        {
            return AuthenticateResult.NoResult();
        }

        var validationResult = await _validator.ValidateApiKeyAsync(presentedKey, Context.RequestAborted).ConfigureAwait(false);
        if (validationResult.IsFailure)
        {
            return AuthenticateResult.Fail("Invalid API Key");
        }

        var apiKey = validationResult.Value;
        Context.Items[HttpContextApiKeyItemKey] = apiKey;

        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, apiKey.OwnerId),
            new(ClaimTypes.Name, apiKey.Name),
            new("api_key_id", apiKey.Id.Value)
        };

        if (apiKey.Scopes is not null)
        {
            foreach (var scope in apiKey.Scopes)
            {
                claims.Add(new Claim("scope", scope));
            }
        }

        var identity = new ClaimsIdentity(claims, Scheme.Name);
        var principal = new ClaimsPrincipal(identity);
        var ticket = new AuthenticationTicket(principal, Scheme.Name);

        return AuthenticateResult.Success(ticket);
    }

    /// <inheritdoc />
    protected override Task HandleChallengeAsync(AuthenticationProperties properties)
    {
        Response.Headers["WWW-Authenticate"] = $"ApiKey realm=\"API\", header=\"{Options.HeaderName}\"";
        return base.HandleChallengeAsync(properties);
    }
}
