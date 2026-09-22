// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.AspNetCore.Authentication;

using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;
using EricksonLopez.Security.Abstractions.Primitives;
using EricksonLopez.Security.Abstractions.Tokens;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;

/// <summary>
/// Provides middleware that intercepts HTTP requests, extracts API keys from headers or query parameters,
/// validates them against the registered <see cref="IApiKeyValidator"/>, and assigns
/// a validated <see cref="ClaimsPrincipal"/> to <see cref="HttpContext.User"/>.
/// </summary>
public sealed class ApiKeyAuthenticationMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ApiKeyAuthenticationOptions _options;

    /// <summary>
    /// Specifies the key for storing the authenticated <see cref="ApiKey"/> instance in <see cref="HttpContext.Items"/>.
    /// </summary>
    public const string HttpContextApiKeyItemKey = "EricksonLopez.Security.ApiKey";

    /// <summary>
    /// Initializes a new instance of the <see cref="ApiKeyAuthenticationMiddleware"/> class.
    /// </summary>
    /// <param name="next">The next middleware delegate in the HTTP request pipeline.</param>
    /// <param name="options">The configured API key authentication options accessor.</param>
    /// <exception cref="ArgumentNullException"><paramref name="next"/> is <see langword="null"/></exception>
    public ApiKeyAuthenticationMiddleware(RequestDelegate next, IOptions<ApiKeyAuthenticationOptions> options)
    {
        _next = next ?? throw new ArgumentNullException(nameof(next));
        _options = options?.Value ?? new ApiKeyAuthenticationOptions();
    }

    /// <summary>
    /// Processes an HTTP request to authenticate the caller via API key.
    /// </summary>
    /// <param name="context">The current HTTP context for the request.</param>
    /// <param name="validator">The API key validation service.</param>
    /// <returns>A task representing the asynchronous operation.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="context"/> or <paramref name="validator"/> is <see langword="null"/></exception>
    public async Task InvokeAsync(HttpContext context, IApiKeyValidator validator)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(validator);

        string? presentedKey = null;

        // 1. Try Header
        if (!string.IsNullOrEmpty(_options.HeaderName) && context.Request.Headers.TryGetValue(_options.HeaderName, out var headerValues))
        {
            presentedKey = headerValues.ToString();
        }

        // 2. Try Authorization: Bearer / ApiKey header fallback
        if (string.IsNullOrEmpty(presentedKey) && context.Request.Headers.TryGetValue("Authorization", out var authHeaderValues))
        {
            var authHeader = authHeaderValues.ToString();
            if (authHeader.StartsWith("ApiKey ", StringComparison.OrdinalIgnoreCase))
            {
                presentedKey = authHeader[7..].Trim();
            }
        }

        if (string.IsNullOrWhiteSpace(presentedKey))
        {
            if (_options.RequireApiKey)
            {
                // EC-003 fix: include WWW-Authenticate header per RFC 7235 §4.1.
                // Clients use this header to discover supported authentication scheme and realm.
                context.Response.Headers["WWW-Authenticate"] = $"ApiKey realm=\"API\", header=\"{_options.HeaderName}\"";
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                await context.Response.WriteAsync("API key is required.").ConfigureAwait(false);
                return;
            }

            await _next(context).ConfigureAwait(false);
            return;
        }

        var validationResult = await validator.ValidateApiKeyAsync(presentedKey, context.RequestAborted).ConfigureAwait(false);
        if (validationResult.IsFailure)
        {
            // EC-003 fix: include WWW-Authenticate header per RFC 7235 to indicate the supported scheme.
            context.Response.Headers["WWW-Authenticate"] = $"ApiKey realm=\"API\", header=\"{_options.HeaderName}\"";
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            await context.Response.WriteAsync("Invalid API Key").ConfigureAwait(false);
            return;
        }

        var apiKey = validationResult.Value;
        context.Items[HttpContextApiKeyItemKey] = apiKey;

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
                claims.Add(new("scope", scope));
            }
        }

        var identity = new ClaimsIdentity(claims, _options.AuthenticationScheme);
        context.User = new ClaimsPrincipal(identity);

        await _next(context).ConfigureAwait(false);
    }
}
