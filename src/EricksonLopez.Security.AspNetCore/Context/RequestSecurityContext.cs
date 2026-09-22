// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.AspNetCore.Context;

using System;
using System.Security.Claims;
using EricksonLopez.Security.Abstractions.Primitives;
using EricksonLopez.Security.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;

/// <summary>
/// Provides a scoped implementation of <see cref="IRequestSecurityContext"/> that resolves security properties from the active <see cref="IHttpContextAccessor"/>.
/// </summary>
public sealed class RequestSecurityContext : IRequestSecurityContext
{
    private readonly IHttpContextAccessor _httpContextAccessor;

    /// <summary>
    /// Initializes a new instance of the <see cref="RequestSecurityContext"/> class with the specified HTTP context accessor.
    /// </summary>
    /// <param name="httpContextAccessor">The accessor for retrieving the ambient HTTP context.</param>
    /// <exception cref="ArgumentNullException"><paramref name="httpContextAccessor"/> is <see langword="null"/></exception>
    public RequestSecurityContext(IHttpContextAccessor httpContextAccessor)
    {
        _httpContextAccessor = httpContextAccessor ?? throw new ArgumentNullException(nameof(httpContextAccessor));
    }

    private HttpContext? HttpContext => _httpContextAccessor.HttpContext;

    /// <summary>
    /// Gets a value indicating whether the current request is authenticated.
    /// </summary>
    public bool IsAuthenticated => HttpContext?.User?.Identity?.IsAuthenticated == true;

    /// <summary>
    /// Gets the unique identifier of the authenticated actor (user or subject) for the current request, if present.
    /// </summary>
    public string? ActorId => HttpContext?.User?.FindFirst(ClaimTypes.NameIdentifier)?.Value;

    /// <summary>
    /// Gets the authenticated API key associated with the current HTTP request, if authenticated via API key.
    /// </summary>
    public ApiKey? ApiKey => HttpContext?.Items[ApiKeyAuthenticationHandler.HttpContextApiKeyItemKey] as ApiKey;

    /// <summary>
    /// Gets the claims principal associated with the current HTTP request context.
    /// </summary>
    public ClaimsPrincipal? Principal => HttpContext?.User;

    /// <inheritdoc />
    public bool HasScope(string scope)
    {
        if (string.IsNullOrWhiteSpace(scope))
        {
            return false;
        }

        if (ApiKey is not null && ApiKey.HasScope(scope))
        {
            return true;
        }

        return HttpContext?.User?.HasClaim("scope", scope) == true;
    }
}
