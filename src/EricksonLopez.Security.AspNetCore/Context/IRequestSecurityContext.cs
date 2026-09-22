// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.AspNetCore.Context;

using System.Security.Claims;
using EricksonLopez.Security.Abstractions.Primitives;

/// <summary>
/// Defines a scoped security context providing strongly-typed access to authenticated identity metadata,
/// API keys, and authorization claims for the current HTTP request.
/// </summary>
public interface IRequestSecurityContext
{
    /// <summary>
    /// Gets a value indicating whether the current request is authenticated.
    /// </summary>
    bool IsAuthenticated { get; }

    /// <summary>
    /// Gets the authenticated actor / user identifier, or <see langword="null"/> if unauthenticated.
    /// </summary>
    string? ActorId { get; }

    /// <summary>
    /// Gets the authenticated <see cref="ApiKey"/> if the request was authenticated via API key.
    /// </summary>
    ApiKey? ApiKey { get; }

    /// <summary>
    /// Gets the <see cref="ClaimsPrincipal"/> associated with the current HTTP context.
    /// </summary>
    ClaimsPrincipal? Principal { get; }

    /// <summary>
    /// Determines whether the authenticated principal or API key possesses the specified scope.
    /// </summary>
    /// <param name="scope">The scope to check.</param>
    /// <returns><see langword="true"/> if granted; otherwise, <see langword="false"/>.</returns>
    bool HasScope(string scope);
}
