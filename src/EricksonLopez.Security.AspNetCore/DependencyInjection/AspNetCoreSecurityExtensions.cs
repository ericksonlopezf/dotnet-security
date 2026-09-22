// Copyright © Erickson Lopez. MIT License.

namespace Microsoft.Extensions.DependencyInjection;

using System;
using EricksonLopez.Security.AspNetCore.Authentication;
using EricksonLopez.Security.AspNetCore.Context;
using EricksonLopez.Security.AspNetCore.Headers;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;

/// <summary>
/// Provides extension methods for registering and configuring ASP.NET Core security middleware,
/// headers, and request context services in an <see cref="IServiceCollection"/>.
/// </summary>
public static class AspNetCoreSecurityExtensions
{
    /// <summary>
    /// Registers ASP.NET Core security services including headers options, API key authentication options,
    /// and scoped <see cref="IRequestSecurityContext"/>.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="configureHeaders">Optional action to configure security headers.</param>
    /// <param name="configureApiKeyAuth">Optional action to configure API key authentication.</param>
    /// <returns>The service collection for chaining.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="services"/> is <see langword="null"/></exception>
    public static IServiceCollection AddSecurityAspNetCore(
        this IServiceCollection services,
        Action<SecurityHeadersOptions>? configureHeaders = null,
        Action<ApiKeyAuthenticationOptions>? configureApiKeyAuth = null)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddHttpContextAccessor();
        services.AddScoped<IRequestSecurityContext, RequestSecurityContext>();
        services.AddOptions();

        if (configureHeaders is not null)
        {
            services.Configure(configureHeaders);
        }

        if (configureApiKeyAuth is not null)
        {
            services.Configure(configureApiKeyAuth);
        }

        return services;
    }

    /// <summary>
    /// Adds <see cref="SecurityHeadersMiddleware"/> to the application request pipeline.
    /// </summary>
    /// <param name="app">The application builder.</param>
    /// <returns>The application builder for chaining.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="app"/> is <see langword="null"/></exception>
    public static IApplicationBuilder UseSecurityHeaders(this IApplicationBuilder app)
    {
        ArgumentNullException.ThrowIfNull(app);
        return app.UseMiddleware<SecurityHeadersMiddleware>();
    }

    /// <summary>
    /// Adds <see cref="ApiKeyAuthenticationMiddleware"/> to the application request pipeline.
    /// </summary>
    /// <param name="app">The application builder.</param>
    /// <returns>The application builder for chaining.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="app"/> is <see langword="null"/></exception>
    public static IApplicationBuilder UseApiKeyAuthentication(this IApplicationBuilder app)
    {
        ArgumentNullException.ThrowIfNull(app);
        return app.UseMiddleware<ApiKeyAuthenticationMiddleware>();
    }

    /// <summary>
    /// Configures API Key authentication using the native ASP.NET Core AuthenticationHandler.
    /// </summary>
    /// <param name="builder">The authentication builder.</param>
    /// <param name="configureOptions">An action to configure the <see cref="ApiKeyAuthenticationOptions"/>.</param>
    /// <returns>The original <see cref="AuthenticationBuilder"/> instance.</returns>
    public static AuthenticationBuilder AddApiKeySupport(
        this AuthenticationBuilder builder,
        Action<ApiKeyAuthenticationOptions>? configureOptions = null)
    {
        return builder.AddScheme<ApiKeyAuthenticationOptions, ApiKeyAuthenticationHandler>(
            "ApiKey",
            "API Key Authentication",
            configureOptions ?? (_ => { }));
    }

    /// <summary>
    /// Registers the <see cref="EricksonLopez.Security.AspNetCore.Identity.IdentityPasswordHasherBridge{TUser}"/>
    /// as ASP.NET Core Identity's <see cref="Microsoft.AspNetCore.Identity.IPasswordHasher{TUser}"/>.
    /// </summary>
    /// <typeparam name="TUser">The user entity type.</typeparam>
    /// <param name="services">The service collection.</param>
    /// <returns>The service collection for chaining.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="services"/> is <see langword="null"/></exception>
    public static IServiceCollection AddEricksonLopezIdentityPasswordHasher<TUser>(this IServiceCollection services)
        where TUser : class
    {
        ArgumentNullException.ThrowIfNull(services);
        services.AddSingleton<Microsoft.AspNetCore.Identity.IPasswordHasher<TUser>, EricksonLopez.Security.AspNetCore.Identity.IdentityPasswordHasherBridge<TUser>>();
        return services;
    }
}
