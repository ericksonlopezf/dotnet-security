// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Saml2.DependencyInjection;

using System;
using EricksonLopez.Security.Saml2.Abstractions;
using EricksonLopez.Security.Saml2.Claims;
using EricksonLopez.Security.Saml2.Cryptography;
using EricksonLopez.Security.Saml2.Models;
using EricksonLopez.Security.Saml2.Services;
using EricksonLopez.Security.Saml2.Xsw;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

/// <summary>
/// Provides extension methods for registering SAML 2.0 Service Provider components in dependency injection.
/// </summary>
public static class Saml2ServiceCollectionExtensions
{
    /// <summary>
    /// Registers SAML 2.0 Service Provider services with XSW defense and XMLDSig verification.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="configureOptions">An action to configure <see cref="Saml2Options"/>.</param>
    /// <returns>The <see cref="IServiceCollection"/> instance for chaining.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="services"/> is <see langword="null"/></exception>
    public static IServiceCollection AddSaml2Security(
        this IServiceCollection services,
        Action<Saml2Options>? configureOptions = null)
    {
        ArgumentNullException.ThrowIfNull(services);

        if (configureOptions is not null)
        {
            services.Configure(configureOptions);
        }
        else
        {
            services.Configure<Saml2Options>(_ => { });
        }

        services.TryAddSingleton<ISaml2XswValidator, Saml2XswValidator>();
        services.TryAddSingleton<ISaml2SignatureValidator, Saml2SignatureValidator>();
        services.TryAddSingleton<ISaml2AssertionDecryptor, Saml2AssertionDecryptor>();
        services.TryAddSingleton<ISaml2ClaimsMapper, Saml2ClaimsMapper>();
        services.TryAddScoped<ISaml2Service, Saml2Service>();

        return services;
    }
}
