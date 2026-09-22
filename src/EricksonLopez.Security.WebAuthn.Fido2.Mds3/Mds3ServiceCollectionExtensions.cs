// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.WebAuthn.Fido2.Mds3;

using System;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

/// <summary>
/// Provides extension methods to register FIDO Alliance MDS3 metadata services into the DI container.
/// </summary>
public static class Mds3ServiceCollectionExtensions
{
    /// <summary>
    /// Adds the FIDO Alliance MDS3 metadata service to the dependency injection container.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="configureOptions">The optional configuration delegate for <see cref="Mds3Options"/>.</param>
    /// <returns>The same service collection for chaining.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="services"/> is <see langword="null"/></exception>
    /// <example>
    /// <code>
    /// builder.Services
    ///     .AddWebAuthnFido2(opts => opts.RelyingPartyId = "example.com")
    ///     .AddFidoMds3(opts =>
    ///     {
    ///         opts.AllowUnknownAuthenticators = false;  // strict: only MDS3-listed authenticators
    ///         opts.CacheDuration = TimeSpan.FromHours(12);
    ///     });
    /// </code>
    /// </example>
    public static IServiceCollection AddFidoMds3(
        this IServiceCollection services,
        Action<Mds3Options>? configureOptions = null)
    {
        ArgumentNullException.ThrowIfNull(services);

        if (configureOptions is not null)
        {
            services.Configure(configureOptions);
        }

        // Register typed HttpClient for MDS3 fetching
        services.AddHttpClient<HttpMds3MetadataService>(static client =>
        {
            client.Timeout = TimeSpan.FromSeconds(30);
            client.DefaultRequestHeaders.Add("Accept", "application/jwt");
        });

        // Register the interface → implementation binding
        services.TryAddSingleton<IMds3MetadataService, HttpMds3MetadataService>();

        return services;
    }
}
