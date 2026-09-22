// Copyright © Erickson Lopez. MIT License.
using System;
using Microsoft.Extensions.DependencyInjection;

namespace EricksonLopez.Security.Pki;

/// <summary>
/// Provides extension methods for registering Public Key Infrastructure (PKI) certificate validation services into the service collection.
/// </summary>
public static class SecurityPkiServiceCollectionExtensions
{
    /// <summary>
    /// Registers the <see cref="ICertificateChainValidator"/> implementation into the service collection.
    /// </summary>
    /// <param name="services">The service collection to configure.</param>
    /// <returns>The same service collection instance for method chaining.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="services"/> is <see langword="null"/></exception>
    public static IServiceCollection AddSecurityPki(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddSingleton<ICertificateChainValidator, CertificateChainValidator>();
        return services;
    }
}
