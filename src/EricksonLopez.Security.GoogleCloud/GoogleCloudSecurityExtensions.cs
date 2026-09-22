// Copyright © Erickson Lopez. MIT License.

namespace Microsoft.Extensions.DependencyInjection;

using System;
using EricksonLopez.Security.Abstractions.KeyManagement;
using EricksonLopez.Security.Abstractions.Secrets;
using EricksonLopez.Security.GoogleCloud;

/// <summary>
/// Provides extension methods for registering Google Cloud KMS and Secret Manager key and secret store adapters in an <see cref="IServiceCollection"/>.
/// </summary>
public static class GoogleCloudSecurityExtensions
{
    /// <summary>
    /// Registers Google Cloud KMS and Secret Manager adapters with default options.
    /// </summary>
    /// <param name="services">The service collection to register the adapters into.</param>
    /// <returns>The configured <see cref="IServiceCollection"/> instance.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="services"/> is <see langword="null"/></exception>
    public static IServiceCollection AddGoogleCloudSecurity(
        this IServiceCollection services)
    {
        return services.AddGoogleCloudSecurity(_ => { });
    }

    /// <summary>
    /// Registers Google Cloud KMS and Secret Manager adapters.
    /// </summary>
    /// <param name="services">The service collection to register the adapters into.</param>
    /// <param name="configure">The configuration delegate for Google Cloud security options.</param>
    /// <returns>The configured <see cref="IServiceCollection"/> instance.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="services"/> or <paramref name="configure"/> is <see langword="null"/></exception>
    public static IServiceCollection AddGoogleCloudSecurity(
        this IServiceCollection services,
        Action<GoogleCloudSecurityOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configure);

        services.Configure(configure);
        services.AddSingleton<IKeyStore, GoogleCloudKmsKeyStore>();
        services.AddSingleton<ISecretStore, GoogleCloudSecretManagerStore>();

        return services;
    }
}
