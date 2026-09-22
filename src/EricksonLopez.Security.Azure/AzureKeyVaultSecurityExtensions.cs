// Copyright © Erickson Lopez. MIT License.

namespace Microsoft.Extensions.DependencyInjection;

using System;
using EricksonLopez.Security.Abstractions.KeyManagement;
using EricksonLopez.Security.Abstractions.Secrets;
using EricksonLopez.Security.Azure;

/// <summary>
/// Provides extension methods for registering Azure Key Vault key and secret store adapters in an <see cref="IServiceCollection"/>.
/// </summary>
public static class AzureKeyVaultSecurityExtensions
{
    /// <summary>
    /// Registers Azure Key Vault key store and secret store adapters with default options.
    /// </summary>
    /// <param name="services">The service collection to register the adapters into.</param>
    /// <returns>The configured <see cref="IServiceCollection"/> instance.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="services"/> is <see langword="null"/></exception>
    public static IServiceCollection AddAzureKeyVaultSecurity(
        this IServiceCollection services)
    {
        return services.AddAzureKeyVaultSecurity(_ => { });
    }

    /// <summary>
    /// Registers Azure Key Vault key store and secret store adapters.
    /// </summary>
    /// <param name="services">The service collection to register the adapters into.</param>
    /// <param name="configure">The configuration delegate for Azure Key Vault options.</param>
    /// <returns>The configured <see cref="IServiceCollection"/> instance.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="services"/> or <paramref name="configure"/> is <see langword="null"/></exception>
    public static IServiceCollection AddAzureKeyVaultSecurity(
        this IServiceCollection services,
        Action<AzureKeyVaultOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configure);

        services.Configure(configure);
        services.AddSingleton<IKeyStore, AzureKeyVaultKeyStore>();
        services.AddSingleton<ISecretStore, AzureKeyVaultSecretStore>();

        return services;
    }
}
