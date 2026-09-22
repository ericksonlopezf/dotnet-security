// Copyright © Erickson Lopez. MIT License.

namespace Microsoft.Extensions.DependencyInjection;

using System;
using EricksonLopez.Security.Abstractions.KeyManagement;
using EricksonLopez.Security.Abstractions.Secrets;
using EricksonLopez.Security.HashiCorpVault;

/// <summary>
/// Provides extension methods for registering HashiCorp Vault key and secret store adapters in an <see cref="IServiceCollection"/>.
/// </summary>
public static class HashiCorpVaultSecurityExtensions
{
    /// <summary>
    /// Registers HashiCorp Vault Transit key store and KV v2 secret store adapters with default options.
    /// </summary>
    /// <param name="services">The service collection to register the adapters into.</param>
    /// <returns>The configured <see cref="IServiceCollection"/> instance.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="services"/> is <see langword="null"/></exception>
    public static IServiceCollection AddHashiCorpVaultSecurity(
        this IServiceCollection services)
    {
        return services.AddHashiCorpVaultSecurity(_ => { });
    }

    /// <summary>
    /// Registers HashiCorp Vault Transit key store and KV v2 secret store adapters.
    /// </summary>
    /// <param name="services">The service collection to register the adapters into.</param>
    /// <param name="configure">The configuration delegate for HashiCorp Vault options.</param>
    /// <returns>The configured <see cref="IServiceCollection"/> instance.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="services"/> or <paramref name="configure"/> is <see langword="null"/></exception>
    public static IServiceCollection AddHashiCorpVaultSecurity(
        this IServiceCollection services,
        Action<HashiCorpVaultOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configure);

        services.Configure(configure);
        services.AddSingleton<IKeyStore, HashiCorpVaultKeyStore>();
        services.AddSingleton<ISecretStore, HashiCorpVaultSecretStore>();

        return services;
    }
}
