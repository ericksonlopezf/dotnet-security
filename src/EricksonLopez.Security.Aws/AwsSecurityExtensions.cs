// Copyright © Erickson Lopez. MIT License.

namespace Microsoft.Extensions.DependencyInjection;

using System;
using EricksonLopez.Security.Abstractions.KeyManagement;
using EricksonLopez.Security.Abstractions.Secrets;
using EricksonLopez.Security.Aws;

/// <summary>
/// Provides extension methods for registering AWS KMS key store and AWS Secrets Manager secret store adapters in an <see cref="IServiceCollection"/>.
/// </summary>
public static class AwsSecurityExtensions
{
    /// <summary>
    /// Registers AWS KMS key store and AWS Secrets Manager secret store adapters with default options.
    /// </summary>
    /// <param name="services">The service collection to register the adapters into.</param>
    /// <returns>The configured <see cref="IServiceCollection"/> instance.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="services"/> is <see langword="null"/></exception>
    public static IServiceCollection AddAwsSecurity(
        this IServiceCollection services)
    {
        return services.AddAwsSecurity(_ => { });
    }

    /// <summary>
    /// Registers AWS KMS key store and AWS Secrets Manager secret store adapters.
    /// </summary>
    /// <param name="services">The service collection to register the adapters into.</param>
    /// <param name="configure">The configuration delegate for AWS security options.</param>
    /// <returns>The configured <see cref="IServiceCollection"/> instance.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="services"/> or <paramref name="configure"/> is <see langword="null"/></exception>
    public static IServiceCollection AddAwsSecurity(
        this IServiceCollection services,
        Action<AwsSecurityOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configure);

        services.Configure(configure);
        services.AddSingleton<IKeyStore, AwsKmsKeyStore>();
        services.AddSingleton<ISecretStore, AwsSecretsManagerSecretStore>();

        return services;
    }
}
