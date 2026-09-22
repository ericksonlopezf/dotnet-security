// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Privacy.Hibp.DependencyInjection;

using System;
using System.Net.Http;
using EricksonLopez.Security.Privacy.Hibp.Abstractions;
using EricksonLopez.Security.Privacy.Hibp.Clients;
using EricksonLopez.Security.Privacy.Hibp.Models;
using EricksonLopez.Security.Privacy.Hibp.Validators;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

/// <summary>
/// Provides extension methods for registering Have I Been Pwned privacy services in an <see cref="IServiceCollection"/>.
/// </summary>
public static class HibpServiceCollectionExtensions
{
    /// <summary>
    /// Registers the Have I Been Pwned k-Anonymity client and password validator.
    /// </summary>
    /// <param name="services">The service collection to register services into.</param>
    /// <param name="configureOptions">An optional configuration delegate for HIBP options.</param>
    /// <returns>The configured <see cref="IServiceCollection"/> instance.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="services"/> is <see langword="null"/></exception>
    public static IServiceCollection AddHaveIBeenPwned(
        this IServiceCollection services,
        Action<HibpOptions>? configureOptions = null)
    {
        ArgumentNullException.ThrowIfNull(services);

        if (configureOptions is not null)
        {
            services.Configure(configureOptions);
        }
        else
        {
            services.Configure<HibpOptions>(_ => { });
        }

        services.AddHttpClient<IHaveIBeenPwnedClient, HaveIBeenPwnedClient>((sp, client) =>
        {
            var options = sp.GetRequiredService<IOptions<HibpOptions>>().Value;
            client.BaseAddress = new Uri(options.BaseUrl);
            client.Timeout = options.Timeout;
            client.DefaultRequestHeaders.UserAgent.ParseAdd(options.UserAgent);
        });

        services.TryAddScoped<IPasswordPwnedValidator, PasswordPwnedValidator>();

        return services;
    }
}
