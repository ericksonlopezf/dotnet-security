// Copyright © Erickson Lopez. MIT License.

using System;
using EricksonLopez.Security.WebAuthn.Fido2.Abstractions;
using EricksonLopez.Security.WebAuthn.Fido2.Models;
using EricksonLopez.Security.WebAuthn.Fido2.Parsers;
using EricksonLopez.Security.WebAuthn.Fido2.Services;
using EricksonLopez.Security.WebAuthn.Fido2.Verifiers;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace EricksonLopez.Security.WebAuthn.Fido2.DependencyInjection;

/// <summary>
/// Provides extension methods for configuring WebAuthn / FIDO2 Relying Party services in dependency injection.
/// </summary>
public static class WebAuthnServiceCollectionExtensions
{
    /// <summary>
    /// Registers WebAuthn Level 2/3 and FIDO2 Relying Party services.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="configureOptions">An action to configure <see cref="WebAuthnOptions"/>.</param>
    /// <returns>The <see cref="IServiceCollection"/> instance for chaining.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="services"/> is <see langword="null"/></exception>
    public static IServiceCollection AddWebAuthnFido2(
        this IServiceCollection services,
        Action<WebAuthnOptions>? configureOptions = null)
    {
        ArgumentNullException.ThrowIfNull(services);

        if (configureOptions is not null)
        {
            services.Configure(configureOptions);
        }
        else
        {
            services.Configure<WebAuthnOptions>(_ => { });
        }

        services.TryAddSingleton<ICoseKeyParser, CoseKeyParser>();
        services.TryAddSingleton<IAuthenticatorDataParser, AuthenticatorDataParser>();

        services.TryAddEnumerable(ServiceDescriptor.Singleton<IAttestationVerifier, NoneAttestationVerifier>());
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IAttestationVerifier, PackedAttestationVerifier>());
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IAttestationVerifier, AndroidSafetyNetAttestationVerifier>());
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IAttestationVerifier, TpmAttestationVerifier>());
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IAttestationVerifier, FidoU2FAttestationVerifier>());

        services.TryAddScoped<IWebAuthnCeremonyService, WebAuthnCeremonyService>();

        return services;
    }
}
