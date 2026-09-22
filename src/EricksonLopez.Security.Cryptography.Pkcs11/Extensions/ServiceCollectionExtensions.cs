// Copyright © Erickson Lopez. MIT License.

namespace Microsoft.Extensions.DependencyInjection;

using System;
using EricksonLopez.Security.Abstractions.Cryptography;
using EricksonLopez.Security.Cryptography.Pkcs11.Hsm;
using EricksonLopez.Security.Cryptography.Pkcs11.Interop;
using EricksonLopez.Security.Cryptography.Pkcs11.Signing;

/// <summary>
/// Provides extension methods for registering PKCS#11 hardware security module (HSM) services in an <see cref="IServiceCollection"/>.
/// </summary>
public static class Pkcs11ServiceCollectionExtensions
{
    /// <summary>
    /// Registers PKCS#11 native library and session manager components into the service collection.
    /// </summary>
    /// <param name="services">The service collection to configure.</param>
    /// <param name="libraryPath">The absolute path to the native PKCS#11 shared library.</param>
    /// <param name="slotId">The cryptographic slot identifier to open a session on.</param>
    /// <returns>The configured <see cref="IServiceCollection"/> instance.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="services"/> is <see langword="null"/></exception>
    /// <exception cref="ArgumentException"><paramref name="libraryPath"/> is <see langword="null"/> or white-space</exception>
    /// <exception cref="InvalidOperationException">The PKCS#11 session initialization fails when resolved from the service provider</exception>
    public static IServiceCollection AddEricksonLopezPkcs11(this IServiceCollection services, string libraryPath, uint slotId)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentException.ThrowIfNullOrWhiteSpace(libraryPath);

        services.AddSingleton(sp => new Pkcs11NativeLibrary(libraryPath));

        services.AddSingleton(sp =>
        {
            var lib = sp.GetRequiredService<Pkcs11NativeLibrary>();
            var sessionResult = Pkcs11SessionManager.OpenSession(lib, slotId);

            if (sessionResult.IsFailure)
            {
                throw new InvalidOperationException($"Failed to initialize PKCS#11 session: {sessionResult.Error.Description}");
            }

            return sessionResult.Value;
        });

        services.AddSingleton<IDigitalSignatureEngine, Pkcs11DigitalSignatureEngine>();

        return services;
    }
}
