// Copyright © Erickson Lopez. MIT License.

namespace Microsoft.Extensions.DependencyInjection;

using EricksonLopez.Security.Abstractions.Cryptography;
using EricksonLopez.Security.Abstractions.Passwords;
using EricksonLopez.Security.Abstractions.Randomness;
using EricksonLopez.Security.Cryptography.Encryption;
using EricksonLopez.Security.Cryptography.Passwords;
using EricksonLopez.Security.Cryptography.Randomness;

/// <summary>
/// Provides extension methods for registering cryptographic services in an <see cref="IServiceCollection"/>.
/// </summary>
public static class CryptographyServiceCollectionExtensions
{
    /// <summary>
    /// Registers the core cryptography primitives (RNG, ConstantTimeComparer, AEAD AES-GCM, and PBKDF2 PasswordHasher) as singletons.
    /// </summary>
    /// <param name="services">The service collection to register cryptographic services into.</param>
    /// <returns>The configured <see cref="IServiceCollection"/> instance.</returns>
    public static IServiceCollection AddEricksonLopezCryptographyCore(this IServiceCollection services)
    {
        services.AddSingleton<ICryptographicRandomNumberGenerator, CryptographicRandomNumberGenerator>();
        services.AddSingleton<IConstantTimeComparer, ConstantTimeComparer>();
        services.AddSingleton<IAuthenticatedEncryptionEngine, AesGcmAuthenticatedEncryptionEngine>();
        services.AddSingleton<IPasswordHasher, Pbkdf2PasswordHasher>();

        return services;
    }
}
