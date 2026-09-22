// Copyright © Erickson Lopez. MIT License.

namespace Microsoft.Extensions.DependencyInjection;

using System;
using EricksonLopez.Security.Abstractions.Cryptography;
using EricksonLopez.Security.Abstractions.KeyManagement;
using EricksonLopez.Security.Abstractions.Passwords;
using EricksonLopez.Security.Abstractions.Randomness;
using EricksonLopez.Security.Abstractions.Secrets;
using EricksonLopez.Security.Abstractions.Tokens;
using EricksonLopez.Security.Cryptography;
using EricksonLopez.Security.KeyManagement;
using EricksonLopez.Security.Passwords;
using EricksonLopez.Security.Randomness;
using EricksonLopez.Security.Secrets;
using EricksonLopez.Security.Tokens;

/// <summary>
/// Provides extension methods for registering <c>EricksonLopez.Security</c> services,
/// cryptographic engines, key managers, password hashers, token generators, and secret protectors in the dependency injection container.
/// </summary>
public static class SecurityServiceCollectionExtensions
{
    /// <summary>
    /// Registers core security primitives, CSPRNG randomness, constant-time comparers, and envelope serializers.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <returns>The service collection for chaining.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="services"/> is <see langword="null"/></exception>
    public static IServiceCollection AddSecurityCore(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddSingleton<ICryptographicRandomNumberGenerator>(CryptographicRandom.Shared);
        services.AddSingleton<IConstantTimeComparer>(ConstantTimeComparer.Shared);
        services.AddSingleton<IAuthenticatedEncryptionEngine>(AesGcmEncryptionEngine.Shared);
        services.AddSingleton<ISecurityEnvelopeSerializer>(BinarySecurityEnvelopeSerializer.Shared);

        return services;
    }

    /// <summary>
    /// Registers key management infrastructure: in-memory key store (default), key ring, and key lifecycle manager.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <returns>The service collection for chaining.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="services"/> is <see langword="null"/></exception>
    public static IServiceCollection AddKeyManagement(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddSecurityCore();
        services.AddSingleton<IKeyStore, InMemoryKeyStore>();
        services.AddSingleton<IKeyRevocationNotifier, InProcessKeyRevocationNotifier>();
        services.AddSingleton<KeyRing>(sp => new KeyRing(
            sp.GetRequiredService<IKeyStore>(),
            sp.GetService<KeyRingOptions>(),
            sp.GetService<IKeyRevocationNotifier>()));
        services.AddSingleton<IKeyRing>(sp => sp.GetRequiredService<KeyRing>());
        services.AddSingleton<IEncryptionKeyProvider>(sp => sp.GetRequiredService<KeyRing>());
        services.AddSingleton<IKeyLifecycleManager>(sp => new KeyLifecycleManager(
            sp.GetRequiredService<IKeyStore>(),
            null,
            false,
            sp.GetService<IKeyRevocationNotifier>()));

        return services;
    }

    /// <summary>
    /// Registers a distributed key revocation notifier using a custom asynchronous dispatch delegate (e.g., Redis Pub/Sub, RabbitMQ, Kafka).
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="publishHandler">The delegate invoked to broadcast revocation events to an external message broker.</param>
    /// <returns>The service collection for chaining.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="services"/> or <paramref name="publishHandler"/> is <see langword="null"/></exception>
    public static IServiceCollection AddDistributedKeyRevocationNotifier(
        this IServiceCollection services,
        Func<EricksonLopez.Security.Abstractions.Primitives.KeyIdentifier, EricksonLopez.Security.Abstractions.Primitives.KeyVersion, EricksonLopez.Security.Abstractions.Primitives.KeyPurpose, System.Threading.CancellationToken, System.Threading.Tasks.ValueTask> publishHandler)
    {
        // Stryker disable once Statement : Defensive null check redundant with downstream service collection validation
        ArgumentNullException.ThrowIfNull(services);
        // Stryker disable once Statement : Defensive null check redundant with DelegateKeyRevocationNotifier constructor validation
        ArgumentNullException.ThrowIfNull(publishHandler);

        var notifier = new DelegateKeyRevocationNotifier(publishHandler);
        services.AddSingleton<DelegateKeyRevocationNotifier>(notifier);
        services.AddSingleton<IKeyRevocationNotifier>(notifier);

        return services;
    }

    /// <summary>
    /// Registers a distributed key revocation notifier using a service-provider-resolved asynchronous dispatch delegate.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="publishHandlerFactory">The factory function that resolves the publish delegate from the service provider.</param>
    /// <returns>The service collection for chaining.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="services"/> or <paramref name="publishHandlerFactory"/> is <see langword="null"/></exception>
    public static IServiceCollection AddDistributedKeyRevocationNotifier(
        this IServiceCollection services,
        Func<IServiceProvider, Func<EricksonLopez.Security.Abstractions.Primitives.KeyIdentifier, EricksonLopez.Security.Abstractions.Primitives.KeyVersion, EricksonLopez.Security.Abstractions.Primitives.KeyPurpose, System.Threading.CancellationToken, System.Threading.Tasks.ValueTask>> publishHandlerFactory)
    {
        // Stryker disable once Statement : Defensive null check redundant with downstream service collection validation
        ArgumentNullException.ThrowIfNull(services);
        // Stryker disable once Statement : Defensive null check redundant with factory delegate invocation validation
        ArgumentNullException.ThrowIfNull(publishHandlerFactory);

        services.AddSingleton<DelegateKeyRevocationNotifier>(sp =>
        {
            var handler = publishHandlerFactory(sp);
            return new DelegateKeyRevocationNotifier(handler);
        });
        services.AddSingleton<IKeyRevocationNotifier>(sp => sp.GetRequiredService<DelegateKeyRevocationNotifier>());

        return services;
    }

    /// <summary>
    /// Registers modern password security hashing infrastructure (PBKDF2-HMAC-SHA512 default with Argon2id support).
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="iterations">Optional iterations count for PBKDF2 (defaults to 210,000).</param>
    /// <returns>The service collection for chaining.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="services"/> is <see langword="null"/></exception>
    public static IServiceCollection AddPasswordSecurity(this IServiceCollection services, int iterations = Pbkdf2PasswordHasher.DefaultIterations)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddSingleton<Pbkdf2PasswordHasher>(_ => new Pbkdf2PasswordHasher(iterations));
        services.AddSingleton<LegacyPbkdf2PasswordHasher>(_ => LegacyPbkdf2PasswordHasher.Default);
        services.AddSingleton<CompositePasswordHasher>(sp =>
            new CompositePasswordHasher(
                primaryHasher: sp.GetRequiredService<Pbkdf2PasswordHasher>(),
                additionalHashers: [sp.GetRequiredService<LegacyPbkdf2PasswordHasher>()]));
        services.AddSingleton<IPasswordHasher>(sp => sp.GetRequiredService<CompositePasswordHasher>());
        services.AddSingleton<ISimplePasswordHasher>(sp => sp.GetRequiredService<CompositePasswordHasher>());

        return services;
    }

    /// <summary>
    /// Registers token security infrastructure: opaque token generators, HMAC token hashers, and API key generators.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="pepperKey">Optional application-level pepper key bytes for HMAC-SHA256 hashing.</param>
    /// <returns>The service collection for chaining.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="services"/> is <see langword="null"/></exception>
    public static IServiceCollection AddTokenSecurity(this IServiceCollection services, byte[]? pepperKey = null)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddSecurityCore();
        services.AddSingleton<IApiKeyStore, InMemoryApiKeyStore>();
        services.AddSingleton<ITokenGenerator>(OpaqueTokenGenerator.Shared);
        if (pepperKey is not null && pepperKey.Length > 0)
        {
            services.AddSingleton<ITokenHasher>(_ => new HmacSha256TokenHasher(pepperKey));
        }
        else
        {
            services.AddSingleton<ITokenHasher>(_ => new HmacSha256TokenHasher());
        }
        services.AddSingleton<IApiKeyGenerator, ApiKeyGenerator>();
        services.AddSingleton<IApiKeyValidator, ApiKeyValidator>();

        return services;
    }

    /// <summary>
    /// Registers envelope-based secret protection and secret resolution infrastructure.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <returns>The service collection for chaining.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="services"/> is <see langword="null"/></exception>
    public static IServiceCollection AddSecretProtection(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddKeyManagement();
        services.AddSingleton<ISecretProtector, AesGcmSecretProtector>();
        services.AddSingleton<ISecretStore, EnvironmentSecretStore>();
        services.AddSingleton<ISecretResolver, CompositeSecretResolver>();

        return services;
    }

    /// <summary>
    /// Registers the complete suite of <c>EricksonLopez.Security</c> services in one call.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <returns>The service collection for chaining.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="services"/> is <see langword="null"/></exception>
    public static IServiceCollection AddEricksonLopezSecurity(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddPasswordSecurity();
        services.AddTokenSecurity();
        services.AddSecretProtection();

        return services;
    }
}
