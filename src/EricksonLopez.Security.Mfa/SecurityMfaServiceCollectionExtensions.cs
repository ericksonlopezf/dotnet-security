// Copyright © Erickson Lopez. MIT License.
using System;
using System.Diagnostics.CodeAnalysis;
using Microsoft.Extensions.DependencyInjection;

namespace EricksonLopez.Security.Mfa;

/// <summary>
/// Provides extension methods for registering multi-factor authentication and TOTP services into the service collection.
/// </summary>
public static class SecurityMfaServiceCollectionExtensions
{
    /// <summary>
    /// Registers the <see cref="ITotpService"/> implementation into the service collection.
    /// </summary>
    /// <param name="services">The service collection to configure.</param>
    /// <returns>The same service collection instance for method chaining.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="services"/> is <see langword="null"/></exception>
    public static IServiceCollection AddSecurityMfa(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddSingleton<ITotpService, TotpService>();
        services.AddSingleton<IRecoveryCodeGenerator, RecoveryCodeGenerator>();
        Microsoft.Extensions.DependencyInjection.Extensions.ServiceCollectionDescriptorExtensions.TryAddSingleton<ITotpReplayStore, InMemoryTotpReplayStore>(services);
        return services;
    }

    /// <summary>
    /// Overrides the default in-memory TOTP replay store with a custom distributed store implementation.
    /// </summary>
    /// <typeparam name="TStore">The distributed store type implementing <see cref="ITotpReplayStore"/>.</typeparam>
    /// <param name="services">The service collection to configure.</param>
    /// <returns>The same service collection instance for method chaining.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="services"/> is <see langword="null"/></exception>
    public static IServiceCollection AddDistributedTotpReplayStore<[DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicConstructors)] TStore>(this IServiceCollection services)
        where TStore : class, ITotpReplayStore
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddSingleton<ITotpReplayStore, TStore>();
        return services;
    }

    /// <summary>
    /// Overrides the default in-memory TOTP replay store with a delegate-based distributed store handler.
    /// </summary>
    /// <param name="services">The service collection to configure.</param>
    /// <param name="asyncHandler">The asynchronous delegate invoked to record replay keys.</param>
    /// <param name="syncHandler">Optional synchronous delegate invoked during synchronous verification.</param>
    /// <returns>The same service collection instance for method chaining.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="services"/> or <paramref name="asyncHandler"/> is <see langword="null"/></exception>
    public static IServiceCollection AddDistributedTotpReplayStore(
        this IServiceCollection services,
        Func<string, DateTimeOffset, System.Threading.CancellationToken, System.Threading.Tasks.ValueTask<bool>> asyncHandler,
        Func<string, DateTimeOffset, bool>? syncHandler = null)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(asyncHandler);

        services.AddSingleton<ITotpReplayStore>(new DelegateTotpReplayStore(asyncHandler, syncHandler));
        return services;
    }
}

