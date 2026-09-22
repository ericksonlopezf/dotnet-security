// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Tests.DependencyInjection;

using System;
using EricksonLopez.Security.Abstractions.Cryptography;
using EricksonLopez.Security.Abstractions.KeyManagement;
using EricksonLopez.Security.Abstractions.Passwords;
using EricksonLopez.Security.Abstractions.Randomness;
using EricksonLopez.Security.Abstractions.Secrets;
using EricksonLopez.Security.Abstractions.Tokens;
using EricksonLopez.Security.Passwords;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

public sealed class DependencyInjectionTests
{
    [Fact]
    public void AddSecurityCore_RegistersExpectedServices()
    {
        var services = new ServiceCollection();
        var returned = services.AddSecurityCore();
        Assert.Same(services, returned);

        using var provider = services.BuildServiceProvider();
        Assert.NotNull(provider.GetService<ICryptographicRandomNumberGenerator>());
        Assert.NotNull(provider.GetService<IConstantTimeComparer>());
        Assert.NotNull(provider.GetService<IAuthenticatedEncryptionEngine>());
        Assert.NotNull(provider.GetService<ISecurityEnvelopeSerializer>());

        var ex = Assert.Throws<ArgumentNullException>(() => SecurityServiceCollectionExtensions.AddSecurityCore(null!));
        Assert.DoesNotContain("ServiceCollectionServiceExtensions", ex.StackTrace);
    }

    [Fact]
    public void AddKeyManagement_RegistersExpectedServices_And_InheritedSecurityCore()
    {
        var services = new ServiceCollection();
        var returned = services.AddKeyManagement();
        Assert.Same(services, returned);

        using var provider = services.BuildServiceProvider();
        // Assert SecurityCore services registered transitively
        Assert.NotNull(provider.GetService<ICryptographicRandomNumberGenerator>());
        Assert.NotNull(provider.GetService<ISecurityEnvelopeSerializer>());

        // Assert KeyManagement services
        Assert.NotNull(provider.GetService<IKeyStore>());
        Assert.NotNull(provider.GetService<IKeyRing>());
        Assert.NotNull(provider.GetService<IEncryptionKeyProvider>());
        Assert.NotNull(provider.GetService<IKeyLifecycleManager>());

        var ex = Assert.Throws<ArgumentNullException>(() => SecurityServiceCollectionExtensions.AddKeyManagement(null!));
        Assert.DoesNotContain("AddSecurityCore", ex.StackTrace);
    }

    [Fact]
    public void AddPasswordSecurity_RegistersExpectedServices()
    {
        var services = new ServiceCollection();
        var returned = services.AddPasswordSecurity(iterations: 15_000);
        Assert.Same(services, returned);

        using var provider = services.BuildServiceProvider();
        Assert.NotNull(provider.GetService<Pbkdf2PasswordHasher>());
        Assert.NotNull(provider.GetService<LegacyPbkdf2PasswordHasher>());
        Assert.NotNull(provider.GetService<IPasswordHasher>());
        Assert.NotNull(provider.GetService<ISimplePasswordHasher>());

        // Default iterations overload
        var servicesDefault = new ServiceCollection();
        servicesDefault.AddPasswordSecurity();
        using var providerDefault = servicesDefault.BuildServiceProvider();
        Assert.NotNull(providerDefault.GetService<IPasswordHasher>());
        Assert.NotNull(providerDefault.GetService<ISimplePasswordHasher>());

        var ex = Assert.Throws<ArgumentNullException>(() => SecurityServiceCollectionExtensions.AddPasswordSecurity(null!));
        Assert.DoesNotContain("ServiceCollectionServiceExtensions", ex.StackTrace);
    }

    [Fact]
    public void AddTokenSecurity_RegistersExpectedServices_And_InheritedSecurityCore()
    {
        var services = new ServiceCollection();
        var returned = services.AddTokenSecurity();
        Assert.Same(services, returned);

        using var provider = services.BuildServiceProvider();
        // Assert SecurityCore services registered transitively
        Assert.NotNull(provider.GetService<ICryptographicRandomNumberGenerator>());

        // Assert TokenSecurity services
        Assert.NotNull(provider.GetService<ITokenGenerator>());
        Assert.NotNull(provider.GetService<ITokenHasher>());
        Assert.NotNull(provider.GetService<IApiKeyGenerator>());
        Assert.NotNull(provider.GetService<IApiKeyValidator>());
        Assert.NotNull(provider.GetService<IApiKeyStore>());

        var ex = Assert.Throws<ArgumentNullException>(() => SecurityServiceCollectionExtensions.AddTokenSecurity(null!));
        Assert.DoesNotContain("AddSecurityCore", ex.StackTrace);
    }

    [Fact]
    public void AddSecretProtection_RegistersExpectedServices_And_InheritedKeyManagement()
    {
        var services = new ServiceCollection();
        var returned = services.AddSecretProtection();
        Assert.Same(services, returned);

        using var provider = services.BuildServiceProvider();
        // Assert KeyManagement services registered transitively
        Assert.NotNull(provider.GetService<IKeyRing>());

        // Assert SecretProtection services
        Assert.NotNull(provider.GetService<ISecretProtector>());
        Assert.NotNull(provider.GetService<ISecretStore>());
        Assert.NotNull(provider.GetService<ISecretResolver>());

        var ex = Assert.Throws<ArgumentNullException>(() => SecurityServiceCollectionExtensions.AddSecretProtection(null!));
        Assert.DoesNotContain("AddKeyManagement", ex.StackTrace);
    }

    [Fact]
    public void AddEricksonLopezSecurity_RegistersAllCoreServices()
    {
        var services = new ServiceCollection();
        var returned = services.AddEricksonLopezSecurity();
        Assert.Same(services, returned);

        using var provider = services.BuildServiceProvider();

        Assert.NotNull(provider.GetService<ICryptographicRandomNumberGenerator>());
        Assert.NotNull(provider.GetService<IConstantTimeComparer>());
        Assert.NotNull(provider.GetService<IAuthenticatedEncryptionEngine>());
        Assert.NotNull(provider.GetService<ISecurityEnvelopeSerializer>());
        Assert.NotNull(provider.GetService<IKeyStore>());
        Assert.NotNull(provider.GetService<IKeyRing>());
        Assert.NotNull(provider.GetService<IEncryptionKeyProvider>());
        Assert.NotNull(provider.GetService<IKeyLifecycleManager>());
        Assert.NotNull(provider.GetService<IPasswordHasher>());
        Assert.NotNull(provider.GetService<ITokenGenerator>());
        Assert.NotNull(provider.GetService<ITokenHasher>());
        Assert.NotNull(provider.GetService<IApiKeyGenerator>());
        Assert.NotNull(provider.GetService<IApiKeyValidator>());
        Assert.NotNull(provider.GetService<ISecretProtector>());
        Assert.NotNull(provider.GetService<ISecretStore>());
        Assert.NotNull(provider.GetService<ISecretResolver>());

        var ex = Assert.Throws<ArgumentNullException>(() => SecurityServiceCollectionExtensions.AddEricksonLopezSecurity(null!));
        Assert.DoesNotContain("AddPasswordSecurity", ex.StackTrace);
    }
}
