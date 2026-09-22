// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Tests.DependencyInjection;

using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using EricksonLopez.Result;
using EricksonLopez.Security.Abstractions.Cryptography;
using EricksonLopez.Security.Abstractions.KeyManagement;
using EricksonLopez.Security.Abstractions.Passwords;
using EricksonLopez.Security.Abstractions.Primitives;
using EricksonLopez.Security.Abstractions.Randomness;
using EricksonLopez.Security.Abstractions.Secrets;
using EricksonLopez.Security.Abstractions.Tokens;
using EricksonLopez.Security.KeyManagement;
using EricksonLopez.Security.Passwords;
using EricksonLopez.Security.Tokens;
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
        var klm = provider.GetService<IKeyLifecycleManager>() as KeyLifecycleManager;
        Assert.NotNull(klm);
        Assert.False(klm.FailOnAuditFailure);
        Assert.NotNull(provider.GetService<IKeyRevocationNotifier>());

        var ex = Assert.Throws<ArgumentNullException>(() => SecurityServiceCollectionExtensions.AddKeyManagement(null!));
        Assert.DoesNotContain("AddSecurityCore", ex.StackTrace);
    }

    [Fact]
    public void AddDistributedKeyRevocationNotifier_RegistersDelegateNotifier()
    {
        var services = new ServiceCollection();
        Func<EricksonLopez.Security.Abstractions.Primitives.KeyIdentifier, EricksonLopez.Security.Abstractions.Primitives.KeyVersion, EricksonLopez.Security.Abstractions.Primitives.KeyPurpose, System.Threading.CancellationToken, System.Threading.Tasks.ValueTask> handler =
            (id, v, p, ct) => System.Threading.Tasks.ValueTask.CompletedTask;

        var returned = services.AddDistributedKeyRevocationNotifier(handler);
        Assert.Same(services, returned);

        using var provider = services.BuildServiceProvider();
        var notifier = provider.GetService<IKeyRevocationNotifier>();
        Assert.NotNull(notifier);

        // Null checks
        Assert.Throws<ArgumentNullException>("services", () => SecurityServiceCollectionExtensions.AddDistributedKeyRevocationNotifier(null!, handler));
        Assert.Throws<ArgumentNullException>("publishHandler", () => services.AddDistributedKeyRevocationNotifier((Func<EricksonLopez.Security.Abstractions.Primitives.KeyIdentifier, EricksonLopez.Security.Abstractions.Primitives.KeyVersion, EricksonLopez.Security.Abstractions.Primitives.KeyPurpose, System.Threading.CancellationToken, System.Threading.Tasks.ValueTask>)null!));

        // Factory overload
        var servicesFactory = new ServiceCollection();
        servicesFactory.AddDistributedKeyRevocationNotifier(sp => handler);
        using var providerFactory = servicesFactory.BuildServiceProvider();
        Assert.NotNull(providerFactory.GetService<IKeyRevocationNotifier>());

        Assert.Throws<ArgumentNullException>("services", () => SecurityServiceCollectionExtensions.AddDistributedKeyRevocationNotifier(null!, sp => handler));
        Assert.Throws<ArgumentNullException>("publishHandlerFactory", () => services.AddDistributedKeyRevocationNotifier((Func<IServiceProvider, Func<EricksonLopez.Security.Abstractions.Primitives.KeyIdentifier, EricksonLopez.Security.Abstractions.Primitives.KeyVersion, EricksonLopez.Security.Abstractions.Primitives.KeyPurpose, System.Threading.CancellationToken, System.Threading.Tasks.ValueTask>>)null!));
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

    [Fact]
    public void AddTokenSecurity_WithEmptyPepperKey_RegistersUnpepperedHasher()
    {
        var services = new ServiceCollection();
        services.AddTokenSecurity(Array.Empty<byte>());
        using var provider = services.BuildServiceProvider();
        var hasher = provider.GetRequiredService<ITokenHasher>();
        Assert.NotNull(hasher);

        var services3 = new ServiceCollection();
        services3.AddTokenSecurity(new byte[] { 1, 2, 3, 4 });
        using var p3 = services3.BuildServiceProvider();
        var pepperedHasher = p3.GetRequiredService<ITokenHasher>() as HmacSha256TokenHasher;
        Assert.NotNull(pepperedHasher);
        Assert.NotNull(pepperedHasher.PepperKey);
    }

    [Fact]
    public void AddDistributedKeyRevocationNotifier_ValidatesArguments_And_Registers()
    {
        var services = new ServiceCollection();
        Func<KeyIdentifier, KeyVersion, KeyPurpose, CancellationToken, ValueTask> handler = (_, _, _, _) => ValueTask.CompletedTask;
        Func<IServiceProvider, Func<KeyIdentifier, KeyVersion, KeyPurpose, CancellationToken, ValueTask>> factory = _ => handler;

        var ex1 = Assert.Throws<ArgumentNullException>(() => SecurityServiceCollectionExtensions.AddDistributedKeyRevocationNotifier(null!, handler));
        Assert.Equal("services", ex1.ParamName);
        var ex2 = Assert.Throws<ArgumentNullException>(() => SecurityServiceCollectionExtensions.AddDistributedKeyRevocationNotifier(services, (Func<KeyIdentifier, KeyVersion, KeyPurpose, CancellationToken, ValueTask>)null!));
        Assert.Equal("publishHandler", ex2.ParamName);
        var ex3 = Assert.Throws<ArgumentNullException>(() => SecurityServiceCollectionExtensions.AddDistributedKeyRevocationNotifier(null!, factory));
        Assert.Equal("services", ex3.ParamName);
        var ex4 = Assert.Throws<ArgumentNullException>(() => SecurityServiceCollectionExtensions.AddDistributedKeyRevocationNotifier(services, (Func<IServiceProvider, Func<KeyIdentifier, KeyVersion, KeyPurpose, CancellationToken, ValueTask>>)null!));
        Assert.Equal("publishHandlerFactory", ex4.ParamName);

        services.AddDistributedKeyRevocationNotifier(handler);
        var services2 = new ServiceCollection();
        services2.AddDistributedKeyRevocationNotifier(factory);

        using var p1 = services.BuildServiceProvider();
        Assert.NotNull(p1.GetService<IKeyRevocationNotifier>());

        using var p2 = services2.BuildServiceProvider();
        Assert.NotNull(p2.GetService<IKeyRevocationNotifier>());
    }

    [Fact]
    public void AddKeyManagement_DoesNotDisposeKeyStore_WhenLifecycleManagerDisposed()
    {
        var services = new ServiceCollection();
        var store = new DisposableKeyStore();
        services.AddSingleton<IKeyStore>(store);
        services.AddKeyManagement();

        using (var provider = services.BuildServiceProvider())
        {
            var manager = provider.GetRequiredService<IKeyLifecycleManager>();
            ((IDisposable)manager).Dispose();
            Assert.False(store.Disposed);
        }
    }

    private sealed class DisposableKeyStore : IKeyStore, IDisposable
    {
        public bool Disposed { get; private set; }
        public void Dispose() => Disposed = true;
        public ValueTask<Result> SaveKeyAsync(CryptographicKey key, CancellationToken cancellationToken = default) => ValueTask.FromResult(Result.Success());
        public ValueTask<Result<CryptographicKey>> GetKeyAsync(KeyIdentifier keyId, KeyVersion version, CancellationToken cancellationToken = default) => throw new NotImplementedException();
        public ValueTask<Result<IReadOnlyList<KeyMetadata>>> ListMetadataAsync(KeyPurpose? purpose = null, CancellationToken cancellationToken = default) => throw new NotImplementedException();
        public ValueTask<Result> UpdateStatusAsync(KeyIdentifier keyId, KeyVersion version, KeyStatus newStatus, CancellationToken cancellationToken = default) => ValueTask.FromResult(Result.Success());
    }
}
