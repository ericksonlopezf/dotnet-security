// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Mfa.Tests;

using System;
using Microsoft.Extensions.DependencyInjection;
using AwesomeAssertions;
using Xunit;

public sealed class SecurityMfaServiceCollectionExtensionsTests
{
    [Fact]
    public void AddSecurityMfa_RegistersTotpServiceAsSingleton()
    {
        var services = new ServiceCollection();

        var returned = services.AddSecurityMfa();
        returned.Should().BeSameAs(services);

        using var provider = services.BuildServiceProvider();

        var totp = provider.GetService<ITotpService>();
        totp.Should().NotBeNull().And.BeOfType<TotpService>();

        var recovery = provider.GetService<IRecoveryCodeGenerator>();
        recovery.Should().NotBeNull().And.BeOfType<RecoveryCodeGenerator>();

        var replay = provider.GetService<ITotpReplayStore>();
        replay.Should().NotBeNull().And.BeOfType<InMemoryTotpReplayStore>();
    }

    [Fact]
    public void AddSecurityMfa_NullServices_ThrowsArgumentNullException()
    {
        IServiceCollection services = null!;
        var ex = Assert.Throws<ArgumentNullException>(() => services.AddSecurityMfa());
        ex.StackTrace.Should().NotContain("ServiceCollectionServiceExtensions");
    }

    [Fact]
    public void AddDistributedTotpReplayStore_Generic_RegistersCustomStore()
    {
        var services = new ServiceCollection();
        var returned = services.AddDistributedTotpReplayStore<InMemoryTotpReplayStore>();
        returned.Should().BeSameAs(services);

        using var provider = services.BuildServiceProvider();
        var replay = provider.GetService<ITotpReplayStore>();
        replay.Should().NotBeNull().And.BeOfType<InMemoryTotpReplayStore>();
    }

    [Fact]
    public void AddDistributedTotpReplayStore_Generic_NullServices_ThrowsArgumentNullException()
    {
        IServiceCollection services = null!;
        Assert.Throws<ArgumentNullException>(() => services.AddDistributedTotpReplayStore<InMemoryTotpReplayStore>());
    }

    [Fact]
    public void AddDistributedTotpReplayStore_Delegate_NullArguments_ThrowsArgumentNullException()
    {
        IServiceCollection nullServices = null!;
        Assert.Throws<ArgumentNullException>(() => nullServices.AddDistributedTotpReplayStore((k, e, ct) => System.Threading.Tasks.ValueTask.FromResult(true)));

        var services = new ServiceCollection();
        Assert.Throws<ArgumentNullException>(() => services.AddDistributedTotpReplayStore(null!));
    }
}
