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
        var ex = Assert.Throws<ArgumentNullException>("services", () => services.AddDistributedTotpReplayStore<InMemoryTotpReplayStore>());
        ex.ParamName.Should().Be("services");
    }

    [Fact]
    public void AddDistributedTotpReplayStore_Delegate_NullArguments_ThrowsArgumentNullException()
    {
        IServiceCollection nullServices = null!;
        var ex1 = Assert.Throws<ArgumentNullException>("services", () => nullServices.AddDistributedTotpReplayStore((k, e, ct) => System.Threading.Tasks.ValueTask.FromResult(true)));
        ex1.ParamName.Should().Be("services");

        var services = new ServiceCollection();
        var ex2 = Assert.Throws<ArgumentNullException>("asyncHandler", () => services.AddDistributedTotpReplayStore(null!));
        ex2.ParamName.Should().Be("asyncHandler");
    }

    [Fact]
    public void AddDistributedTotpReplayStore_Delegate_WithSyncHandler_RegistersCustomStore()
    {
        var services = new ServiceCollection();
        var returned = services.AddDistributedTotpReplayStore(
            (k, e, ct) => System.Threading.Tasks.ValueTask.FromResult(true),
            (k, e) => true);
        returned.Should().BeSameAs(services);

        using var provider = services.BuildServiceProvider();
        var replay = provider.GetService<ITotpReplayStore>();
        replay.Should().NotBeNull().And.BeOfType<DelegateTotpReplayStore>();
    }
}
