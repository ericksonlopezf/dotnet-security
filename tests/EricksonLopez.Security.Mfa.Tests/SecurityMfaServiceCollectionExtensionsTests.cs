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
    }

    [Fact]
    public void AddSecurityMfa_NullServices_ThrowsArgumentNullException()
    {
        IServiceCollection services = null!;
        var ex = Assert.Throws<ArgumentNullException>(() => services.AddSecurityMfa());
        ex.StackTrace.Should().NotContain("ServiceCollectionServiceExtensions");
    }
}
