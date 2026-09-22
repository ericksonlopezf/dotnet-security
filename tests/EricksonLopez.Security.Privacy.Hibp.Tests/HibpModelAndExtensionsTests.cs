// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Privacy.Hibp.Tests;

using System;
using System.Net.Http;
using AwesomeAssertions;
using EricksonLopez.Security.Privacy.Hibp.Abstractions;
using EricksonLopez.Security.Privacy.Hibp.DependencyInjection;
using EricksonLopez.Security.Privacy.Hibp.Models;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Xunit;

public sealed class HibpModelAndExtensionsTests
{
    [Fact]
    public void HibpOptions_Defaults_AreCorrect()
    {
        var options = new HibpOptions();

        options.BaseUrl.Should().Be("https://api.pwnedpasswords.com/");
        options.UserAgent.Should().Be("EricksonLopez-Security-Hibp-Client");
        options.AddPadding.Should().BeTrue();
        options.Timeout.Should().Be(TimeSpan.FromSeconds(5));
        options.MaxAllowedBreachCount.Should().Be(0);
    }

    [Fact]
    public void HibpOptions_Properties_CanBeSet()
    {
        var options = new HibpOptions
        {
            BaseUrl = "https://custom.pwned.local/",
            UserAgent = "CustomUserAgent/2.0",
            AddPadding = false,
            Timeout = TimeSpan.FromSeconds(15),
            MaxAllowedBreachCount = 10
        };

        options.BaseUrl.Should().Be("https://custom.pwned.local/");
        options.UserAgent.Should().Be("CustomUserAgent/2.0");
        options.AddPadding.Should().BeFalse();
        options.Timeout.Should().Be(TimeSpan.FromSeconds(15));
        options.MaxAllowedBreachCount.Should().Be(10);
    }

    [Fact]
    public void PwnedPasswordCheckResult_ConstructorAndProperties_Work()
    {
        var res1 = new PwnedPasswordCheckResult("ABCDE", 50);
        res1.HashPrefix.Should().Be("ABCDE");
        res1.BreachCount.Should().Be(50);
        res1.IsPwned.Should().BeTrue();

        var res2 = new PwnedPasswordCheckResult("00000", 0);
        res2.IsPwned.Should().BeFalse();

        Assert.Throws<ArgumentNullException>(() => new PwnedPasswordCheckResult(null!, 0));
        Assert.Throws<ArgumentException>(() => new PwnedPasswordCheckResult("  ", 0));
    }

    [Fact]
    public void PwnedPasswordEntry_ConstructorAndProperties_Work()
    {
        var entry = new PwnedPasswordEntry("1234567890ABCDEF", 42);
        entry.Suffix.Should().Be("1234567890ABCDEF");
        entry.BreachCount.Should().Be(42);

        Assert.Throws<ArgumentNullException>(() => new PwnedPasswordEntry(null!, 0));
        Assert.Throws<ArgumentException>(() => new PwnedPasswordEntry("  ", 0));
    }

    [Fact]
    public void AddHaveIBeenPwned_WithoutOptions_RegistersServices()
    {
        var services = new ServiceCollection();
        var returned = services.AddHaveIBeenPwned();

        returned.Should().BeSameAs(services);
        services.Should().Contain(sd => sd.ServiceType == typeof(IConfigureOptions<HibpOptions>));

        var provider = services.BuildServiceProvider();
        using var scope = provider.CreateScope();

        var validator = scope.ServiceProvider.GetService<IPasswordPwnedValidator>();
        var client = scope.ServiceProvider.GetService<IHaveIBeenPwnedClient>();
        var factory = scope.ServiceProvider.GetRequiredService<IHttpClientFactory>();
        var namedClient = factory.CreateClient(nameof(IHaveIBeenPwnedClient));

        validator.Should().NotBeNull();
        client.Should().NotBeNull();
        namedClient.BaseAddress.Should().Be(new Uri("https://api.pwnedpasswords.com/"));
        namedClient.Timeout.Should().Be(TimeSpan.FromSeconds(5));
        namedClient.DefaultRequestHeaders.UserAgent.ToString().Should().Contain("EricksonLopez-Security-Hibp-Client");
    }

    [Fact]
    public void AddHaveIBeenPwned_WithOptions_ConfiguresOptions()
    {
        var services = new ServiceCollection();
        services.AddHaveIBeenPwned(options =>
        {
            options.MaxAllowedBreachCount = 100;
            options.UserAgent = "MyTestAgent";
        });

        var provider = services.BuildServiceProvider();
        var options = provider.GetRequiredService<IOptions<HibpOptions>>().Value;

        options.MaxAllowedBreachCount.Should().Be(100);
        options.UserAgent.Should().Be("MyTestAgent");
    }

    [Fact]
    public void AddHaveIBeenPwned_NullServices_ThrowsArgumentNullException()
    {
        IServiceCollection services = null!;
        var ex = Assert.Throws<ArgumentNullException>("services", () => services.AddHaveIBeenPwned());
        ex.StackTrace.Should().NotContain("Configure");
    }
}
