// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Pki.Tests;

using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using AwesomeAssertions;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

public sealed class PkiModelAndExtensionsTests
{
    [Fact]
    public void CertificateRevocationStatus_EnumValues_AreCorrect()
    {
        ((int)CertificateRevocationStatus.Valid).Should().Be(0);
        ((int)CertificateRevocationStatus.Revoked).Should().Be(1);
        ((int)CertificateRevocationStatus.Unknown).Should().Be(2);
    }

    [Fact]
    public void CertificateValidationOptions_Defaults_AreCorrect()
    {
        var options = new CertificateValidationOptions();

        options.RevocationMode.Should().Be(X509RevocationMode.Online);
        options.RevocationFlag.Should().Be(X509RevocationFlag.EntireChain);
        options.CustomTrustAnchors.Should().NotBeNull();
        options.CustomTrustAnchors.Should().BeEmpty();
    }

    [Fact]
    public void CertificateValidationOptions_Properties_CanBeSet()
    {
        var customList = new List<X509Certificate2>();
        var options = new CertificateValidationOptions
        {
            RevocationMode = X509RevocationMode.NoCheck,
            RevocationFlag = X509RevocationFlag.EndCertificateOnly,
            CustomTrustAnchors = customList
        };

        options.RevocationMode.Should().Be(X509RevocationMode.NoCheck);
        options.RevocationFlag.Should().Be(X509RevocationFlag.EndCertificateOnly);
        options.CustomTrustAnchors.Should().BeSameAs(customList);
    }

    [Fact]
    public void SecurityPkiServiceCollectionExtensions_AddSecurityPki_RegistersServices()
    {
        var services = new ServiceCollection();
        var returnedServices = services.AddSecurityPki();

        returnedServices.Should().BeSameAs(services);

        var provider = services.BuildServiceProvider();
        var validator1 = provider.GetService<ICertificateChainValidator>();
        var validator2 = provider.GetService<ICertificateChainValidator>();

        validator1.Should().NotBeNull();
        validator1.Should().BeOfType<CertificateChainValidator>();
        validator1.Should().BeSameAs(validator2); // Singleton
    }

    [Fact]
    public void SecurityPkiServiceCollectionExtensions_AddSecurityPki_NullServices_ThrowsArgumentNullException()
    {
        IServiceCollection services = null!;
        var ex = Assert.Throws<ArgumentNullException>("services", () => services.AddSecurityPki());
        ex.StackTrace.Should().NotContain("AddSingleton");
    }
}
