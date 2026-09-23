// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.WebAuthn.Fido2.Mds3.Tests;

using System;
using System.Collections.Generic;
using System.Net.Http;
using AwesomeAssertions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Xunit;

public sealed class Mds3ModelAndExtensionsTests
{
    [Fact]
    public void Models_PropertiesAndRecords_InstantiateCorrectly()
    {
        var aaguid = Guid.NewGuid();
        var report = new AuthenticatorStatusReport(
            AuthenticatorStatus.FidoCertifiedL3,
            "2026-06-01",
            "https://fido.org/cert",
            "cert-data",
            "L3");

        report.Status.Should().Be(AuthenticatorStatus.FidoCertifiedL3);
        report.EffectiveDate.Should().Be("2026-06-01");
        report.Url.Should().Be("https://fido.org/cert");
        report.Certificate.Should().Be("cert-data");
        report.CertificationLevel.Should().Be("L3");

        var rootCerts = new List<byte[]> { new byte[] { 1, 2, 3 } };
        var now = DateTimeOffset.UtcNow;
        var metadata = new AuthenticatorMetadata(
            "YubiKey 5 Series",
            new List<AuthenticatorStatusReport> { report },
            rootCerts,
            now,
            aaguid);

        metadata.Description.Should().Be("YubiKey 5 Series");
        metadata.StatusReports.Should().HaveCount(1);
        metadata.AttestationRootCertificates.Should().Equal(rootCerts);
        metadata.TimeOfLastStatusChange.Should().Be(now);
        metadata.Aaguid.Should().Be(aaguid);

        var defaultOpts = new Mds3Options();
        defaultOpts.MetadataBlobUrl.Should().Be("https://mds3.fidoalliance.org/");
        defaultOpts.CacheDuration.Should().Be(TimeSpan.FromHours(24));
        defaultOpts.ValidateJwtSignature.Should().BeTrue();
        defaultOpts.AllowUnknownAuthenticators.Should().BeTrue();
        defaultOpts.DisallowedStatuses.Should().HaveCount(5);

        var opts = new Mds3Options
        {
            MetadataBlobUrl = "https://custom-mds.org/",
            CacheDuration = TimeSpan.FromHours(48),
            ValidateJwtSignature = false,
            AllowUnknownAuthenticators = false,
            DisallowedStatuses = new[] { AuthenticatorStatus.Revoked }
        };

        opts.MetadataBlobUrl.Should().Be("https://custom-mds.org/");
        opts.CacheDuration.Should().Be(TimeSpan.FromHours(48));
        opts.ValidateJwtSignature.Should().BeFalse();
        opts.AllowUnknownAuthenticators.Should().BeFalse();
        opts.DisallowedStatuses.Should().HaveCount(1);
    }

    [Fact]
    public void Models_NullChecks_ThrowArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => new AuthenticatorStatusReport(AuthenticatorStatus.Revoked, null!));

        var reports = new List<AuthenticatorStatusReport>();
        var certs = new List<byte[]>();
        var now = DateTimeOffset.UtcNow;

        Assert.Throws<ArgumentNullException>(() => new AuthenticatorMetadata(null!, reports, certs, now));
        Assert.Throws<ArgumentNullException>(() => new AuthenticatorMetadata("desc", null!, certs, now));
        Assert.Throws<ArgumentNullException>(() => new AuthenticatorMetadata("desc", reports, null!, now));
    }

    [Fact]
    public void DependencyInjection_AddFidoMds3_RegistersServices()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddFidoMds3(opts =>
        {
            opts.AllowUnknownAuthenticators = false;
        });

        var provider = services.BuildServiceProvider();
        var mdsService = provider.GetRequiredService<IMds3MetadataService>();
        mdsService.Should().NotBeNull();

        var clientFactory = provider.GetRequiredService<IHttpClientFactory>();
        var client = clientFactory.CreateClient(nameof(HttpMds3MetadataService));
        client.Timeout.Should().Be(TimeSpan.FromSeconds(30));
        client.DefaultRequestHeaders.Accept.ToString().Should().Contain("application/jwt");

        var options = provider.GetRequiredService<IOptions<Mds3Options>>().Value;
        options.AllowUnknownAuthenticators.Should().BeFalse();
    }

    [Fact]
    public void DependencyInjection_NullAction_RegistersDefaultsSuccessfully()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddFidoMds3(null);

        var provider = services.BuildServiceProvider();
        provider.GetRequiredService<IMds3MetadataService>().Should().NotBeNull();
    }

    [Fact]
    public void DependencyInjection_NullServices_ThrowsArgumentNullException()
    {
        var ex = Assert.Throws<ArgumentNullException>(() => Mds3ServiceCollectionExtensions.AddFidoMds3(null!));
        ex.ParamName.Should().Be("services");
        ex.StackTrace.Should().NotContain("HttpClientFactoryServiceCollectionExtensions");
    }

    [Fact]
    public async Task Service_Dispose_ThrowsObjectDisposedException_OnSubsequentCalls()
    {
        var httpClient = new HttpClient();
        var options = Microsoft.Extensions.Options.Options.Create(new Mds3Options());
        var logger = Microsoft.Extensions.Logging.Abstractions.NullLogger<HttpMds3MetadataService>.Instance;
        var service = new HttpMds3MetadataService(httpClient, options, logger);

        service.Dispose();

        await Assert.ThrowsAsync<ObjectDisposedException>(() => service.RefreshAsync());
        await Assert.ThrowsAsync<ObjectDisposedException>(() => service.GetMetadataAsync(Guid.NewGuid()));
        await Assert.ThrowsAsync<ObjectDisposedException>(() => service.ValidateAuthenticatorStatusAsync(Guid.NewGuid()));
    }
}
