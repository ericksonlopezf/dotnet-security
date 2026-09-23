// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Pki.Tests;

using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using AwesomeAssertions;
using Xunit;

using EricksonLopez.Security.Pki.Tests.Fixtures;

public sealed class CertificateChainValidatorTests : IClassFixture<PkiTestCertificatesFixture>
{
    private readonly PkiTestCertificatesFixture _fixture;

    public CertificateChainValidatorTests(PkiTestCertificatesFixture fixture)
    {
        _fixture = fixture ?? throw new ArgumentNullException(nameof(fixture));
    }

    [Fact]
    public void ValidateCertificate_WithCustomTrustAnchor_ReturnsSuccess()
    {
        var validator = new CertificateChainValidator();
        var options = new CertificateValidationOptions
        {
            RevocationMode = X509RevocationMode.NoCheck,
            RevocationFlag = X509RevocationFlag.EntireChain,
            CustomTrustAnchors = { _fixture.RootCert }
        };

        var result = validator.ValidateCertificate(_fixture.LeafWithKey, options);

        result.IsSuccess.Should().BeTrue();
        result.Value.Should().BeTrue();
    }


    [Fact]
    public void ValidateCertificate_UntrustedRootWithoutAnchor_ReturnsUnauthorized()
    {
        // Create self-signed untrusted leaf
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=UntrustedSelfSigned", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddYears(1));

        var validator = new CertificateChainValidator();
        var options = new CertificateValidationOptions
        {
            RevocationMode = X509RevocationMode.NoCheck
        };

        var result = validator.ValidateCertificate(cert, options);

        result.IsFailure.Should().BeTrue();
        result.Error.Code.Should().Be("Pki.CertificateChainInvalid");
        result.Error.Description.Should().StartWith("X.509 certificate chain validation failed:");
        result.Error.Description.Should().Contain("UntrustedRoot");
    }

    [Fact]
    public void ValidateCertificate_NullCertificate_ThrowsArgumentNullException()
    {
        var validator = new CertificateChainValidator();
        var act = () => validator.ValidateCertificate(null!);
        act.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void ValidateCertificate_DefaultOptions_HandlesEvaluation()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=UntrustedDefaultOptions", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddYears(1));

        var validator = new CertificateChainValidator();
        // Passing null options triggers options ?? new CertificateValidationOptions()
        var result = validator.ValidateCertificate(cert, options: null);

        result.IsFailure.Should().BeTrue();
        result.Error.Code.Should().Be("Pki.CertificateChainInvalid");
        result.Error.Description.Should().StartWith("X.509 certificate chain validation failed:");
        result.Error.Description.Should().Contain("UntrustedRoot");
    }

    [Fact]
    public void ValidateCertificate_ExpiredCertificate_ReturnsFailureWithDetails()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=ExpiredCert", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddYears(-2), DateTimeOffset.UtcNow.AddYears(-1));

        var validator = new CertificateChainValidator();
        var result = validator.ValidateCertificate(cert);

        result.IsFailure.Should().BeTrue();
        result.Error.Code.Should().Be("Pki.CertificateChainInvalid");
        result.Error.Description.Should().StartWith("X.509 certificate chain validation failed:");
        result.Error.Description.Should().Contain("NotTimeValid");
    }

    [Fact]
    public void ValidateCertificate_UntrustedAndExpired_ReturnsMultipleErrorsJoinedWithSemicolon()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=UntrustedAndExpired", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddYears(-3), DateTimeOffset.UtcNow.AddYears(-2));

        var validator = new CertificateChainValidator();
        var result = validator.ValidateCertificate(cert);

        result.IsFailure.Should().BeTrue();
        result.Error.Code.Should().Be("Pki.CertificateChainInvalid");
        result.Error.Description.Should().StartWith("X.509 certificate chain validation failed:");
        result.Error.Description.Should().Contain("; ");
        result.Error.Description.Should().Contain("UntrustedRoot");
        result.Error.Description.Should().Contain("NotTimeValid");
    }

    [Fact]
    public void ValidateCertificate_WithMatchingHostName_ReturnsSuccess()
    {
        var validator = new CertificateChainValidator();
        var options = new CertificateValidationOptions
        {
            RevocationMode = X509RevocationMode.NoCheck,
            CustomTrustAnchors = { _fixture.RootCert },
            ExpectedHostName = "LeafClient"
        };

        var result = validator.ValidateCertificate(_fixture.LeafWithKey, options);

        result.IsSuccess.Should().BeTrue();
    }

    [Fact]
    public void ValidateCertificate_WithMismatchedHostName_ReturnsUnauthorized()
    {
        var validator = new CertificateChainValidator();
        var options = new CertificateValidationOptions
        {
            RevocationMode = X509RevocationMode.NoCheck,
            CustomTrustAnchors = { _fixture.RootCert },
            ExpectedHostName = "mismatched.example.com"
        };

        var result = validator.ValidateCertificate(_fixture.LeafWithKey, options);

        result.IsFailure.Should().BeTrue();
        result.Error.Code.Should().Be("Pki.CertificateHostnameMismatch");
    }

    [Fact]
    public void ValidateCertificate_WithMissingRequiredEku_ReturnsUnauthorized()
    {
        var validator = new CertificateChainValidator();
        var options = new CertificateValidationOptions
        {
            RevocationMode = X509RevocationMode.NoCheck,
            CustomTrustAnchors = { _fixture.RootCert },
            RequiredExtendedKeyUsageOid = "1.3.6.1.5.5.7.3.1" // Server Authentication
        };

        var result = validator.ValidateCertificate(_fixture.LeafWithKey, options);

        result.IsFailure.Should().BeTrue();
        result.Error.Code.Should().Be("Pki.CertificateEkuMismatch");
    }

    [Fact]
    public void ValidateCertificate_WithMatchingRequiredEku_ReturnsSuccess()
    {
        const string serverAuthOid = "1.3.6.1.5.5.7.3.1";
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=LeafClientWithEku", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
        req.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        var ekuCollection = new OidCollection { new Oid(serverAuthOid) };
        req.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(ekuCollection, false));

        var serial = new byte[8];
        RandomNumberGenerator.Fill(serial);
        var now = DateTimeOffset.UtcNow;
        using var cert = req.Create(_fixture.RootCert, now.AddMinutes(-5), now.AddYears(1), serial);
        using var certWithKey = cert.CopyWithPrivateKey(rsa);

        var validator = new CertificateChainValidator();
        var options = new CertificateValidationOptions
        {
            RevocationMode = X509RevocationMode.NoCheck,
            CustomTrustAnchors = { _fixture.RootCert },
            RequiredExtendedKeyUsageOid = serverAuthOid
        };

        var result = validator.ValidateCertificate(certWithKey, options);

        result.IsSuccess.Should().BeTrue();
        result.Value.Should().BeTrue();
    }

    [Fact]
    public void ValidateCertificate_WithMismatchedEkuOid_ReturnsUnauthorized()
    {
        const string clientAuthOid = "1.3.6.1.5.5.7.3.2";
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=LeafClientWithClientEku", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
        req.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        var ekuCollection = new OidCollection { new Oid(clientAuthOid) };
        req.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(ekuCollection, false));

        var serial = new byte[8];
        RandomNumberGenerator.Fill(serial);
        var now = DateTimeOffset.UtcNow;
        using var cert = req.Create(_fixture.RootCert, now.AddMinutes(-5), now.AddYears(1), serial);
        using var certWithKey = cert.CopyWithPrivateKey(rsa);

        var validator = new CertificateChainValidator();
        var options = new CertificateValidationOptions
        {
            RevocationMode = X509RevocationMode.NoCheck,
            CustomTrustAnchors = { _fixture.RootCert },
            RequiredExtendedKeyUsageOid = "1.3.6.1.5.5.7.3.1" // Server Authentication
        };

        var result = validator.ValidateCertificate(certWithKey, options);

        result.IsFailure.Should().BeTrue();
        result.Error.Code.Should().Be("Pki.CertificateEkuMismatch");
        result.Error.Description.Should().Contain("1.3.6.1.5.5.7.3.1");
    }
}
