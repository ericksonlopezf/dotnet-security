// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Saml2.Tests.Fixtures;

using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

/// <summary>
/// Shared test fixture providing pre-generated self-signed RSA certificates for SAML2 test execution,
/// avoiding redundant RSA key generation per test method and ensuring deterministic disposal.
/// </summary>
public sealed class SamlTestCertificatesFixture : IDisposable
{
    public X509Certificate2 IdpCert { get; }
    public X509Certificate2 SpCert { get; }
    public X509Certificate2 SpDecCert { get; }

    public SamlTestCertificatesFixture()
    {
        using var rsa = RSA.Create(2048);
        var certReq = new CertificateRequest("CN=TestIdP", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        IdpCert = certReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddHours(1));

        using var spRsa = RSA.Create(2048);
        var spReq = new CertificateRequest("CN=TestSP", spRsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        SpCert = spReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddHours(1));

        using var decRsa = RSA.Create(2048);
        var decReq = new CertificateRequest("CN=TestDecSP", decRsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        SpDecCert = decReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddHours(1));
    }

    public void Dispose()
    {
        IdpCert.Dispose();
        SpCert.Dispose();
        SpDecCert.Dispose();
    }
}
