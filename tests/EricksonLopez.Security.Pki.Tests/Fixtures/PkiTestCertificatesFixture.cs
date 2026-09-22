// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Pki.Tests.Fixtures;

using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

/// <summary>
/// Provides shared X.509 certificates and keys for PKI tests to eliminate repetitive RSA generation.
/// </summary>
public sealed class PkiTestCertificatesFixture : IDisposable
{
    public X509Certificate2 RootCert { get; }
    public X509Certificate2 LeafWithKey { get; }

    public PkiTestCertificatesFixture()
    {
        using var rootRsa = RSA.Create(2048);
        var rootReq = new CertificateRequest("CN=TestRootCA", rootRsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        rootReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, true, 1, true));
        rootReq.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));

        var now = DateTimeOffset.UtcNow;
        RootCert = rootReq.CreateSelfSigned(now.AddMinutes(-5), now.AddYears(2));

        using var leafRsa = RSA.Create(2048);
        var leafReq = new CertificateRequest("CN=LeafClient", leafRsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        leafReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
        leafReq.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));

        var serial = new byte[8];
        RandomNumberGenerator.Fill(serial);
        using var leafCert = leafReq.Create(RootCert, now.AddMinutes(-5), now.AddYears(1), serial);
        LeafWithKey = leafCert.CopyWithPrivateKey(leafRsa);
    }

    public void Dispose()
    {
        RootCert.Dispose();
        LeafWithKey.Dispose();
    }
}
