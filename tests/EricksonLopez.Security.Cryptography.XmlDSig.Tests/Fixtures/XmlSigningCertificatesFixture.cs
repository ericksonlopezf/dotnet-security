// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Cryptography.XmlDSig.Tests.Fixtures;

using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

/// <summary>
/// Shared test fixture providing pre-generated self-signed RSA certificates for XML digital signature tests,
/// avoiding redundant RSA-2048 key generation per test method and ensuring deterministic disposal.
/// </summary>
public sealed class XmlSigningCertificatesFixture : IDisposable
{
    public X509Certificate2 Cert { get; }
    public X509Certificate2 PublicOnlyCert { get; }
    public RSA Rsa { get; }

    public XmlSigningCertificatesFixture()
    {
        Rsa = RSA.Create(2048);
        var req = new CertificateRequest(
            "CN=EricksonLopez Fiscal Signing, O=EricksonLopez, C=DO",
            Rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);

        var rawCert = req.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddMinutes(-5),
            DateTimeOffset.UtcNow.AddYears(1));

        // Export and import to ensure full private key binding
        var pfx = rawCert.Export(X509ContentType.Pfx);
#if NET9_0_OR_GREATER
        Cert = X509CertificateLoader.LoadPkcs12(pfx, null, X509KeyStorageFlags.Exportable);
        PublicOnlyCert = X509CertificateLoader.LoadCertificate(rawCert.RawData);
#else
#pragma warning disable SYSLIB0057
        Cert = new X509Certificate2(pfx, (string?)null, X509KeyStorageFlags.Exportable);
        PublicOnlyCert = new X509Certificate2(rawCert.RawData);
#pragma warning restore SYSLIB0057
#endif
    }

    public void Dispose()
    {
        Cert.Dispose();
        PublicOnlyCert.Dispose();
        Rsa.Dispose();
    }
}
