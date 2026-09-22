// Copyright © Erickson Lopez. MIT License.
using System.Security.Cryptography.X509Certificates;
using EricksonLopez.Result;

namespace EricksonLopez.Security.Pki;

/// <summary>
/// Defines certificate chain verification and trust anchor evaluation.
/// </summary>
public interface ICertificateChainValidator
{
    /// <summary>
    /// Validates an X.509 certificate against the system or custom trust anchors and revocation rules.
    /// </summary>
    /// <param name="certificate">The certificate to validate.</param>
    /// <param name="options">Optional validation options.</param>
    /// <returns>A successful result if the certificate and its chain are valid; otherwise, a security error.</returns>
    Result<bool> ValidateCertificate(X509Certificate2 certificate, CertificateValidationOptions? options = null);
}
