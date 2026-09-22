// Copyright © Erickson Lopez. MIT License.
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;

namespace EricksonLopez.Security.Pki;

/// <summary>
/// Specifies configuration options for X.509 certificate chain validation and revocation verification.
/// </summary>
public sealed class CertificateValidationOptions
{
    /// <summary>
    /// Gets or sets the revocation checking mode. Default is <see cref="X509RevocationMode.Online"/> (secure-by-default).
    /// </summary>
    public X509RevocationMode RevocationMode { get; set; } = X509RevocationMode.Online;

    /// <summary>
    /// Gets or sets the revocation flag specifying whether to check revocation for the entire chain or end-entity only.
    /// Default is <see cref="X509RevocationFlag.EntireChain"/> (secure-by-default to verify all intermediate CAs).
    /// </summary>
    public X509RevocationFlag RevocationFlag { get; set; } = X509RevocationFlag.EntireChain;

    /// <summary>
    /// Gets or sets a collection of custom trusted root CA certificates.
    /// </summary>
    public IList<X509Certificate2> CustomTrustAnchors { get; set; } = new List<X509Certificate2>();

    /// <summary>
    /// Gets or sets an optional expected host name (FQDN) to validate against the certificate's Subject Alternative Names (SAN) or Subject Common Name.
    /// </summary>
    public string? ExpectedHostName { get; set; }

    /// <summary>
    /// Gets or sets an optional required Extended Key Usage (EKU) OID (e.g. "1.3.6.1.5.5.7.3.1" for Server Authentication).
    /// </summary>
    public string? RequiredExtendedKeyUsageOid { get; set; }
}
