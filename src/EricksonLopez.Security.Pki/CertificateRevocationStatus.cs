// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Pki;

/// <summary>
/// Specifies the revocation status of an X.509 digital certificate.
/// </summary>
public enum CertificateRevocationStatus
{
    /// <summary>
    /// Indicates that the certificate is verified as valid and not revoked.
    /// </summary>
    Valid = 0,

    /// <summary>
    /// Indicates that the certificate has been revoked by the issuing Certificate Authority.
    /// </summary>
    Revoked = 1,

    /// <summary>
    /// Indicates that the certificate revocation status cannot be determined due to network or accessibility issues.
    /// </summary>
    Unknown = 2
}
