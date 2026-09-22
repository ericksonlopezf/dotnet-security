// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.WebAuthn.Fido2.Enums;

/// <summary>
/// Specifies cryptographic signature algorithms registered in the IANA COSE Algorithms registry.
/// </summary>
public enum CoseAlgorithmIdentifier
{
    /// <summary>
    /// Specifies ECDSA with SHA-256 over the NIST P-256 curve (COSE ID -7).
    /// </summary>
    ES256 = -7,

    /// <summary>
    /// Specifies EdDSA with Ed25519 (COSE ID -8).
    /// </summary>
    EdDSA = -8,

    /// <summary>
    /// Specifies ECDSA with SHA-384 over the NIST P-384 curve (COSE ID -35).
    /// </summary>
    ES384 = -35,

    /// <summary>
    /// Specifies ECDSA with SHA-512 over the NIST P-521 curve (COSE ID -36).
    /// </summary>
    ES512 = -36,

    /// <summary>
    /// Specifies RSASSA-PSS with SHA-256 (COSE ID -37).
    /// </summary>
    PS256 = -37,

    /// <summary>
    /// Specifies RSASSA-PKCS1-v1_5 with SHA-256 (COSE ID -257).
    /// </summary>
    RS256 = -257
}
