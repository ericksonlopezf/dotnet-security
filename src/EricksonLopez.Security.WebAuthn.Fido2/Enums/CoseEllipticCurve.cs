// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.WebAuthn.Fido2.Enums;

/// <summary>
/// Specifies elliptic curves registered in the IANA COSE Elliptic Curves registry (COSE parameter -1).
/// </summary>
public enum CoseEllipticCurve
{
    /// <summary>
    /// Specifies the NIST P-256 curve (secp256r1).
    /// </summary>
    P256 = 1,

    /// <summary>
    /// Specifies the NIST P-384 curve (secp384r1).
    /// </summary>
    P384 = 2,

    /// <summary>
    /// Specifies the NIST P-521 curve (secp521r1).
    /// </summary>
    P521 = 3,

    /// <summary>
    /// Specifies the Ed25519 curve for EdDSA.
    /// </summary>
    Ed25519 = 6
}
