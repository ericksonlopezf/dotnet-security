// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.WebAuthn.Fido2.Enums;

/// <summary>
/// Specifies the key type in a COSE Key structure (COSE parameter 1).
/// </summary>
public enum CoseKeyType
{
    /// <summary>
    /// Specifies an Octet Key Pair (e.g. Ed25519, X25519).
    /// </summary>
    Okp = 1,

    /// <summary>
    /// Specifies an Elliptic Curve key pair with two coordinates (x, y).
    /// </summary>
    Ec2 = 2,

    /// <summary>
    /// Specifies an RSA key pair.
    /// </summary>
    Rsa = 3
}
