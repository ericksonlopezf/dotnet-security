// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Mfa;

/// <summary>
/// Specifies the cryptographic hash algorithm for TOTP code generation.
/// </summary>
public enum TotpHashAlgorithm
{
    /// <summary>
    /// Specifies HMAC-SHA1 (default standard algorithm used by most authenticator apps).
    /// </summary>
    Sha1 = 0,

    /// <summary>
    /// Specifies HMAC-SHA256 for enhanced security.
    /// </summary>
    Sha256 = 1,

    /// <summary>
    /// Specifies HMAC-SHA512 for maximum security.
    /// </summary>
    Sha512 = 2
}
