// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Abstractions.Primitives;

/// <summary>
/// Specifies the exclusive cryptographic purpose for which a key is authorized.
/// Mitigates key reuse vulnerabilities across incompatible cryptographic operations.
/// </summary>
public enum KeyPurpose
{
    /// <summary>
    /// Specifies that the key is authorized exclusively for authenticated data encryption (e.g., AES-GCM).
    /// </summary>
    Encryption = 1,

    /// <summary>
    /// Specifies that the key is authorized exclusively for digital signatures and HMAC generation.
    /// </summary>
    Signing = 2,

    /// <summary>
    /// Specifies that the key is authorized exclusively for keyed cryptographic hashing and token derivation.
    /// </summary>
    Hashing = 3,

    /// <summary>
    /// Specifies that the key is authorized exclusively for protecting, generating, and validating opaque security tokens.
    /// </summary>
    TokenProtection = 4,

    /// <summary>
    /// Specifies that the key is authorized exclusively for encrypting sensitive credentials and secrets at rest.
    /// </summary>
    SecretProtection = 5,

    /// <summary>
    /// Specifies that the key is authorized exclusively for key-wrapping (encrypting other cryptographic keys).
    /// </summary>
    KeyWrapping = 6
}
