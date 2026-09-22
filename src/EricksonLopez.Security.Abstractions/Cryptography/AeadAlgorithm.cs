// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Abstractions.Cryptography;


/// <summary>
/// Specifies the Authenticated Encryption with Associated Data (AEAD) algorithm.
/// </summary>
public enum AeadAlgorithm : byte
{
    /// <summary>
    /// Specifies the Advanced Encryption Standard with Galois/Counter Mode (AES-256-GCM) per NIST SP 800-38D.
    /// Uses 256-bit keys, 96-bit (12-byte) nonces, and 128-bit (16-byte) authentication tags.
    /// </summary>
    Aes256Gcm = 1,

    /// <summary>
    /// Specifies the ChaCha20 stream cipher with Poly1305 authenticator per RFC 8439.
    /// Uses 256-bit keys, 96-bit (12-byte) nonces, and 128-bit (16-byte) authentication tags.
    /// </summary>
    ChaCha20Poly1305 = 2,

    /// <summary>
    /// Specifies the HKDF-Enhanced AES-256-GCM AEAD scheme providing per-operation key isolation.
    /// </summary>
    HkdfAes256Gcm = 3
}
