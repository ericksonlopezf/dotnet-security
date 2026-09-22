// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Abstractions.Primitives;

/// <summary>
/// Specifies the lifecycle state of a cryptographic key in the key management hierarchy.
/// </summary>
public enum KeyStatus
{
    /// <summary>
    /// Specifies that the key is active and authorized for both encryption/signing and decryption/verification.
    /// </summary>
    Active = 1,

    /// <summary>
    /// Specifies that the key has been retired and is authorized only for legacy decryption and verification.
    /// </summary>
    Retired = 2,

    /// <summary>
    /// Specifies that the key has been revoked and is prohibited for all operations.
    /// </summary>
    Revoked = 3,

    /// <summary>
    /// Specifies that the key material has been securely wiped and destroyed.
    /// </summary>
    Destroyed = 4
}
