// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.WebAuthn.Fido2.Enums;

/// <summary>
/// Specifies the Relying Party's preference for attestation statement conveyance during registration.
/// </summary>
public enum AttestationConveyancePreference
{
    /// <summary>
    /// Specifies that the Relying Party does not require authenticator attestation.
    /// </summary>
    None = 1,

    /// <summary>
    /// Specifies that the Relying Party prefers verifiable, potentially anonymized attestation statements.
    /// </summary>
    Indirect = 2,

    /// <summary>
    /// Specifies that the Relying Party requests direct, unaltered attestation statements from the authenticator.
    /// </summary>
    Direct = 3,

    /// <summary>
    /// Specifies that the Relying Party requests enterprise attestation conveying device identifiers.
    /// </summary>
    Enterprise = 4
}
