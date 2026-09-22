// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.WebAuthn.Fido2.Enums;

/// <summary>
/// Specifies the Relying Party's requirements for user verification during WebAuthn ceremonies.
/// </summary>
public enum UserVerificationRequirement
{
    /// <summary>
    /// Specifies that user verification is preferred but the operation will not fail if omitted.
    /// </summary>
    Preferred = 1,

    /// <summary>
    /// Specifies that user verification is strictly required (e.g. PIN or Biometrics). Ceremony fails if omitted.
    /// </summary>
    Required = 2,

    /// <summary>
    /// Specifies that user verification is discouraged to minimize user friction.
    /// </summary>
    Discouraged = 3
}
