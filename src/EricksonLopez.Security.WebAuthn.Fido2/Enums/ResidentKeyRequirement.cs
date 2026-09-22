// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.WebAuthn.Fido2.Enums;

/// <summary>
/// Specifies the Relying Party's requirement for creating a discoverable credential (resident key / passkey).
/// </summary>
public enum ResidentKeyRequirement
{
    /// <summary>
    /// Specifies that creation of a client-side discoverable credential is discouraged.
    /// </summary>
    Discouraged = 1,

    /// <summary>
    /// Specifies that creation of a client-side discoverable credential is preferred if supported.
    /// </summary>
    Preferred = 2,

    /// <summary>
    /// Specifies that creation of a client-side discoverable credential is required (passkey mode).
    /// </summary>
    Required = 3
}
