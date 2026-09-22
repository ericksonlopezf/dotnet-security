// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.WebAuthn.Fido2.Enums;

using System;
using System.Diagnostics.CodeAnalysis;

/// <summary>
/// Defines bit flags for the WebAuthn Authenticator Data byte.
/// </summary>
[Flags]
[SuppressMessage("Naming", "CA1711:Identifiers should not have incorrect suffix", Justification = "Standard W3C WebAuthn specification nomenclature.")]
public enum AuthenticatorDataFlags : byte
{
    /// <summary>
    /// Indicates that no flags are set.
    /// </summary>
    None = 0,

    /// <summary>
    /// Indicates that user presence was verified (bit 0, UP).
    /// </summary>
    UserPresent = 0x01,

    /// <summary>
    /// Reserved for future use (bit 1, RFU1).
    /// </summary>
    Reserved1 = 0x02,

    /// <summary>
    /// Indicates that user verification succeeded via PIN or biometrics (bit 2, UV).
    /// </summary>
    UserVerified = 0x04,

    /// <summary>
    /// Indicates that the credential is eligible for backup synchronization (bit 3, BE).
    /// </summary>
    BackupEligibility = 0x08,

    /// <summary>
    /// Indicates that the credential is currently backed up (bit 4, BS).
    /// </summary>
    BackupState = 0x10,

    /// <summary>
    /// Reserved for future use (bit 5, RFU2).
    /// </summary>
    Reserved2 = 0x20,

    /// <summary>
    /// Indicates that attested credential data is included in the authenticator data (bit 6, AT).
    /// </summary>
    AttestedCredentialData = 0x40,

    /// <summary>
    /// Indicates that extension data is included in the authenticator data (bit 7, ED).
    /// </summary>
    ExtensionData = 0x80
}
