// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.WebAuthn.Fido2.Mds3;

/// <summary>
/// Specifies FIDO Alliance authenticator status values defined by the FIDO Metadata Service.
/// </summary>
public enum AuthenticatorStatus
{
    /// <summary>Specifies that the authenticator is not yet FIDO certified.</summary>
    NotFidoCertified = 0,

    /// <summary>Specifies that the authenticator is FIDO certified at level 1.</summary>
    FidoCertified = 1,

    /// <summary>Specifies that a user verification bypass vulnerability has been identified.</summary>
    UserVerificationBypass = 2,

    /// <summary>Specifies that an attestation key compromise has been identified.</summary>
    AttestationKeyCompromise = 3,

    /// <summary>Specifies that a remote user key compromise has been identified.</summary>
    UserKeyRemoteCompromise = 4,

    /// <summary>Specifies that a physical compromise of the authenticator has been identified.</summary>
    UserKeyPhysicalCompromise = 5,

    /// <summary>Specifies that a non-urgent software or firmware update is available.</summary>
    UpdateAvailable = 6,

    /// <summary>Specifies that the device has been revoked by the vendor or FIDO Alliance.</summary>
    Revoked = 7,

    /// <summary>Specifies that this authenticator self-reported using a known-invalid attestation key.</summary>
    SelfAssertionSubmitted = 8,

    /// <summary>Specifies that the authenticator is FIDO certified at level 1+.</summary>
    FidoCertifiedL1Plus = 9,

    /// <summary>Specifies that the authenticator is FIDO certified at level 2.</summary>
    FidoCertifiedL2 = 10,

    /// <summary>Specifies that the authenticator is FIDO certified at level 2+.</summary>
    FidoCertifiedL2Plus = 11,

    /// <summary>Specifies that the authenticator is FIDO certified at level 3.</summary>
    FidoCertifiedL3 = 12,

    /// <summary>Specifies that the authenticator is FIDO certified at level 3+.</summary>
    FidoCertifiedL3Plus = 13,
}
