// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.WebAuthn.Fido2.Enums;

/// <summary>
/// Specifies the authenticators' acceptable attachment modalities.
/// </summary>
public enum AuthenticatorAttachment
{
    /// <summary>
    /// Specifies a platform authenticator attached directly to the client device (e.g. Windows Hello, Touch ID, Face ID).
    /// </summary>
    Platform = 1,

    /// <summary>
    /// Specifies a cross-platform roaming authenticator (e.g. USB security key, NFC, BLE).
    /// </summary>
    CrossPlatform = 2
}
