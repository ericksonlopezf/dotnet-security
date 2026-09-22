// Copyright © Erickson Lopez. MIT License.

using System;
using EricksonLopez.Security.WebAuthn.Fido2.Enums;

namespace EricksonLopez.Security.WebAuthn.Fido2.Models;

/// <summary>
/// Represents the parsed WebAuthn Authenticator Data structure.
/// </summary>
public sealed record AuthenticatorData
{
    /// <summary>
    /// Gets the SHA-256 hash of the Relying Party ID (32 bytes).
    /// </summary>
    public byte[] RpIdHash { get; init; }

    /// <summary>
    /// Gets the bit flags (UserPresent, UserVerified, AttestedCredentialData, etc.).
    /// </summary>
    public AuthenticatorDataFlags Flags { get; init; }

    /// <summary>
    /// Gets the signature counter (32-bit big-endian integer, detecting cloned authenticators).
    /// </summary>
    public uint SignCount { get; init; }

    /// <summary>
    /// Gets the attested credential data, present if <see cref="AuthenticatorDataFlags.AttestedCredentialData"/> flag is set.
    /// </summary>
    public AttestedCredentialData? AttestedCredentialData { get; init; }

    /// <summary>
    /// Gets the raw extension data bytes, present if <see cref="AuthenticatorDataFlags.ExtensionData"/> flag is set.
    /// </summary>
    public byte[]? ExtensionData { get; init; }

    /// <summary>
    /// Gets the raw binary representation of the Authenticator Data.
    /// </summary>
    public byte[] RawBytes { get; init; }

    /// <summary>
    /// Gets a value indicating whether the User Present (UP) bit was set.
    /// </summary>
    public bool UserPresent => Flags.HasFlag(AuthenticatorDataFlags.UserPresent);

    /// <summary>
    /// Gets a value indicating whether the User Verified (UV) bit was set.
    /// </summary>
    public bool UserVerified => Flags.HasFlag(AuthenticatorDataFlags.UserVerified);

    /// <summary>
    /// Gets a value indicating whether the Backup Eligibility (BE) bit was set (passkey capability).
    /// </summary>
    public bool BackupEligibility => Flags.HasFlag(AuthenticatorDataFlags.BackupEligibility);

    /// <summary>
    /// Gets a value indicating whether the Backup State (BS) bit was set (synced passkey).
    /// </summary>
    public bool BackupState => Flags.HasFlag(AuthenticatorDataFlags.BackupState);

    /// <summary>
    /// Initializes a new instance of the <see cref="AuthenticatorData"/> record with parsed flags, counter, and optional payload data.
    /// </summary>
    /// <param name="rpIdHash">The SHA-256 hash of the Relying Party ID.</param>
    /// <param name="flags">The authenticator data bit flags.</param>
    /// <param name="signCount">The signature counter value.</param>
    /// <param name="rawBytes">The raw binary bytes of the authenticator data.</param>
    /// <param name="attestedCredentialData">The optional attested credential data.</param>
    /// <param name="extensionData">The optional raw extension data bytes.</param>
    /// <exception cref="ArgumentNullException"><paramref name="rpIdHash"/> or <paramref name="rawBytes"/> is <see langword="null"/></exception>
    public AuthenticatorData(
        byte[] rpIdHash,
        AuthenticatorDataFlags flags,
        uint signCount,
        byte[] rawBytes,
        AttestedCredentialData? attestedCredentialData = null,
        byte[]? extensionData = null)
    {
        RpIdHash = rpIdHash ?? throw new ArgumentNullException(nameof(rpIdHash));
        Flags = flags;
        SignCount = signCount;
        RawBytes = rawBytes ?? throw new ArgumentNullException(nameof(rawBytes));
        AttestedCredentialData = attestedCredentialData;
        ExtensionData = extensionData;
    }
}
