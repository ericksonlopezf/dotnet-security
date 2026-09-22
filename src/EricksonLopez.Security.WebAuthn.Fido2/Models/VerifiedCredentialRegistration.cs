// Copyright © Erickson Lopez. MIT License.

using System;

namespace EricksonLopez.Security.WebAuthn.Fido2.Models;

/// <summary>
/// Represents the validated output of a WebAuthn credential registration ceremony, ready for persistence in storage.
/// </summary>
public sealed record VerifiedCredentialRegistration
{
    /// <summary>
    /// Gets the unique credential identifier.
    /// </summary>
    public byte[] CredentialId { get; init; }

    /// <summary>
    /// Gets the user handle associated with the credential.
    /// </summary>
    public byte[] UserHandle { get; init; }

    /// <summary>
    /// Gets the validated COSE public key.
    /// </summary>
    public CosePublicKey PublicKey { get; init; }

    /// <summary>
    /// Gets the initial signature counter (typically 0).
    /// </summary>
    public uint SignCount { get; init; }

    /// <summary>
    /// Gets the Authenticator Attestation GUID (AAGUID).
    /// </summary>
    public Guid Aaguid { get; init; }

    /// <summary>
    /// Gets a value indicating whether the credential is a discoverable passkey capable of multi-device synchronization.
    /// </summary>
    public bool IsBackupEligible { get; init; }

    /// <summary>
    /// Gets a value indicating whether the credential is currently synced/backed up.
    /// </summary>
    public bool IsBackedUp { get; init; }

    /// <summary>
    /// Gets the attestation format verified (e.g. "none" or "packed").
    /// </summary>
    public string AttestationFormat { get; init; }

    /// <summary>
    /// Initializes a new instance of the <see cref="VerifiedCredentialRegistration"/> record with ceremony verification results.
    /// </summary>
    /// <param name="credentialId">The unique binary credential identifier.</param>
    /// <param name="userHandle">The user handle associated with the credential.</param>
    /// <param name="publicKey">The validated COSE public key.</param>
    /// <param name="signCount">The initial signature counter.</param>
    /// <param name="aaguid">The Authenticator Attestation GUID (AAGUID).</param>
    /// <param name="isBackupEligible">A value indicating whether the credential is a discoverable passkey capable of multi-device synchronization.</param>
    /// <param name="isBackedUp">A value indicating whether the credential is currently synced/backed up.</param>
    /// <param name="attestationFormat">The verified attestation format identifier.</param>
    /// <exception cref="ArgumentNullException"><paramref name="credentialId"/>, <paramref name="userHandle"/>, <paramref name="publicKey"/>, or <paramref name="attestationFormat"/> is <see langword="null"/></exception>
    public VerifiedCredentialRegistration(
        byte[] credentialId,
        byte[] userHandle,
        CosePublicKey publicKey,
        uint signCount,
        Guid aaguid,
        bool isBackupEligible,
        bool isBackedUp,
        string attestationFormat)
    {
        CredentialId = credentialId ?? throw new ArgumentNullException(nameof(credentialId));
        UserHandle = userHandle ?? throw new ArgumentNullException(nameof(userHandle));
        PublicKey = publicKey ?? throw new ArgumentNullException(nameof(publicKey));
        SignCount = signCount;
        Aaguid = aaguid;
        IsBackupEligible = isBackupEligible;
        IsBackedUp = isBackedUp;
        AttestationFormat = attestationFormat ?? throw new ArgumentNullException(nameof(attestationFormat));
    }
}
