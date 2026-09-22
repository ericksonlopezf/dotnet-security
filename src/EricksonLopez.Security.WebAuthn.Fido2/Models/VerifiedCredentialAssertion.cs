// Copyright © Erickson Lopez. MIT License.

using System;

namespace EricksonLopez.Security.WebAuthn.Fido2.Models;

/// <summary>
/// Represents the validated output of a WebAuthn credential assertion (authentication) ceremony.
/// </summary>
public sealed record VerifiedCredentialAssertion
{
    /// <summary>
    /// Gets the credential identifier that authenticated.
    /// </summary>
    public byte[] CredentialId { get; init; }

    /// <summary>
    /// Gets the optional user handle returned by the authenticator.
    /// </summary>
    public byte[]? UserHandle { get; init; }

    /// <summary>
    /// Gets the updated signature counter to be persisted in storage.
    /// </summary>
    public uint UpdatedSignCount { get; init; }

    /// <summary>
    /// Gets a value indicating whether user verification (biometrics or PIN) was successfully performed.
    /// </summary>
    public bool UserVerified { get; init; }

    /// <summary>
    /// Gets a value indicating whether the credential was confirmed present via user interaction.
    /// </summary>
    public bool UserPresent { get; init; }

    /// <summary>
    /// Gets a value indicating whether the credential is confirmed backed up / passkey synced.
    /// </summary>
    public bool IsBackedUp { get; init; }

    /// <summary>
    /// Initializes a new instance of the <see cref="VerifiedCredentialAssertion"/> record with the ceremony verification results.
    /// </summary>
    /// <param name="credentialId">The binary credential identifier that authenticated.</param>
    /// <param name="updatedSignCount">The updated signature counter to be persisted in storage.</param>
    /// <param name="userVerified">A value indicating whether user verification was successfully performed.</param>
    /// <param name="userPresent">A value indicating whether the user was confirmed present.</param>
    /// <param name="isBackedUp">A value indicating whether the credential is confirmed backed up.</param>
    /// <param name="userHandle">The optional user handle returned by the authenticator.</param>
    /// <exception cref="ArgumentNullException"><paramref name="credentialId"/> is <see langword="null"/></exception>
    public VerifiedCredentialAssertion(
        byte[] credentialId,
        uint updatedSignCount,
        bool userVerified,
        bool userPresent,
        bool isBackedUp,
        byte[]? userHandle = null)
    {
        CredentialId = credentialId ?? throw new ArgumentNullException(nameof(credentialId));
        UpdatedSignCount = updatedSignCount;
        UserVerified = userVerified;
        UserPresent = userPresent;
        IsBackedUp = isBackedUp;
        UserHandle = userHandle;
    }
}
