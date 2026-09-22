// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Abstractions.Primitives;

using System;

/// <summary>
/// Represents immutable metadata describing a cryptographic key, its lifecycle state, and cryptographic algorithm bindings.
/// </summary>
/// <param name="KeyId">The unique key identifier.</param>
/// <param name="Version">The monotonic positive key version.</param>
/// <param name="Purpose">The exclusive authorized purpose of the key.</param>
/// <param name="Status">The lifecycle state of the key.</param>
/// <param name="AlgorithmId">The cryptographic algorithm standard identifier (e.g., "AES-256-GCM").</param>
/// <param name="CreatedAtUtc">The UTC timestamp when the key was created.</param>
/// <param name="ExpiresAtUtc">The optional UTC timestamp when the key expires.</param>
/// <param name="RevokedAtUtc">The optional UTC timestamp when the key was revoked.</param>
public sealed record KeyMetadata(
    KeyIdentifier KeyId,
    KeyVersion Version,
    KeyPurpose Purpose,
    KeyStatus Status,
    string AlgorithmId,
    DateTimeOffset CreatedAtUtc,
    DateTimeOffset? ExpiresAtUtc = null,
    DateTimeOffset? RevokedAtUtc = null)
{
    /// <summary>
    /// Determines whether the key is currently active and within its valid time window.
    /// </summary>
    /// <param name="nowUtc">The reference UTC time (defaults to UtcNow).</param>
    /// <returns><see langword="true"/> if active and not expired; otherwise, <see langword="false"/>.</returns>
    public bool IsUsableForNewOperations(DateTimeOffset? nowUtc = null)
    {
        var now = nowUtc ?? DateTimeOffset.UtcNow;
        return Status == KeyStatus.Active && (ExpiresAtUtc is null || ExpiresAtUtc.Value > now);
    }

    /// <summary>
    /// Determines whether the key is eligible for legacy decryption or verification operations.
    /// </summary>
    /// <returns><see langword="true"/> if the key is eligible for legacy decryption or verification operations; otherwise, <see langword="false"/>.</returns>
    public bool IsUsableForDecryption() => Status is KeyStatus.Active or KeyStatus.Retired;
}
