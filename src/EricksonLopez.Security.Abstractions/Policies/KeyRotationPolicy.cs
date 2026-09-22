// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Abstractions.Policies;

using System;
using EricksonLopez.Result;
using EricksonLopez.Security.Abstractions.Cryptography;
using EricksonLopez.Security.Abstractions.Errors;
using EricksonLopez.Security.Abstractions.Primitives;

/// <summary>
/// Defines policy rules governing automated cryptographic key rotation schedules, grace periods, and algorithms.
/// </summary>
/// <param name="RotationInterval">Maximum duration a key remains active before requiring rotation (defaults to 90 days).</param>
/// <param name="RetirementGracePeriod">Duration a retired key remains available for legacy decryption before archival (defaults to 365 days).</param>
/// <param name="PreferredAlgorithm">The preferred AEAD algorithm for newly generated keys.</param>
public sealed record KeyRotationPolicy(
    TimeSpan RotationInterval,
    TimeSpan RetirementGracePeriod,
    AeadAlgorithm PreferredAlgorithm = AeadAlgorithm.Aes256Gcm) : ISecurityPolicy<KeyMetadata>
{
    /// <summary>
    /// Gets the default enterprise key rotation policy (90 days rotation, 365 days legacy decryption grace).
    /// </summary>
    public static readonly KeyRotationPolicy Default = new(
        RotationInterval: TimeSpan.FromDays(90),
        RetirementGracePeriod: TimeSpan.FromDays(365),
        PreferredAlgorithm: AeadAlgorithm.Aes256Gcm);

    /// <inheritdoc />
    public Result Validate(KeyMetadata target) => Validate(target, null);

    /// <summary>
    /// Validates the key rotation policy against key metadata using a specified reference UTC time.
    /// </summary>
    /// <param name="target">The key metadata to evaluate.</param>
    /// <param name="nowUtc">The reference UTC time (defaults to UtcNow).</param>
    /// <returns>A <see cref="Result"/> indicating pass or policy violation.</returns>
    public Result Validate(KeyMetadata target, DateTimeOffset? nowUtc)
    {
        if (target is null)
        {
            return SecurityError.SecurityPolicyViolation(nameof(KeyRotationPolicy), "Key metadata cannot be null.");
        }

        if (target.Status == KeyStatus.Active)
        {
            var now = nowUtc ?? DateTimeOffset.UtcNow;
            var age = now - target.CreatedAtUtc;
            if (age > RotationInterval)
            {
                return SecurityError.SecurityPolicyViolation(
                    nameof(KeyRotationPolicy),
                    $"Key '{target.KeyId}:{target.Version}' age ({age.TotalDays:F1} days) exceeds rotation interval ({RotationInterval.TotalDays:F1} days). Key rotation required.");
            }
        }

        return Result.Success();
    }
}
