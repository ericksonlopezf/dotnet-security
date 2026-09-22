// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Abstractions.Policies;

using System;
using EricksonLopez.Result;
using EricksonLopez.Security.Abstractions.Errors;
using EricksonLopez.Security.Abstractions.Primitives;

/// <summary>
/// Defines policy rules governing API key issuance constraints, entropy length, prefix formats, and maximum lifetime.
/// </summary>
/// <param name="SecretByteLength">Entropy byte length for the secret component (min 24 bytes = 192 bits).</param>
/// <param name="MaxLifetime">Maximum permitted lifetime for an issued API key (defaults to 365 days).</param>
/// <param name="RequireExpiration">Specifies a value indicating whether API keys must have an explicit expiration date.</param>
public sealed record ApiKeyPolicy(
    int SecretByteLength = 32,
    TimeSpan? MaxLifetime = null,
    bool RequireExpiration = true) : ISecurityPolicy<ApiKey>
{
    /// <summary>
    /// Gets the default API key policy: 32 bytes of secret entropy, 365-day maximum lifetime, and mandatory expiration.
    /// </summary>
    public static readonly ApiKeyPolicy Default = new(
        SecretByteLength: 32,
        MaxLifetime: TimeSpan.FromDays(365),
        RequireExpiration: true);

    /// <inheritdoc />
    public Result Validate(ApiKey target)
    {
        if (target is null)
        {
            return SecurityError.SecurityPolicyViolation(nameof(ApiKeyPolicy), "API key cannot be null.");
        }

        if (RequireExpiration && !target.ExpiresAtUtc.HasValue)
        {
            return SecurityError.SecurityPolicyViolation(nameof(ApiKeyPolicy), "API key must define an expiration date.");
        }

        if (MaxLifetime.HasValue && target.ExpiresAtUtc.HasValue)
        {
            var lifetime = target.ExpiresAtUtc.Value - target.CreatedAtUtc;
            if (lifetime > MaxLifetime.Value)
            {
                return SecurityError.SecurityPolicyViolation(
                    nameof(ApiKeyPolicy),
                    $"API key lifetime ({lifetime.TotalDays:F1} days) exceeds maximum allowed ({MaxLifetime.Value.TotalDays:F1} days).");
            }
        }

        return Result.Success();
    }
}
