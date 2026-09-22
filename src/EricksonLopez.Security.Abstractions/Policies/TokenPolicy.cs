// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Abstractions.Policies;

using System;
using EricksonLopez.Result;
using EricksonLopez.Security.Abstractions.Errors;
using EricksonLopez.Security.Abstractions.Primitives;

/// <summary>
/// Defines policy rules governing minimum entropy length and lifetime limits for opaque tokens.
/// </summary>
/// <param name="MinimumByteLength">Minimum entropy byte length (defaults to 32 bytes = 256 bits).</param>
/// <param name="MaxLifetime">Maximum lifetime for issued tokens (e.g. refresh tokens, reset tokens).</param>
public sealed record TokenPolicy(
    int MinimumByteLength = 32,
    TimeSpan? MaxLifetime = null) : ISecurityPolicy<OpaqueToken>
{
    /// <summary>
    /// Gets the default token policy: 32-byte minimum entropy and 30-day maximum lifetime.
    /// </summary>
    public static readonly TokenPolicy Default = new(
        MinimumByteLength: 32,
        MaxLifetime: TimeSpan.FromDays(30));

    /// <inheritdoc />
    public Result Validate(OpaqueToken target)
    {
        if (target.IsEmpty)
        {
            return SecurityError.SecurityPolicyViolation(nameof(TokenPolicy), "Token cannot be empty.");
        }

        if (target.Length < MinimumByteLength)
        {
            return SecurityError.SecurityPolicyViolation(
                nameof(TokenPolicy),
                $"Token length ({target.Length}) is less than required minimum length ({MinimumByteLength}).");
        }

        return Result.Success();
    }
}
