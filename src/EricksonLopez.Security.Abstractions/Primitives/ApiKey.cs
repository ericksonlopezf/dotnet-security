// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Abstractions.Primitives;

using System;
using System.Collections.Generic;
using System.Diagnostics;

/// <summary>
/// Represents an immutable, persisted API key metadata entity without storing the plaintext secret.
/// Stores only the key identifier, display prefix, salted cryptographic hash, and access scopes.
/// </summary>
/// <param name="Id">Unique API key identifier for indexed lookup.</param>
/// <param name="OwnerId">Identifier of the owning identity or tenant.</param>
/// <param name="Name">Human-readable description or client name.</param>
/// <param name="DisplayPrefix">Safe display prefix (e.g. "ek_live_9f8a...").</param>
/// <param name="HashedSecret">Secure cryptographic hash of the secret portion.</param>
/// <param name="CreatedAtUtc">UTC creation timestamp.</param>
/// <param name="ExpiresAtUtc">Optional UTC expiration timestamp.</param>
/// <param name="RevokedAtUtc">Optional UTC revocation timestamp.</param>
/// <param name="Scopes">Authorized scope strings granted to this API key.</param>
[DebuggerDisplay("{DisplayPrefix} ({OwnerId}, Active={IsActive()})")]
public sealed record ApiKey(
    ApiKeyId Id,
    string OwnerId,
    string Name,
    string DisplayPrefix,
    string HashedSecret,
    DateTimeOffset CreatedAtUtc,
    DateTimeOffset? ExpiresAtUtc = null,
    DateTimeOffset? RevokedAtUtc = null,
    IReadOnlySet<string>? Scopes = null)
{
    /// <summary>
    /// Gets a value indicating whether this API key has been revoked.
    /// </summary>
    public bool IsRevoked => RevokedAtUtc.HasValue;

    /// <summary>
    /// Determines whether the API key is currently active, non-revoked, and within its validity window.
    /// </summary>
    /// <param name="nowUtc">Reference UTC timestamp to evaluate against, or <see langword="null"/> to use <see cref="DateTimeOffset.UtcNow"/>.</param>
    /// <returns><see langword="true"/> if valid and active; otherwise, <see langword="false"/>.</returns>
    public bool IsActive(DateTimeOffset? nowUtc = null)
    {
        var now = nowUtc ?? DateTimeOffset.UtcNow;
        if (RevokedAtUtc.HasValue)
        {
            return false;
        }

        return ExpiresAtUtc is null || ExpiresAtUtc.Value > now;
    }

    /// <summary>
    /// Determines whether the API key is authorized for a specific scope.
    /// </summary>
    /// <param name="scope">Requested scope name to evaluate.</param>
    /// <returns><see langword="true"/> if authorized; otherwise, <see langword="false"/>.</returns>
    public bool HasScope(string scope)
    {
        if (Scopes is null or { Count: 0 })
        {
            return false;
        }

        return Scopes.Contains(scope);
    }
}
