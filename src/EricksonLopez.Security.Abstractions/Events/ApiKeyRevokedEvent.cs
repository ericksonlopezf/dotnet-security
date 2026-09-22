// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Abstractions.Events;

using System;
using EricksonLopez.Security.Abstractions.Primitives;

/// <summary>
/// Represents a security event published whenever an active API key is revoked.
/// </summary>
/// <param name="EventId">The unique event identifier.</param>
/// <param name="TimestampUtc">The UTC timestamp when the event occurred.</param>
/// <param name="KeyId">The identifier of the revoked API key.</param>
/// <param name="OwnerId">The identifier of the user or system that owns the API key.</param>
/// <param name="Reason">The reason explaining why the key was revoked.</param>
/// <param name="TenantId">The optional tenant identifier associated with the key.</param>
/// <param name="ActorId">The optional identity of the actor who revoked the key.</param>
public sealed record ApiKeyRevokedEvent(
    Guid EventId,
    DateTimeOffset TimestampUtc,
    ApiKeyId KeyId,
    string OwnerId,
    string Reason,
    string? TenantId = null,
    string? ActorId = null) : ISecurityEvent
{
    /// <inheritdoc />
    public SecurityEventSeverity Severity => SecurityEventSeverity.Warning;

    /// <inheritdoc />
    public string EventType => "Security.ApiKeyRevoked";

    /// <summary>
    /// Creates a new instance of the <see cref="ApiKeyRevokedEvent"/> record.
    /// </summary>
    /// <param name="keyId">The identifier of the revoked API key.</param>
    /// <param name="ownerId">The identifier of the user or system that owns the API key.</param>
    /// <param name="reason">The reason explaining why the key was revoked.</param>
    /// <param name="tenantId">The optional tenant identifier associated with the key.</param>
    /// <param name="actorId">The optional identity of the actor who revoked the key.</param>
    /// <returns>A newly initialized <see cref="ApiKeyRevokedEvent"/> instance.</returns>
    public static ApiKeyRevokedEvent Create(
        ApiKeyId keyId,
        string ownerId,
        string reason,
        string? tenantId = null,
        string? actorId = null) =>
        new(Guid.NewGuid(), DateTimeOffset.UtcNow, keyId, ownerId, reason, tenantId, actorId);
}
