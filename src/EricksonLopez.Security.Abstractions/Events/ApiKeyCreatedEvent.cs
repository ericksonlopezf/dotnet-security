// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Abstractions.Events;

using System;
using EricksonLopez.Security.Abstractions.Primitives;

/// <summary>
/// Represents a security event published whenever a new API key is issued.
/// </summary>
/// <param name="EventId">Unique identifier for the security event.</param>
/// <param name="TimestampUtc">UTC timestamp when the event occurred.</param>
/// <param name="KeyId">Identifier of the newly created API key.</param>
/// <param name="OwnerId">Identifier of the user or system that owns the API key.</param>
/// <param name="DisplayPrefix">Non-sensitive prefix for safe display in user interfaces.</param>
/// <param name="TenantId">Optional tenant identifier associated with the key.</param>
/// <param name="ActorId">Optional identity of the actor who created the key.</param>
public sealed record ApiKeyCreatedEvent(
    Guid EventId,
    DateTimeOffset TimestampUtc,
    ApiKeyId KeyId,
    string OwnerId,
    string DisplayPrefix,
    string? TenantId = null,
    string? ActorId = null) : ISecurityEvent
{
    /// <inheritdoc />
    public SecurityEventSeverity Severity => SecurityEventSeverity.Informational;

    /// <inheritdoc />
    public string EventType => "Security.ApiKeyCreated";

    /// <summary>
    /// Creates a new instance of the <see cref="ApiKeyCreatedEvent"/> record.
    /// </summary>
    /// <param name="keyId">Identifier of the newly created API key.</param>
    /// <param name="ownerId">Identifier of the user or system that owns the API key.</param>
    /// <param name="displayPrefix">Non-sensitive prefix for safe display in user interfaces.</param>
    /// <param name="tenantId">Optional tenant identifier associated with the key.</param>
    /// <param name="actorId">Optional identity of the actor who created the key.</param>
    /// <returns>A newly initialized <see cref="ApiKeyCreatedEvent"/> instance.</returns>
    public static ApiKeyCreatedEvent Create(
        ApiKeyId keyId,
        string ownerId,
        string displayPrefix,
        string? tenantId = null,
        string? actorId = null) =>
        new(Guid.NewGuid(), DateTimeOffset.UtcNow, keyId, ownerId, displayPrefix, tenantId, actorId);
}
