// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Abstractions.Events;

using System;

/// <summary>
/// Represents a security event published whenever a stored secret or credential is rotated.
/// </summary>
/// <param name="EventId">Unique identifier for the security event.</param>
/// <param name="TimestampUtc">UTC timestamp when the event occurred.</param>
/// <param name="SecretName">Name or identifier of the rotated secret.</param>
/// <param name="TenantId">Optional identifier of the tenant owning the secret.</param>
/// <param name="ActorId">Optional identifier of the security principal initiating the rotation.</param>
public sealed record SecretRotatedEvent(
    Guid EventId,
    DateTimeOffset TimestampUtc,
    string SecretName,
    string? TenantId = null,
    string? ActorId = null) : ISecurityEvent
{
    /// <inheritdoc />
    public SecurityEventSeverity Severity => SecurityEventSeverity.Informational;

    /// <inheritdoc />
    public string EventType => "Security.SecretRotated";

    /// <summary>
    /// Creates a new instance of <see cref="SecretRotatedEvent"/> with an automatically generated event ID and current UTC timestamp.
    /// </summary>
    /// <param name="secretName">Name or identifier of the rotated secret.</param>
    /// <param name="tenantId">Optional identifier of the tenant owning the secret.</param>
    /// <param name="actorId">Optional identifier of the security principal initiating the rotation.</param>
    /// <returns>A newly initialized <see cref="SecretRotatedEvent"/> instance.</returns>
    public static SecretRotatedEvent Create(string secretName, string? tenantId = null, string? actorId = null) =>
        new(Guid.NewGuid(), DateTimeOffset.UtcNow, secretName, tenantId, actorId);
}
