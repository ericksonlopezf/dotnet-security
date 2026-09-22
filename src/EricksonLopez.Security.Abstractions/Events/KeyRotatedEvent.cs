// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Abstractions.Events;

using System;
using EricksonLopez.Security.Abstractions.Primitives;

/// <summary>
/// Represents a security event published whenever a cryptographic key is rotated.
/// </summary>
/// <param name="EventId">Unique identifier for the security event.</param>
/// <param name="TimestampUtc">UTC timestamp when the event occurred.</param>
/// <param name="KeyId">Identifier of the rotated key.</param>
/// <param name="PreviousVersion">Version of the key prior to rotation.</param>
/// <param name="NewVersion">New active version of the key after rotation.</param>
/// <param name="Purpose">Authorized purpose of the rotated key.</param>
/// <param name="TenantId">Optional identifier of the tenant owning the key.</param>
/// <param name="ActorId">Optional identifier of the security principal initiating the rotation.</param>
public sealed record KeyRotatedEvent(
    Guid EventId,
    DateTimeOffset TimestampUtc,
    KeyIdentifier KeyId,
    KeyVersion PreviousVersion,
    KeyVersion NewVersion,
    KeyPurpose Purpose,
    string? TenantId = null,
    string? ActorId = null) : ISecurityEvent
{
    /// <inheritdoc />
    public SecurityEventSeverity Severity => SecurityEventSeverity.Informational;

    /// <inheritdoc />
    public string EventType => "Security.KeyRotated";

    /// <summary>
    /// Creates a new instance of <see cref="KeyRotatedEvent"/> with automatically generated event ID and current UTC timestamp.
    /// </summary>
    /// <param name="keyId">Identifier of the rotated key.</param>
    /// <param name="previousVersion">Version of the key prior to rotation.</param>
    /// <param name="newVersion">New active version of the key after rotation.</param>
    /// <param name="purpose">Authorized purpose of the rotated key.</param>
    /// <param name="tenantId">Optional identifier of the tenant owning the key.</param>
    /// <param name="actorId">Optional identifier of the security principal initiating the rotation.</param>
    /// <returns>A newly initialized <see cref="KeyRotatedEvent"/> instance.</returns>
    public static KeyRotatedEvent Create(
        KeyIdentifier keyId,
        KeyVersion previousVersion,
        KeyVersion newVersion,
        KeyPurpose purpose,
        string? tenantId = null,
        string? actorId = null) =>
        new(Guid.NewGuid(), DateTimeOffset.UtcNow, keyId, previousVersion, newVersion, purpose, tenantId, actorId);
}
