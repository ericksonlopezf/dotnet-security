// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Abstractions.Events;

using System;
using EricksonLopez.Security.Abstractions.Primitives;

/// <summary>
/// Represents a high-severity security event published whenever a cryptographic key is revoked.
/// </summary>
/// <param name="EventId">Unique identifier for the security event.</param>
/// <param name="TimestampUtc">UTC timestamp when the event occurred.</param>
/// <param name="KeyId">Identifier of the cryptographic key being revoked.</param>
/// <param name="Version">Version of the key being revoked.</param>
/// <param name="Purpose">Cryptographic purpose of the revoked key.</param>
/// <param name="Reason">Explanation for why the key was revoked.</param>
/// <param name="TenantId">Optional tenant identifier associated with the key.</param>
/// <param name="ActorId">Optional identity of the actor who revoked the key.</param>
public sealed record KeyRevokedEvent(
    Guid EventId,
    DateTimeOffset TimestampUtc,
    KeyIdentifier KeyId,
    KeyVersion Version,
    KeyPurpose Purpose,
    string Reason,
    string? TenantId = null,
    string? ActorId = null) : ISecurityEvent
{
    /// <inheritdoc />
    public SecurityEventSeverity Severity => SecurityEventSeverity.High;

    /// <inheritdoc />
    public string EventType => "Security.KeyRevoked";

    /// <summary>
    /// Creates a new instance of the <see cref="KeyRevokedEvent"/> record.
    /// </summary>
    /// <param name="keyId">Identifier of the cryptographic key being revoked.</param>
    /// <param name="version">Version of the key being revoked.</param>
    /// <param name="purpose">Cryptographic purpose of the revoked key.</param>
    /// <param name="reason">Explanation for why the key was revoked.</param>
    /// <param name="tenantId">Optional tenant identifier associated with the key.</param>
    /// <param name="actorId">Optional identity of the actor who revoked the key.</param>
    /// <returns>A newly initialized <see cref="KeyRevokedEvent"/> instance.</returns>
    public static KeyRevokedEvent Create(
        KeyIdentifier keyId,
        KeyVersion version,
        KeyPurpose purpose,
        string reason,
        string? tenantId = null,
        string? actorId = null) =>
        new(Guid.NewGuid(), DateTimeOffset.UtcNow, keyId, version, purpose, reason, tenantId, actorId);
}
