// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Abstractions.Events;

using System;

/// <summary>
/// Defines a contract for strongly-typed, auditable security events emitted by the security subsystem.
/// Can be consumed directly by application event buses or bridged into <c>EricksonLopez.Auditing</c>.
/// </summary>
public interface ISecurityEvent
{
    /// <summary>
    /// Gets the unique identifier of the security event instance.
    /// </summary>
    Guid EventId { get; }

    /// <summary>
    /// Gets the UTC timestamp when the security event occurred.
    /// </summary>
    DateTimeOffset TimestampUtc { get; }

    /// <summary>
    /// Gets the severity rating of this security event.
    /// </summary>
    SecurityEventSeverity Severity { get; }

    /// <summary>
    /// Gets the standardized semantic name of the event type.
    /// </summary>
    string EventType { get; }

    /// <summary>
    /// Gets the optional tenant or partition identifier.
    /// </summary>
    string? TenantId { get; }

    /// <summary>
    /// Gets the actor or user ID who initiated the operation.
    /// </summary>
    string? ActorId { get; }
}
