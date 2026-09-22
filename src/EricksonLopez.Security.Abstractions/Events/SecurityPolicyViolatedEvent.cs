// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Abstractions.Events;

using System;

/// <summary>
/// Represents a security event emitted whenever a security policy rule is violated.
/// </summary>
/// <param name="EventId">Unique identifier for the security event.</param>
/// <param name="TimestampUtc">UTC timestamp when the event occurred.</param>
/// <param name="PolicyName">Name of the violated security policy.</param>
/// <param name="ViolationDetails">Detailed diagnostic information describing the policy violation.</param>
/// <param name="TargetResource">Optional resource identifier targeted by the violating action.</param>
/// <param name="TenantId">Optional identifier of the tenant context.</param>
/// <param name="ActorId">Optional identifier of the security principal associated with the violation.</param>
public sealed record SecurityPolicyViolatedEvent(
    Guid EventId,
    DateTimeOffset TimestampUtc,
    string PolicyName,
    string ViolationDetails,
    string? TargetResource = null,
    string? TenantId = null,
    string? ActorId = null) : ISecurityEvent
{
    /// <inheritdoc />
    public SecurityEventSeverity Severity => SecurityEventSeverity.Warning;

    /// <inheritdoc />
    public string EventType => "Security.PolicyViolated";

    /// <summary>
    /// Creates a new instance of <see cref="SecurityPolicyViolatedEvent"/> with an automatically generated event ID and current UTC timestamp.
    /// </summary>
    /// <param name="policyName">Name of the violated security policy.</param>
    /// <param name="violationDetails">Detailed diagnostic information describing the policy violation.</param>
    /// <param name="targetResource">Optional resource identifier targeted by the violating action.</param>
    /// <param name="tenantId">Optional identifier of the tenant context.</param>
    /// <param name="actorId">Optional identifier of the security principal associated with the violation.</param>
    /// <returns>A newly initialized <see cref="SecurityPolicyViolatedEvent"/> instance.</returns>
    public static SecurityPolicyViolatedEvent Create(
        string policyName,
        string violationDetails,
        string? targetResource = null,
        string? tenantId = null,
        string? actorId = null) =>
        new(Guid.NewGuid(), DateTimeOffset.UtcNow, policyName, violationDetails, targetResource, tenantId, actorId);
}
