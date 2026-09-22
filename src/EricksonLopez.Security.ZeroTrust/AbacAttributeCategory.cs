// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.ZeroTrust;

/// <summary>
/// Defines standard category constants for ABAC attributes.
/// </summary>
public static class AbacAttributeCategory
{
    /// <summary>
    /// Represents the attribute category for the requesting subject (e.g., UserId, Roles, Department, TenantId, ClearanceLevel).
    /// </summary>
    public const string Subject = "Subject";

    /// <summary>
    /// Represents the attribute category for the target resource (e.g., ResourceType, ResourceId, Classification, OwnerId, Status).
    /// </summary>
    public const string Resource = "Resource";

    /// <summary>
    /// Represents the attribute category for the requested action (e.g., Read, Write, Delete, Approve, Sign, Export).
    /// </summary>
    public const string Action = "Action";

    /// <summary>
    /// Represents the attribute category for the contextual environment (e.g., RequestTime, IpAddress, DeviceTrustLevel, Location).
    /// </summary>
    public const string Environment = "Environment";
}
