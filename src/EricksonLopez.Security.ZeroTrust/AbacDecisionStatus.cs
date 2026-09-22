// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.ZeroTrust;

/// <summary>
/// Represents the evaluation status result from the ABAC policy engine.
/// </summary>
public enum AbacDecisionStatus
{
    /// <summary>
    /// Specifies that access is permitted.
    /// </summary>
    Permit = 1,

    /// <summary>
    /// Specifies that access is explicitly denied.
    /// </summary>
    Deny = 2,

    /// <summary>
    /// Specifies that no policies or rules matched the target evaluation context.
    /// </summary>
    NotApplicable = 3,

    /// <summary>
    /// Specifies that an error or missing required attribute prevented evaluation.
    /// </summary>
    Indeterminate = 4
}
