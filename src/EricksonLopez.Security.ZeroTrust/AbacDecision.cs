// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.ZeroTrust;

/// <summary>
/// Represents the final evaluation decision from the ABAC policy engine.
/// </summary>
/// <param name="Status">The decision status (Permit, Deny, NotApplicable, Indeterminate).</param>
/// <param name="PolicyId">The identifier of the policy that determined the decision.</param>
/// <param name="RuleId">The identifier of the specific rule that determined the decision.</param>
/// <param name="Reason">Optional human-readable diagnostic reason explaining the decision.</param>
public readonly record struct AbacDecision(
    AbacDecisionStatus Status,
    string? PolicyId = null,
    string? RuleId = null,
    string? Reason = null)
{
    /// <summary>
    /// Gets a value indicating whether access was permitted.
    /// </summary>
    public bool IsPermitted => Status == AbacDecisionStatus.Permit;


    /// <summary>
    /// Ensures that the decision is permitted, throwing an <see cref="UnauthorizedAccessException"/> otherwise.
    /// Enforces the Secure-by-Default principle to prevent Fail-Open authorization vulnerabilities (SEC-003).
    /// </summary>
    /// <exception cref="UnauthorizedAccessException"><see cref="IsPermitted"/> is <see langword="false"/></exception>
    public void EnsurePermitted()
    {
        if (!IsPermitted)
        {
            throw new UnauthorizedAccessException(
                $"Access denied by ABAC PDP. Decision status: {Status}. " +
                $"Policy: '{PolicyId ?? "none"}', Rule: '{RuleId ?? "none"}'. Reason: {Reason ?? "No reason provided."}");
        }
    }

    /// <summary>
    /// Creates an <see cref="AbacDecision"/> indicating that access is permitted.
    /// </summary>
    /// <param name="policyId">The identifier of the policy that permitted access.</param>
    /// <param name="ruleId">The identifier of the rule that permitted access.</param>
    /// <param name="reason">An optional diagnostic message explaining the decision.</param>
    /// <returns>An <see cref="AbacDecision"/> with status <see cref="AbacDecisionStatus.Permit"/>.</returns>
    public static AbacDecision Permit(string? policyId = null, string? ruleId = null, string? reason = null) =>
        new(AbacDecisionStatus.Permit, policyId, ruleId, reason);

    /// <summary>
    /// Creates an <see cref="AbacDecision"/> indicating that access is explicitly denied.
    /// </summary>
    /// <param name="policyId">The identifier of the policy that denied access.</param>
    /// <param name="ruleId">The identifier of the rule that denied access.</param>
    /// <param name="reason">An optional diagnostic message explaining the decision.</param>
    /// <returns>An <see cref="AbacDecision"/> with status <see cref="AbacDecisionStatus.Deny"/>.</returns>
    public static AbacDecision Deny(string? policyId = null, string? ruleId = null, string? reason = null) =>
        new(AbacDecisionStatus.Deny, policyId, ruleId, reason);

    /// <summary>
    /// Creates an <see cref="AbacDecision"/> indicating that no matching policy was applicable to the context.
    /// </summary>
    /// <param name="reason">An optional diagnostic message explaining the decision.</param>
    /// <returns>An <see cref="AbacDecision"/> with status <see cref="AbacDecisionStatus.NotApplicable"/>.</returns>
    public static AbacDecision NotApplicable(string? reason = null) =>
        new(AbacDecisionStatus.NotApplicable, null, null, reason ?? "No applicable policies matched the evaluation context.");

    /// <summary>
    /// Creates an <see cref="AbacDecision"/> indicating that an evaluation error or missing attribute occurred.
    /// </summary>
    /// <param name="reason">An optional diagnostic message explaining the decision.</param>
    /// <returns>An <see cref="AbacDecision"/> with status <see cref="AbacDecisionStatus.Indeterminate"/>.</returns>
    public static AbacDecision Indeterminate(string? reason = null) =>
        new(AbacDecisionStatus.Indeterminate, null, null, reason ?? "An evaluation error or missing attribute occurred.");
}
