// Copyright © Erickson Lopez. MIT License.
using System;
using System.Collections.Generic;

namespace EricksonLopez.Security.ZeroTrust;

/// <summary>
/// Provides an in-memory attribute-based access control (ABAC) policy decision point (PDP) implementation.
/// </summary>
public sealed class AbacPolicyEngine : IAbacPolicyEngine
{
    /// <summary>
    /// Gets the default shared singleton instance of the <see cref="AbacPolicyEngine"/>.
    /// </summary>
    public static readonly AbacPolicyEngine Instance = new();

    /// <inheritdoc />
    public AbacDecision Evaluate(AbacContext context, IReadOnlyList<AbacPolicy> policies)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(policies);

        if (policies.Count == 0)
        {
            return AbacDecision.NotApplicable("No policies provided for evaluation.");
        }

        var atLeastOnePolicyApplicable = false;
        var atLeastOnePermit = false;
        string? permittingPolicyId = null;
        string? permittingRuleId = null;
        string? permittingReason = null;

        foreach (var policy in policies)
        {
            if (!policy.AppliesTo(context))
            {
                continue;
            }

            atLeastOnePolicyApplicable = true;
            var policyDecision = EvaluatePolicy(context, policy);

            if (policyDecision.Status == AbacDecisionStatus.Deny)
            {
                // Global Zero-Trust rule: Any Deny overrides across policies
                return policyDecision;
            }

            if (policyDecision.Status == AbacDecisionStatus.Indeterminate)
            {
                // Zero-Trust rule: Fail-closed immediately on any evaluation error or indeterminate state
                return AbacDecision.Deny(
                    policy.PolicyId,
                    policyDecision.RuleId,
                    $"Indeterminate evaluation error in policy '{policy.PolicyId}': {policyDecision.Reason}");
            }

            if (policyDecision.Status == AbacDecisionStatus.Permit)
            {
                atLeastOnePermit = true;
                permittingPolicyId = policyDecision.PolicyId;
                permittingRuleId = policyDecision.RuleId;
                permittingReason = policyDecision.Reason;
            }
        }

        if (!atLeastOnePolicyApplicable)
        {
            return AbacDecision.NotApplicable("No security policies matched the request context.");
        }

        if (atLeastOnePermit)
        {
            return AbacDecision.Permit(permittingPolicyId, permittingRuleId, permittingReason!);
        }

        return AbacDecision.Deny(null, null, "Default Deny: No policy rule explicitly permitted access.");
    }

    /// <inheritdoc />
    /// <remarks>
    /// SEC-003 fix: wraps <see cref="Evaluate"/> and converts <see cref="AbacDecisionStatus.NotApplicable"/>
    /// to <see cref="AbacDecision.Deny(string?,string?,string?)"/>. This enforces fail-closed behaviour:
    /// if no policy applies, access is denied rather than left ambiguous.
    /// </remarks>
    public AbacDecision EvaluateFailClosed(AbacContext context, IReadOnlyList<AbacPolicy> policies)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(policies);

        var decision = Evaluate(context, policies);

        if (decision.Status == AbacDecisionStatus.NotApplicable)
        {
            return AbacDecision.Deny(
                policyId: null,
                ruleId: null,
                reason: "Fail-closed: No applicable policy found for the request context. Access denied by default. " +
                        "Ensure a policy with a matching AppliesTo predicate is registered for this resource type.");
        }

        return decision;
    }

    internal static AbacDecision EvaluatePolicy(AbacContext context, AbacPolicy policy)
    {
        return policy.CombiningAlgorithm switch
        {
            AbacCombiningAlgorithm.DenyOverrides => EvaluateDenyOverrides(context, policy),
            AbacCombiningAlgorithm.PermitOverrides => EvaluatePermitOverrides(context, policy),
            AbacCombiningAlgorithm.FirstApplicable => EvaluateFirstApplicable(context, policy),
            _ => EvaluateDenyOverrides(context, policy)
        };
    }

    private static AbacDecision EvaluateDenyOverrides(AbacContext context, AbacPolicy policy)
    {
        var hasPermit = false;
        string? permitRuleId = null;
        string? permitReason = null;

        foreach (var rule in policy.Rules)
        {
            try
            {
                if (rule.Condition(context))
                {
                    if (rule.Effect == AbacEffect.Deny)
                    {
                        return AbacDecision.Deny(policy.PolicyId, rule.RuleId, rule.Description ?? "Denied by rule.");
                    }

                    if (rule.Effect == AbacEffect.Permit)
                    {
                        hasPermit = true;
                        permitRuleId = rule.RuleId;
                        permitReason = rule.Description;
                    }
                }
            }
            catch (Exception ex)
            {
                return AbacDecision.Indeterminate($"Error evaluating rule '{rule.RuleId}': {ex.Message}");
            }
        }

        if (hasPermit)
        {
            return AbacDecision.Permit(policy.PolicyId, permitRuleId, permitReason ?? "Permitted by rule.");
        }

        return AbacDecision.NotApplicable($"No rules matched within policy '{policy.PolicyId}'.");
    }

    private static AbacDecision EvaluatePermitOverrides(AbacContext context, AbacPolicy policy)
    {
        var hasDeny = false;
        string? denyRuleId = null;
        string? denyReason = null;

        foreach (var rule in policy.Rules)
        {
            try
            {
                if (rule.Condition(context))
                {
                    if (rule.Effect == AbacEffect.Permit)
                    {
                        return AbacDecision.Permit(policy.PolicyId, rule.RuleId, rule.Description ?? "Permitted by rule.");
                    }

                    if (rule.Effect == AbacEffect.Deny)
                    {
                        hasDeny = true;
                        denyRuleId = rule.RuleId;
                        denyReason = rule.Description;
                    }
                }
            }
            catch (Exception ex)
            {
                return AbacDecision.Indeterminate($"Error evaluating rule '{rule.RuleId}': {ex.Message}");
            }
        }

        if (hasDeny)
        {
            return AbacDecision.Deny(policy.PolicyId, denyRuleId, denyReason ?? "Denied by rule.");
        }

        return AbacDecision.NotApplicable($"No rules matched within policy '{policy.PolicyId}'.");
    }

    private static AbacDecision EvaluateFirstApplicable(AbacContext context, AbacPolicy policy)
    {
        foreach (var rule in policy.Rules)
        {
            try
            {
                if (rule.Condition(context))
                {
                    return rule.Effect == AbacEffect.Permit
                        ? AbacDecision.Permit(policy.PolicyId, rule.RuleId, rule.Description ?? "Permitted by first applicable rule.")
                        : AbacDecision.Deny(policy.PolicyId, rule.RuleId, rule.Description ?? "Denied by first applicable rule.");
                }
            }
            catch (Exception ex)
            {
                return AbacDecision.Indeterminate($"Error evaluating rule '{rule.RuleId}': {ex.Message}");
            }
        }

        return AbacDecision.NotApplicable($"No rules matched within policy '{policy.PolicyId}'.");
    }
}
