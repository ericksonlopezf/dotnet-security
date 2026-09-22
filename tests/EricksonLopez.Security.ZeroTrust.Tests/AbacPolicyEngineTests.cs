// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.ZeroTrust.Tests;

using System;
using System.Collections.Generic;
using AwesomeAssertions;
using Xunit;

public sealed class AbacPolicyEngineTests
{
    [Fact]
    public void Evaluate_NullArgumentsAndEmptyPolicies_ReturnsExpected()
    {
        var context = new AbacContext();
        var policy = new AbacPolicy("P1", [AbacRule.PermitIf("R1", _ => true)]);

        Assert.Throws<ArgumentNullException>("context", () => AbacPolicyEngine.Instance.Evaluate(null!, []));
        Assert.Throws<ArgumentNullException>("context", () => AbacPolicyEngine.Instance.Evaluate(null!, [policy]));
        Assert.Throws<ArgumentNullException>("policies", () => AbacPolicyEngine.Instance.Evaluate(context, null!));

        var emptyDecision = AbacPolicyEngine.Instance.Evaluate(context, []);
        emptyDecision.Status.Should().Be(AbacDecisionStatus.NotApplicable);
        emptyDecision.Reason.Should().Be("No policies provided for evaluation.");
    }

    [Fact]
    public void Evaluate_DenyOverrides_DeniesWhenAnyRuleDenies()
    {
        var policy = new AbacPolicy(
            "FinancePolicy",
            rules:
            [
                AbacRule.PermitIf("Rule-Permit-Role", ctx => ctx.Get<string>(AbacAttributeCategory.Subject, "Role") == "Manager", "Manager role permit"),
                AbacRule.DenyIf("Rule-Deny-OutsideHours", ctx => ctx.Get<bool>(AbacAttributeCategory.Environment, "IsAfterHours"), "Outside business hours")
            ],
            combiningAlgorithm: AbacCombiningAlgorithm.DenyOverrides);

        var contextDeny = new AbacContext()
            .WithSubject("Role", "Manager")
            .WithEnvironment("IsAfterHours", true);

        var decisionDeny = AbacPolicyEngine.Instance.Evaluate(contextDeny, [policy]);
        decisionDeny.Status.Should().Be(AbacDecisionStatus.Deny);
        decisionDeny.IsPermitted.Should().BeFalse();
        decisionDeny.PolicyId.Should().Be("FinancePolicy");
        decisionDeny.RuleId.Should().Be("Rule-Deny-OutsideHours");
        decisionDeny.Reason.Should().Be("Outside business hours");

        // When not after hours -> Permit
        var contextPermit = new AbacContext()
            .WithSubject("Role", "Manager")
            .WithEnvironment("IsAfterHours", false);

        var decisionPermit = AbacPolicyEngine.Instance.Evaluate(contextPermit, [policy]);
        decisionPermit.IsPermitted.Should().BeTrue();
        decisionPermit.PolicyId.Should().Be("FinancePolicy");
        decisionPermit.RuleId.Should().Be("Rule-Permit-Role");
        decisionPermit.Reason.Should().Be("Manager role permit");

        // When no rules match -> Default deny at engine level
        var contextNoMatch = new AbacContext()
            .WithSubject("Role", "Guest")
            .WithEnvironment("IsAfterHours", false);

        var decisionNoMatch = AbacPolicyEngine.Instance.Evaluate(contextNoMatch, [policy]);
        decisionNoMatch.Status.Should().Be(AbacDecisionStatus.Deny);
        decisionNoMatch.IsPermitted.Should().BeFalse();
        decisionNoMatch.Reason.Should().Contain("Default Deny");

        // Rule without description falls back to "Permitted by rule."
        var policyNoDesc = new AbacPolicy("PNoDesc", [AbacRule.PermitIf("RNoDesc", _ => true)], AbacCombiningAlgorithm.DenyOverrides);
        var decisionNoDesc = AbacPolicyEngine.Instance.Evaluate(contextPermit, [policyNoDesc]);
        decisionNoDesc.IsPermitted.Should().BeTrue();
        decisionNoDesc.Reason.Should().Be("Permitted by rule.");
    }

    [Fact]
    public void Evaluate_PermitOverrides_PermitsWhenAnyRulePermits()
    {
        var policy = new AbacPolicy(
            "EmergencyPolicy",
            rules:
            [
                AbacRule.DenyIf("Rule-Deny-Default", _ => true, "Default Deny Rule"),
                AbacRule.PermitIf("Rule-Permit-Emergency", ctx => ctx.Get<bool>(AbacAttributeCategory.Environment, "IsEmergency"), "Emergency override")
            ],
            combiningAlgorithm: AbacCombiningAlgorithm.PermitOverrides);

        var contextPermit = new AbacContext().WithEnvironment("IsEmergency", true);
        var decisionPermit = AbacPolicyEngine.Instance.Evaluate(contextPermit, [policy]);
        decisionPermit.IsPermitted.Should().BeTrue();
        decisionPermit.PolicyId.Should().Be("EmergencyPolicy");
        decisionPermit.RuleId.Should().Be("Rule-Permit-Emergency");
        decisionPermit.Reason.Should().Be("Emergency override");

        // When emergency is false -> Deny from Rule-Deny-Default
        var contextDeny = new AbacContext().WithEnvironment("IsEmergency", false);
        var decisionDeny = AbacPolicyEngine.Instance.Evaluate(contextDeny, [policy]);
        decisionDeny.Status.Should().Be(AbacDecisionStatus.Deny);
        decisionDeny.IsPermitted.Should().BeFalse();
        decisionDeny.RuleId.Should().Be("Rule-Deny-Default");
        decisionDeny.Reason.Should().Be("Default Deny Rule");

        // When policy has no matching rules combined with another permitting policy
        var policyNoRules = new AbacPolicy("EmptyPermitPolicy", [AbacRule.DenyIf("R-False", _ => false)], AbacCombiningAlgorithm.PermitOverrides);
        var policyWorking = new AbacPolicy("WorkingPolicy", [AbacRule.PermitIf("R-Permit", _ => true, "Permitted by working policy")]);
        var decisionCombined = AbacPolicyEngine.Instance.Evaluate(contextPermit, [policyNoRules, policyWorking]);
        decisionCombined.IsPermitted.Should().BeTrue();
        decisionCombined.Reason.Should().Be("Permitted by working policy");
    }

    [Fact]
    public void Evaluate_FirstApplicable_ResolvesOnFirstMatchingRule()
    {
        var policy = new AbacPolicy(
            "TieredPolicy",
            rules:
            [
                AbacRule.PermitIf("Rule-1-Admin", ctx => ctx.Get<string>(AbacAttributeCategory.Subject, "Role") == "Admin", "Admin access granted"),
                AbacRule.DenyIf("Rule-2-EveryoneElse", _ => true, "Denied access")
            ],
            combiningAlgorithm: AbacCombiningAlgorithm.FirstApplicable);

        var adminContext = new AbacContext().WithSubject("Role", "Admin");
        var userContext = new AbacContext().WithSubject("Role", "User");

        var adminDecision = AbacPolicyEngine.Instance.Evaluate(adminContext, [policy]);
        var userDecision = AbacPolicyEngine.Instance.Evaluate(userContext, [policy]);

        adminDecision.IsPermitted.Should().BeTrue();
        adminDecision.RuleId.Should().Be("Rule-1-Admin");
        adminDecision.Reason.Should().Be("Admin access granted");

        userDecision.Status.Should().Be(AbacDecisionStatus.Deny);
        userDecision.IsPermitted.Should().BeFalse();
        userDecision.RuleId.Should().Be("Rule-2-EveryoneElse");
        userDecision.Reason.Should().Be("Denied access");

        // When no rules match
        var policyNoMatch = new AbacPolicy("NoMatchFirst", [AbacRule.PermitIf("R1", _ => false)], AbacCombiningAlgorithm.FirstApplicable);
        var decisionNoMatch = AbacPolicyEngine.Instance.Evaluate(adminContext, [policyNoMatch]);
        decisionNoMatch.Status.Should().Be(AbacDecisionStatus.Deny);
        decisionNoMatch.IsPermitted.Should().BeFalse();
    }

    [Fact]
    public void Evaluate_RuleException_ReturnsIndeterminate_AndPreventsSubsequentPermits()
    {
        var throwingRule = new AbacRule("FaultyRule", AbacEffect.Permit, _ => throw new InvalidOperationException("DB Down"));
        var subsequentPermitRule = AbacRule.PermitIf("SubsequentPermit", _ => true);

        var policyDeny = new AbacPolicy("P1", [throwingRule, subsequentPermitRule], AbacCombiningAlgorithm.DenyOverrides);
        var policyPermit = new AbacPolicy("P2", [throwingRule, subsequentPermitRule], AbacCombiningAlgorithm.PermitOverrides);
        var policyFirst = new AbacPolicy("P3", [throwingRule, subsequentPermitRule], AbacCombiningAlgorithm.FirstApplicable);

        var context = new AbacContext();

        // Direct policy evaluations returning Indeterminate, preventing subsequentPermitRule from granting access
        var decDeny = AbacPolicyEngine.Instance.Evaluate(context, [policyDeny]);
        decDeny.Status.Should().Be(AbacDecisionStatus.Deny);
        decDeny.IsPermitted.Should().BeFalse();
        decDeny.Reason.Should().Contain("DB Down");

        var decPermit = AbacPolicyEngine.Instance.Evaluate(context, [policyPermit]);
        decPermit.Status.Should().Be(AbacDecisionStatus.Deny);
        decPermit.IsPermitted.Should().BeFalse();
        decPermit.Reason.Should().Contain("DB Down");

        var decFirst = AbacPolicyEngine.Instance.Evaluate(context, [policyFirst]);
        decFirst.Status.Should().Be(AbacDecisionStatus.Deny);
        decFirst.IsPermitted.Should().BeFalse();
        decFirst.Reason.Should().Contain("DB Down");
    }

    [Fact]
    public void Evaluate_NonMatchingTarget_ReturnsNotApplicable()
    {
        var policy = new AbacPolicy(
            "HrPolicyOnly",
            rules: [AbacRule.PermitIf("Rule-Permit", _ => true)],
            target: ctx => ctx.TryGet<string>(AbacAttributeCategory.Resource, "Type", out var type) && type == "Payroll");

        var context = new AbacContext().WithResource("Type", "Inventory");

        var decision = AbacPolicyEngine.Instance.Evaluate(context, [policy]);
        decision.Status.Should().Be(AbacDecisionStatus.NotApplicable);
        decision.Reason.Should().Be("No security policies matched the request context.");
    }

    [Fact]
    public void Evaluate_CrossPolicyDeny_ImmediatelyOverridesPermits()
    {
        var policyPermit = new AbacPolicy("P-Permit", [AbacRule.PermitIf("R1", _ => true)]);
        var policyDeny = new AbacPolicy("P-Deny", [AbacRule.DenyIf("R2", _ => true, "Security lockdown")]);

        var context = new AbacContext();

        var decision = AbacPolicyEngine.Instance.Evaluate(context, [policyPermit, policyDeny]);
        decision.Status.Should().Be(AbacDecisionStatus.Deny);
        decision.IsPermitted.Should().BeFalse();
        decision.PolicyId.Should().Be("P-Deny");
        decision.RuleId.Should().Be("R2");
    }

    [Fact]
    public void Evaluate_RulesWithNullDescription_UseFallbackReasonStrings()
    {
        var context = new AbacContext();

        // DenyOverrides with null description
        var policyDeny = new AbacPolicy("P1", [AbacRule.DenyIf("R1", _ => true, null)], AbacCombiningAlgorithm.DenyOverrides);
        var decDeny = AbacPolicyEngine.Instance.Evaluate(context, [policyDeny]);
        decDeny.Reason.Should().Be("Denied by rule.");

        // PermitOverrides with null description
        var policyPermit = new AbacPolicy("P2", [AbacRule.PermitIf("R2", _ => true, null)], AbacCombiningAlgorithm.PermitOverrides);
        var decPermit = AbacPolicyEngine.Instance.Evaluate(context, [policyPermit]);
        decPermit.Reason.Should().Be("Permitted by rule.");

        // PermitOverrides deny with null description
        var policyPermitDeny = new AbacPolicy("P2Deny", [AbacRule.DenyIf("R2D", _ => true, null)], AbacCombiningAlgorithm.PermitOverrides);
        var decPermitDeny = AbacPolicyEngine.Instance.Evaluate(context, [policyPermitDeny]);
        decPermitDeny.Reason.Should().Be("Denied by rule.");

        // FirstApplicable permit with null description
        var policyFirstPermit = new AbacPolicy("P3", [AbacRule.PermitIf("R3", _ => true, null)], AbacCombiningAlgorithm.FirstApplicable);
        var decFirstPermit = AbacPolicyEngine.Instance.Evaluate(context, [policyFirstPermit]);
        decFirstPermit.Reason.Should().Be("Permitted by first applicable rule.");

        // FirstApplicable deny with null description
        var policyFirstDeny = new AbacPolicy("P4", [AbacRule.DenyIf("R4", _ => true, null)], AbacCombiningAlgorithm.FirstApplicable);
        var decFirstDeny = AbacPolicyEngine.Instance.Evaluate(context, [policyFirstDeny]);
        decFirstDeny.Reason.Should().Be("Denied by first applicable rule.");
    }

    [Fact]
    public void Evaluate_UnknownCombiningAlgorithm_DefaultsToDenyOverrides()
    {
        var context = new AbacContext();
        var policy = new AbacPolicy("P-Unknown", [AbacRule.PermitIf("R1", _ => true, "Permitted")], (AbacCombiningAlgorithm)999);
        var decision = AbacPolicyEngine.Instance.Evaluate(context, [policy]);
        decision.IsPermitted.Should().BeTrue();
        decision.Reason.Should().Be("Permitted");
    }

    [Fact]
    public void EvaluatePolicy_DenyOverrides_DiagnosticMessages_MatchExactly()
    {
        var context = new AbacContext();
        var throwingRule = new AbacRule("FaultyRule", AbacEffect.Permit, _ => throw new InvalidOperationException("DB Down"));
        var policyThrowing = new AbacPolicy("P-Throw", [throwingRule], AbacCombiningAlgorithm.DenyOverrides);

        var decisionThrow = AbacPolicyEngine.EvaluatePolicy(context, policyThrowing);
        decisionThrow.Status.Should().Be(AbacDecisionStatus.Indeterminate);
        decisionThrow.Reason.Should().Be("Error evaluating rule 'FaultyRule': DB Down");

        var policyNoMatch = new AbacPolicy("P-NoMatch", [AbacRule.PermitIf("R1", _ => false)], AbacCombiningAlgorithm.DenyOverrides);
        var decisionNoMatch = AbacPolicyEngine.EvaluatePolicy(context, policyNoMatch);
        decisionNoMatch.Status.Should().Be(AbacDecisionStatus.NotApplicable);
        decisionNoMatch.Reason.Should().Be("No rules matched within policy 'P-NoMatch'.");
    }

    [Fact]
    public void EvaluatePolicy_PermitOverrides_DiagnosticMessages_MatchExactly()
    {
        var context = new AbacContext();
        var throwingRule = new AbacRule("FaultyRule", AbacEffect.Permit, _ => throw new InvalidOperationException("DB Down"));
        var policyThrowing = new AbacPolicy("P-Throw", [throwingRule], AbacCombiningAlgorithm.PermitOverrides);

        var decisionThrow = AbacPolicyEngine.EvaluatePolicy(context, policyThrowing);
        decisionThrow.Status.Should().Be(AbacDecisionStatus.Indeterminate);
        decisionThrow.Reason.Should().Be("Error evaluating rule 'FaultyRule': DB Down");

        var policyNoMatch = new AbacPolicy("P-NoMatch", [AbacRule.PermitIf("R1", _ => false)], AbacCombiningAlgorithm.PermitOverrides);
        var decisionNoMatch = AbacPolicyEngine.EvaluatePolicy(context, policyNoMatch);
        decisionNoMatch.Status.Should().Be(AbacDecisionStatus.NotApplicable);
        decisionNoMatch.Reason.Should().Be("No rules matched within policy 'P-NoMatch'.");
    }

    [Fact]
    public void EvaluatePolicy_FirstApplicable_DiagnosticMessages_MatchExactly()
    {
        var context = new AbacContext();
        var throwingRule = new AbacRule("FaultyRule", AbacEffect.Permit, _ => throw new InvalidOperationException("DB Down"));
        var policyThrowing = new AbacPolicy("P-Throw", [throwingRule], AbacCombiningAlgorithm.FirstApplicable);

        var decisionThrow = AbacPolicyEngine.EvaluatePolicy(context, policyThrowing);
        decisionThrow.Status.Should().Be(AbacDecisionStatus.Indeterminate);
        decisionThrow.Reason.Should().Be("Error evaluating rule 'FaultyRule': DB Down");

        var policyNoMatch = new AbacPolicy("P-NoMatch", [AbacRule.PermitIf("R1", _ => false)], AbacCombiningAlgorithm.FirstApplicable);
        var decisionNoMatch = AbacPolicyEngine.EvaluatePolicy(context, policyNoMatch);
        decisionNoMatch.Status.Should().Be(AbacDecisionStatus.NotApplicable);
        decisionNoMatch.Reason.Should().Be("No rules matched within policy 'P-NoMatch'.");
    }

    [Fact]
    public void Evaluate_IndeterminatePolicy_FailsClosed_WithDeny_SEC_001()
    {
        var context = new AbacContext();
        var throwingRule = new AbacRule("DbRule", AbacEffect.Permit, _ => throw new InvalidOperationException("DB Unreachable"));
        var policyThrowing = new AbacPolicy("P-Throw", [throwingRule], AbacCombiningAlgorithm.DenyOverrides);

        var decision = AbacPolicyEngine.Instance.Evaluate(context, [policyThrowing]);
        decision.Status.Should().Be(AbacDecisionStatus.Deny, "SEC-001 FAIL-CLOSED: Indeterminate policy evaluation must result in Deny, never Permit or bypass.");
        decision.IsPermitted.Should().BeFalse();
        decision.Reason.Should().Contain("DB Unreachable");
    }

    [Fact]
    public void EnsurePermitted_WhenPermit_DoesNotThrow()
    {
        var permit = AbacDecision.Permit("P1", "R1", "Valid access");
        var act = () => permit.EnsurePermitted();
        act.Should().NotThrow();
    }

    [Fact]
    public void EnsurePermitted_WhenNotApplicableOrDeny_ThrowsUnauthorizedAccessException()
    {
        var notApplicable = AbacDecision.NotApplicable("No policy matched");
        var deny = AbacDecision.Deny("P1", "R1", "Explicitly denied");

        var actNa = () => notApplicable.EnsurePermitted();
        actNa.Should().Throw<UnauthorizedAccessException>()
            .WithMessage("*Access denied by ABAC PDP*NotApplicable*");

        var actDeny = () => deny.EnsurePermitted();
        actDeny.Should().Throw<UnauthorizedAccessException>()
            .WithMessage("*Access denied by ABAC PDP*Deny*");
    }
}
