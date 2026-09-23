// Copyright © Erickson Lopez. MIT License.
// Regression tests for SEC-003: AbacPolicyEngine.EvaluateFailClosed()

namespace EricksonLopez.Security.ZeroTrust.Tests;

using System;
using System.Collections.Generic;
using AwesomeAssertions;
using Xunit;

/// <summary>
/// Regression tests for SEC-003: EvaluateFailClosed must convert NotApplicable to Deny.
/// </summary>
public sealed class AbacPolicyEngineFailClosedTests
{
    // ── SEC-003 REGRESSION TESTS ────────────────────────────────────────────────

    [Fact]
    public void EvaluateFailClosed_NoPoliciesProvided_ReturnsDeny_NotNotApplicable()
    {
        // Before SEC-003 fix: Evaluate([]) returned NotApplicable.
        // A PEP that treated NotApplicable as "allow" would have granted access.
        // After fix: EvaluateFailClosed([]) must return Deny.
        var context = new AbacContext();

        var result = AbacPolicyEngine.Instance.EvaluateFailClosed(context, []);

        result.Status.Should().Be(AbacDecisionStatus.Deny,
            because: "EvaluateFailClosed must never return NotApplicable; no matching policies means Deny");
        result.IsPermitted.Should().BeFalse();
    }

    [Fact]
    public void EvaluateFailClosed_NoMatchingPolicy_ReturnsDeny_NotNotApplicable()
    {
        // Policy only applies to resource "invoices", but context has resource "payroll"
        var policy = new AbacPolicy(
            "InvoicePolicy",
            rules: [AbacRule.PermitIf("PermitAll", _ => true)],
            target: ctx => ctx.Get<string>(AbacAttributeCategory.Resource, "Type") == "invoices");

        var context = new AbacContext().WithResource("Type", "payroll");

        // Evaluate() returns NotApplicable (correct for its semantics)
        var baseResult = AbacPolicyEngine.Instance.Evaluate(context, [policy]);
        baseResult.Status.Should().Be(AbacDecisionStatus.NotApplicable);

        // EvaluateFailClosed() must return Deny for the same input
        var failClosedResult = AbacPolicyEngine.Instance.EvaluateFailClosed(context, [policy]);
        failClosedResult.Status.Should().Be(AbacDecisionStatus.Deny,
            because: "A PEP should never grant access when no policy matches the request context");
        failClosedResult.IsPermitted.Should().BeFalse();
        failClosedResult.Reason.Should().Be(
            "Fail-closed: No applicable policy found for the request context. Access denied by default. " +
            "Ensure a policy with a matching AppliesTo predicate is registered for this resource type.");
    }

    [Fact]
    public void EvaluateFailClosed_PolicyPermitsAccess_ReturnsPermit()
    {
        // A matching Permit should still pass through
        var policy = new AbacPolicy(
            "AdminPolicy",
            rules: [AbacRule.PermitIf("PermitAdmin", ctx => ctx.Get<string>(AbacAttributeCategory.Subject, "Role") == "Admin")]);

        var context = new AbacContext().WithSubject("Role", "Admin");

        var result = AbacPolicyEngine.Instance.EvaluateFailClosed(context, [policy]);

        result.Status.Should().Be(AbacDecisionStatus.Permit);
        result.IsPermitted.Should().BeTrue();
    }

    [Fact]
    public void EvaluateFailClosed_PolicyDeniesAccess_ReturnsDeny()
    {
        // An explicit Deny should still propagate through
        var policy = new AbacPolicy(
            "BlockBannedUsers",
            rules: [AbacRule.DenyIf("DenyBanned", ctx => ctx.Get<bool>(AbacAttributeCategory.Subject, "IsBanned"))]);

        var context = new AbacContext().WithSubject("IsBanned", true);

        var result = AbacPolicyEngine.Instance.EvaluateFailClosed(context, [policy]);

        result.Status.Should().Be(AbacDecisionStatus.Deny);
        result.IsPermitted.Should().BeFalse();
    }

    [Fact]
    public void EvaluateFailClosed_NullContext_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>("context",
            () => AbacPolicyEngine.Instance.EvaluateFailClosed(null!, []));
    }

    [Fact]
    public void EvaluateFailClosed_NullPolicies_ThrowsArgumentNullException()
    {
        var context = new AbacContext();
        Assert.Throws<ArgumentNullException>("policies",
            () => AbacPolicyEngine.Instance.EvaluateFailClosed(context, null!));
    }

    [Fact]
    public void EvaluateFailClosed_IndeterminateDecision_ReturnsDeny()
    {
        // Indeterminate (rule throws) should be treated as Deny in fail-closed mode
        var policy = new AbacPolicy(
            "FaultyPolicy",
            rules: [AbacRule.PermitIf("FaultyRule", _ => throw new InvalidOperationException("Evaluation error"))]);

        var context = new AbacContext();
        var result = AbacPolicyEngine.Instance.EvaluateFailClosed(context, [policy]);

        // Indeterminate is already converted to Deny by the base Evaluate() method
        result.Status.Should().Be(AbacDecisionStatus.Deny,
            because: "indeterminate evaluation errors must produce Deny in a fail-closed PDP");
    }

    [Fact]
    public void EvaluateFailClosed_Vs_Evaluate_DifferentResultsForNotApplicable()
    {
        // This test explicitly proves the behavioral difference between the two methods
        // and serves as a regression test for the SEC-003 authorization bypass.
        var context = new AbacContext();
        var policies = new List<AbacPolicy>(); // empty — no policies cover this request

        var openResult = AbacPolicyEngine.Instance.Evaluate(context, policies);
        var closedResult = AbacPolicyEngine.Instance.EvaluateFailClosed(context, policies);

        openResult.Status.Should().Be(AbacDecisionStatus.NotApplicable,
            because: "Evaluate() returns NotApplicable when no policies are present — PEP must handle this correctly");

        closedResult.Status.Should().Be(AbacDecisionStatus.Deny,
            because: "EvaluateFailClosed() must NEVER return NotApplicable — this prevents the authorization bypass from SEC-003");

        // KEY ASSERTION: The two methods produce different results for the same input.
        // A PEP using Evaluate() incorrectly treating NotApplicable as "allow" is the SEC-003 vulnerability.
        openResult.Status.Should().NotBe(closedResult.Status,
            because: "this proves the behavioral difference that prevents the SEC-003 authorization bypass");
    }
}
