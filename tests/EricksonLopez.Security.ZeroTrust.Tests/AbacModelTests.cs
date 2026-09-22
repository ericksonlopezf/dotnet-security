// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.ZeroTrust.Tests;

using System;
using System.Collections.Generic;
using AwesomeAssertions;
using Xunit;

public sealed class AbacModelTests
{
    [Fact]
    public void AbacAttributeCategory_Constants_MatchExpected()
    {
        AbacAttributeCategory.Subject.Should().Be("Subject");
        AbacAttributeCategory.Resource.Should().Be("Resource");
        AbacAttributeCategory.Action.Should().Be("Action");
        AbacAttributeCategory.Environment.Should().Be("Environment");
    }

    [Fact]
    public void AbacCombiningAlgorithm_EnumValues_MatchExpected()
    {
        ((int)AbacCombiningAlgorithm.DenyOverrides).Should().Be(1);
        ((int)AbacCombiningAlgorithm.PermitOverrides).Should().Be(2);
        ((int)AbacCombiningAlgorithm.FirstApplicable).Should().Be(3);
    }

    [Fact]
    public void AbacDecisionStatus_EnumValues_MatchExpected()
    {
        ((int)AbacDecisionStatus.Permit).Should().Be(1);
        ((int)AbacDecisionStatus.Deny).Should().Be(2);
        ((int)AbacDecisionStatus.NotApplicable).Should().Be(3);
        ((int)AbacDecisionStatus.Indeterminate).Should().Be(4);
    }

    [Fact]
    public void AbacEffect_EnumValues_MatchExpected()
    {
        ((int)AbacEffect.Permit).Should().Be(1);
        ((int)AbacEffect.Deny).Should().Be(2);
    }

    [Fact]
    public void AbacDecision_FactoryMethodsAndProperties_Work()
    {
        var permit = AbacDecision.Permit("P1", "R1", "Allowed");
        permit.Status.Should().Be(AbacDecisionStatus.Permit);
        permit.IsPermitted.Should().BeTrue();
        permit.PolicyId.Should().Be("P1");
        permit.RuleId.Should().Be("R1");
        permit.Reason.Should().Be("Allowed");

        var deny = AbacDecision.Deny("P2", "R2", "Blocked");
        deny.Status.Should().Be(AbacDecisionStatus.Deny);
        deny.IsPermitted.Should().BeFalse();

        var notApp1 = AbacDecision.NotApplicable();
        notApp1.Status.Should().Be(AbacDecisionStatus.NotApplicable);
        notApp1.Reason.Should().Be("No applicable policies matched the evaluation context.");

        var notApp2 = AbacDecision.NotApplicable("Custom Not Applicable");
        notApp2.Reason.Should().Be("Custom Not Applicable");

        var indet1 = AbacDecision.Indeterminate();
        indet1.Status.Should().Be(AbacDecisionStatus.Indeterminate);
        indet1.Reason.Should().Be("An evaluation error or missing attribute occurred.");

        var indet2 = AbacDecision.Indeterminate("Custom Error");
        indet2.Reason.Should().Be("Custom Error");
    }

    [Fact]
    public void AbacRule_Properties_And_NullValidation()
    {
        var rule1 = AbacRule.PermitIf("R-Permit", _ => true, "Permit rule");
        rule1.RuleId.Should().Be("R-Permit");
        rule1.Effect.Should().Be(AbacEffect.Permit);
        rule1.Description.Should().Be("Permit rule");
        rule1.Condition(new AbacContext()).Should().BeTrue();

        var rule2 = AbacRule.DenyIf("R-Deny", _ => false, "Deny rule");
        rule2.Effect.Should().Be(AbacEffect.Deny);
        rule2.Condition(new AbacContext()).Should().BeFalse();

        Assert.Throws<ArgumentNullException>(() => new AbacRule(null!, AbacEffect.Permit, _ => true));
        Assert.Throws<ArgumentNullException>(() => new AbacRule("R1", AbacEffect.Permit, null!));
    }

    [Fact]
    public void AbacPolicy_Properties_And_NullValidation()
    {
        var rules = new List<AbacRule> { AbacRule.PermitIf("R1", _ => true) };
        var policy = new AbacPolicy("P1", rules, AbacCombiningAlgorithm.PermitOverrides, _ => true, "Sample policy");

        policy.PolicyId.Should().Be("P1");
        policy.Rules.Should().BeSameAs(rules);
        policy.CombiningAlgorithm.Should().Be(AbacCombiningAlgorithm.PermitOverrides);
        policy.Description.Should().Be("Sample policy");
        policy.AppliesTo(new AbacContext()).Should().BeTrue();

        // Target null applies to everything
        var universalPolicy = new AbacPolicy("P-All", rules);
        universalPolicy.AppliesTo(new AbacContext()).Should().BeTrue();

        Assert.Throws<ArgumentNullException>(() => new AbacPolicy(null!, rules));
        Assert.Throws<ArgumentNullException>(() => new AbacPolicy("P1", null!));
        Assert.Throws<ArgumentNullException>(() => universalPolicy.AppliesTo(null!));
    }
}
