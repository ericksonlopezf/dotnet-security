# Level 10: Enterprise Zero Trust Architecture & Observability

> **Showcase Level**: Level 10  
> **Source Code**: [`samples/EricksonLopez.Security.Sample/Levels/Level10_EnterpriseZeroTrust.cs`](../../samples/EricksonLopez.Security.Sample/Levels/Level10_EnterpriseZeroTrust.cs)  
> **Packages**: `EricksonLopez.Security.ZeroTrust`, `EricksonLopez.Security.OpenTelemetry`, `EricksonLopez.Security`

---

## 1. Overview & Architectural Role

Level 10 demonstrates dynamic, multidimensional Attribute-Based Access Control (ABAC) in full compliance with **NIST SP 800-162** and **XACML 3.0**, integrated with end-to-end OpenTelemetry distributed tracing and metrics:
- **Dynamic ABAC Authorization**: Decoupled Policy Decision Point (PDP) evaluating real-time context across Subject, Resource, Action, and Environment dimensions.
- **Rule Resolution Strategies**: Conflict resolution using `DenyOverrides`, `PermitOverrides`, or `FirstApplicable`.
- **OpenTelemetry Activity Tracing**: Correlated spans emitted on cryptographic operations with zero allocation when no listener is attached.
- **Security Metrics**: OpenTelemetry meters exporting operation rates, failure counts, and execution histograms.

---

## 2. NIST SP 800-162 Dynamic ABAC Policy Engine

```csharp
using EricksonLopez.Security.ZeroTrust;

// 1. Define contextual rules:
var clearanceRule = AbacRule.PermitIf(
    ruleId: "RULE_CLEARANCE_MATCH",
    condition: ctx =>
    {
        var userClearance = ctx.Get<int>(AbacAttributeCategory.Subject, "ClearanceLevel");
        var resourceClassification = ctx.Get<int>(AbacAttributeCategory.Resource, "ClassificationLevel");
        return userClearance >= resourceClassification;
    },
    description: "Subject clearance must be >= resource classification level.");

var mfaRequiredRule = AbacRule.DenyIf(
    ruleId: "RULE_DENY_NON_MFA_ADMIN",
    condition: ctx =>
    {
        var isAdmin = ctx.Get<bool>(AbacAttributeCategory.Subject, "IsAdmin");
        var mfaActive = ctx.Get<bool>(AbacAttributeCategory.Subject, "MfaVerified");
        return isAdmin && !mfaActive;
    },
    description: "Strictly deny administrative access if MFA is not verified.");

var geoFenceRule = AbacRule.DenyIf(
    ruleId: "RULE_DENY_UNAPPROVED_GEOLOCATION",
    condition: ctx =>
    {
        var country = ctx.Get<string>(AbacAttributeCategory.Environment, "CountryCode");
        return country is "XX" or "SANCTIONED_REGION";
    },
    description: "Deny access originating from restricted or sanctioned geolocations.");

// 2. Compose master policy with Deny-Overrides:
var masterPolicy = new AbacPolicy(
    policyId: "POLICY_ENTERPRISE_ZERO_TRUST_GATEWAY",
    rules: new[] { geoFenceRule, mfaRequiredRule, clearanceRule },
    combiningAlgorithm: AbacCombiningAlgorithm.DenyOverrides,
    description: "Master Zero Trust Policy with Deny-Overrides resolution.");

var policyEngine = new AbacPolicyEngine();
```

---

## 3. Real-Time Context Evaluation

```csharp
// Scenario A: MFA Admin, Clearance L5 -> Resource L4, US Origin
var contextA = new AbacContext()
    .WithSubject("ClearanceLevel", 5)
    .WithSubject("IsAdmin", true)
    .WithSubject("MfaVerified", true)
    .WithResource("ClassificationLevel", 4)
    .WithAction("ExportTopSecretLedger")
    .WithEnvironment("CountryCode", "US");

var decisionA = policyEngine.Evaluate(contextA, new[] { masterPolicy });
// decisionA.IsPermitted == true (Status = Permit)

// Scenario B: Admin without MFA
var contextB = new AbacContext()
    .WithSubject("ClearanceLevel", 5)
    .WithSubject("IsAdmin", true)
    .WithSubject("MfaVerified", false)
    .WithResource("ClassificationLevel", 4)
    .WithAction("ExportTopSecretLedger")
    .WithEnvironment("CountryCode", "US");

var decisionB = policyEngine.Evaluate(contextB, new[] { masterPolicy });
// decisionB.IsPermitted == false (Status = Deny, RuleId = "RULE_DENY_NON_MFA_ADMIN")
```

---

## 4. OpenTelemetry Tracing Integration

Cryptographic and authorization activities emit standard distributed tracing telemetry:

```csharp
using System.Diagnostics;
using EricksonLopez.Security.Diagnostics;

using var activity = SecurityActivitySource.Instance.StartActivity(
    name: "security.abac.evaluate",
    kind: ActivityKind.Internal);

activity?.SetTag("security.policy.id", masterPolicy.PolicyId);
activity?.SetTag("security.decision", decisionA.Status.ToString());
activity?.SetTag("security.actor.clearance", 5);
```
