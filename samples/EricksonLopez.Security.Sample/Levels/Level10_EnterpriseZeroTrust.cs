// Copyright © Erickson Lopez. MIT License.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.Metrics;
using EricksonLopez.Security.Diagnostics;
using EricksonLopez.Security.OpenTelemetry;
using EricksonLopez.Security.ZeroTrust;

namespace EricksonLopez.Security.Sample.Levels;

/// <summary>
/// Level 10: Enterprise Zero Trust Architecture & Observability.
/// Demonstrates multidimensional Attribute-Based Access Control (ABAC) evaluation
/// aligned with NIST SP 800-162 / XACML, integrated with OpenTelemetry cryptographic tracing and meters.
/// </summary>
public static class Level10_EnterpriseZeroTrust
{
    public static void Run()
    {
        Console.WriteLine("\n================================================================================");
        Console.WriteLine("  LEVEL 10: ENTERPRISE ZERO TRUST ARCHITECTURE & OBSERVABILITY");
        Console.WriteLine("================================================================================");

        // -------------------------------------------------------------------------
        // 1. Zero Trust ABAC Policy Engine (NIST SP 800-162 Compliant)
        // -------------------------------------------------------------------------
        Console.WriteLine("\n[1] Zero Trust Dynamic ABAC Authorization Evaluation:");

        // Policy 1: High-Clearance Resource Access
        var clearanceRule = AbacRule.PermitIf(
            ruleId: "RULE_CLEARANCE_MATCH",
            condition: ctx =>
            {
                var userClearance = ctx.Get<int>(AbacAttributeCategory.Subject, "ClearanceLevel");
                var resourceClassification = ctx.Get<int>(AbacAttributeCategory.Resource, "ClassificationLevel");
                return userClearance >= resourceClassification;
            },
            description: "Subject clearance must be greater than or equal to resource classification level.");

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

        var enterpriseZeroTrustPolicy = new AbacPolicy(
            policyId: "POLICY_ENTERPRISE_ZERO_TRUST_GATEWAY",
            rules: new[] { geoFenceRule, mfaRequiredRule, clearanceRule },
            combiningAlgorithm: AbacCombiningAlgorithm.DenyOverrides,
            description: "Master Zero Trust Policy with Deny-Overrides resolution.");

        var policyEngine = new AbacPolicyEngine();

        // Scenario A: Authorized Executive with MFA from US
        var contextExecutive = new AbacContext()
            .WithSubject("ClearanceLevel", 5)
            .WithSubject("IsAdmin", true)
            .WithSubject("MfaVerified", true)
            .WithResource("ClassificationLevel", 4)
            .WithAction("ExportTopSecretLedger")
            .WithEnvironment("CountryCode", "US");

        var decisionA = policyEngine.Evaluate(contextExecutive, new[] { enterpriseZeroTrustPolicy });
        Console.WriteLine($"  -> Scenario A (MFA Admin, Clearance L5 -> Resource L4, US): {decisionA.Status} (Permitted={decisionA.IsPermitted})");

        // Scenario B: Admin without MFA (Violates MFA Rule)
        var contextNoMfa = new AbacContext()
            .WithSubject("ClearanceLevel", 5)
            .WithSubject("IsAdmin", true)
            .WithSubject("MfaVerified", false)
            .WithResource("ClassificationLevel", 4)
            .WithAction("ExportTopSecretLedger")
            .WithEnvironment("CountryCode", "US");

        var decisionB = policyEngine.Evaluate(contextNoMfa, new[] { enterpriseZeroTrustPolicy });
        Console.WriteLine($"  -> Scenario B (Admin without MFA): {decisionB.Status} (Permitted={decisionB.IsPermitted}, Rule={decisionB.RuleId})");

        // Scenario C: Sanctioned Geo Location (Violates Geo Fence)
        var contextSanctionedGeo = new AbacContext()
            .WithSubject("ClearanceLevel", 5)
            .WithSubject("IsAdmin", true)
            .WithSubject("MfaVerified", true)
            .WithResource("ClassificationLevel", 4)
            .WithAction("ExportTopSecretLedger")
            .WithEnvironment("CountryCode", "SANCTIONED_REGION");

        var decisionC = policyEngine.Evaluate(contextSanctionedGeo, new[] { enterpriseZeroTrustPolicy });
        Console.WriteLine($"  -> Scenario C (Sanctioned Location Access): {decisionC.Status} (Permitted={decisionC.IsPermitted}, Rule={decisionC.RuleId})");

        // -------------------------------------------------------------------------
        // 2. OpenTelemetry Cryptographic ActivitySource & Meter Listeners
        // -------------------------------------------------------------------------
        Console.WriteLine("\n[2] OpenTelemetry Cryptographic Distributed Tracing & Metrics:");

        using var activityListener = new ActivityListener
        {
            ShouldListenTo = s => s.Name == SecurityActivitySource.SourceName,
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllData,
            ActivityStarted = act => Console.WriteLine($"     [OTEL SPAN START] {act.OperationName} (Id: {act.Id})"),
            ActivityStopped = act =>
            {
                var algorithm = act.GetTagItem(SecurityActivitySource.TagAlgorithm);
                var result = act.GetTagItem(SecurityActivitySource.TagResult);
                Console.WriteLine($"     [OTEL SPAN STOP]  {act.OperationName} (Duration: {act.Duration.TotalMilliseconds:F2}ms, Algo: {algorithm}, Result: {result})");
            }
        };
        ActivitySource.AddActivityListener(activityListener);

        // Emit an instrumented cryptographic activity span
        using (var span = SecurityActivitySource.Instance.StartActivity(SecurityActivitySource.EncryptOperation))
        {
            span?.SetTag(SecurityActivitySource.TagAlgorithm, "aes-256-gcm");
            span?.SetTag(SecurityActivitySource.TagKeyVersion, "v2");
            span?.SetTag(SecurityActivitySource.TagResult, "success");
            SecurityMeter.EncryptTotal.Add(1, new KeyValuePair<string, object?>(SecurityActivitySource.TagAlgorithm, "aes-256-gcm"));
        }

        Console.WriteLine("--------------------------------------------------------------------------------");

        // -------------------------------------------------------------------------
        // 3. SecurityOpenTelemetryExtensions — OTel Pipeline Integration
        // -------------------------------------------------------------------------
        Console.WriteLine("\n[3] SecurityOpenTelemetryExtensions — OpenTelemetry Pipeline Integration:");
        Console.WriteLine("  The EricksonLopez.Security.OpenTelemetry package provides two extension methods:");
        Console.WriteLine();
        Console.WriteLine("  // Tracing (TracerProviderBuilder overload):");
        Console.WriteLine("  builder.Services.AddOpenTelemetry()");
        Console.WriteLine("      .WithTracing(tracing => tracing");
        Console.WriteLine("          .AddEricksonLopezSecurityInstrumentation()   // subscribes SecurityActivitySource");
        Console.WriteLine("          .AddOtlpExporter());");
        Console.WriteLine();
        Console.WriteLine("  // Metrics (MeterProviderBuilder overload):");
        Console.WriteLine("  builder.Services.AddOpenTelemetry()");
        Console.WriteLine("      .WithMetrics(metrics => metrics");
        Console.WriteLine("          .AddEricksonLopezSecurityInstrumentation()   // subscribes SecurityMeter");
        Console.WriteLine("          .AddOtlpExporter());");
        Console.WriteLine();
        Console.WriteLine($"  -> TracerProviderBuilder extension registers ActivitySource: '{SecurityActivitySource.SourceName}'");
        Console.WriteLine($"  -> MeterProviderBuilder extension registers Meter: '{SecurityMeter.MeterName}'");

        // -------------------------------------------------------------------------
        // 4. AbacDecisionStatus — All Enum Values
        // -------------------------------------------------------------------------
        Console.WriteLine("\n[4] AbacDecisionStatus Enum — All XACML Decision Outcomes:");
        Console.WriteLine($"  -> Permit={AbacDecisionStatus.Permit}   — At least one rule matched with Permit effect and no Deny override.");
        Console.WriteLine($"  -> Deny={AbacDecisionStatus.Deny}     — A Deny rule fired (DenyOverrides) or no Permit was found.");
        Console.WriteLine($"  -> NotApplicable={AbacDecisionStatus.NotApplicable} — No rules matched the context.");
        Console.WriteLine($"  -> Indeterminate={AbacDecisionStatus.Indeterminate} — An error occurred during rule evaluation (defensive catch).");
    }
}
