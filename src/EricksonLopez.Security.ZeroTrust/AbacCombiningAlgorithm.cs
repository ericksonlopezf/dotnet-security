// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.ZeroTrust;

/// <summary>
/// Specifies the rule/policy combining algorithm for resolving multiple evaluations into a single decision.
/// </summary>
public enum AbacCombiningAlgorithm
{
    /// <summary>
    /// Specifies that if any applicable rule evaluates to Deny, the final decision is Deny (Zero-Trust Default).
    /// </summary>
    DenyOverrides = 1,

    /// <summary>
    /// Specifies that if any applicable rule evaluates to Permit, the final decision is Permit.
    /// </summary>
    PermitOverrides = 2,

    /// <summary>
    /// Specifies that rules are evaluated sequentially until the first satisfied condition determines the final decision.
    /// </summary>
    FirstApplicable = 3
}
