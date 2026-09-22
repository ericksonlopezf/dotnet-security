// Copyright © Erickson Lopez. MIT License.
using System;
using System.Collections.Generic;

namespace EricksonLopez.Security.ZeroTrust;

/// <summary>
/// Represents an access control policy containing target criteria, combining algorithm, and a collection of rules.
/// </summary>
public sealed class AbacPolicy
{
    /// <summary>
    /// Gets the unique identifier of the policy.
    /// </summary>
    public string PolicyId { get; }

    /// <summary>
    /// Gets the optional target condition that determines whether this policy applies to a given context.
    /// If <see langword="null"/>, the policy applies to all contexts.
    /// </summary>
    public Func<AbacContext, bool>? Target { get; }

    /// <summary>
    /// Gets the combining algorithm for reconciling the outcomes of the policy's rules.
    /// </summary>
    public AbacCombiningAlgorithm CombiningAlgorithm { get; }

    /// <summary>
    /// Gets the list of rules evaluated by this policy.
    /// </summary>
    public IReadOnlyList<AbacRule> Rules { get; }

    /// <summary>
    /// Gets the optional description of the policy.
    /// </summary>
    public string? Description { get; }

    /// <summary>
    /// Initializes a new instance of the <see cref="AbacPolicy"/> class.
    /// </summary>
    /// <param name="policyId">The unique identifier of the policy.</param>
    /// <param name="rules">The ordered collection of evaluation rules contained in this policy.</param>
    /// <param name="combiningAlgorithm">The algorithm for resolving conflicting rule evaluation outcomes.</param>
    /// <param name="target">The optional predicate determining whether this policy applies to an evaluation context.</param>
    /// <param name="description">The optional human-readable description of the policy.</param>
    /// <exception cref="ArgumentNullException"><paramref name="policyId"/> or <paramref name="rules"/> is <see langword="null"/></exception>
    public AbacPolicy(
        string policyId,
        IReadOnlyList<AbacRule> rules,
        AbacCombiningAlgorithm combiningAlgorithm = AbacCombiningAlgorithm.DenyOverrides,
        Func<AbacContext, bool>? target = null,
        string? description = null)
    {
        ArgumentNullException.ThrowIfNull(policyId);
        ArgumentNullException.ThrowIfNull(rules);

        PolicyId = policyId;
        Rules = rules;
        CombiningAlgorithm = combiningAlgorithm;
        Target = target;
        Description = description;
    }

    /// <summary>
    /// Determines whether this policy applies to the specified context.
    /// </summary>
    /// <param name="context">The attribute context to evaluate against the policy target.</param>
    /// <returns><see langword="true"/> if the policy target matches or is undefined; otherwise, <see langword="false"/>.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="context"/> is <see langword="null"/></exception>
    public bool AppliesTo(AbacContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        return Target == null || Target(context);
    }
}
