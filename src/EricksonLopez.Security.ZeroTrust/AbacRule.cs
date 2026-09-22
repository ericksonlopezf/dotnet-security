// Copyright © Erickson Lopez. MIT License.
using System;

namespace EricksonLopez.Security.ZeroTrust;

/// <summary>
/// Represents an atomic policy rule evaluated against an <see cref="AbacContext"/>.
/// </summary>
public sealed class AbacRule
{
    /// <summary>
    /// Gets the unique identifier of the rule.
    /// </summary>
    public string RuleId { get; }

    /// <summary>
    /// Gets the effect produced if the rule condition evaluates to <see langword="true"/>.
    /// </summary>
    public AbacEffect Effect { get; }

    /// <summary>
    /// Gets the predicate condition evaluated against the context.
    /// </summary>
    public Func<AbacContext, bool> Condition { get; }

    /// <summary>
    /// Gets the optional human-readable description of the rule.
    /// </summary>
    public string? Description { get; }

    /// <summary>
    /// Initializes a new instance of the <see cref="AbacRule"/> class.
    /// </summary>
    /// <param name="ruleId">The unique identifier of the rule.</param>
    /// <param name="effect">The authorization effect returned when the condition evaluates to <see langword="true"/>.</param>
    /// <param name="condition">The predicate evaluated against the attribute context.</param>
    /// <param name="description">The optional human-readable description of the rule.</param>
    /// <exception cref="ArgumentNullException"><paramref name="ruleId"/> or <paramref name="condition"/> is <see langword="null"/></exception>
    public AbacRule(string ruleId, AbacEffect effect, Func<AbacContext, bool> condition, string? description = null)
    {
        ArgumentNullException.ThrowIfNull(ruleId);
        ArgumentNullException.ThrowIfNull(condition);

        RuleId = ruleId;
        Effect = effect;
        Condition = condition;
        Description = description;
    }

    /// <summary>
    /// Creates a rule that yields <see cref="AbacEffect.Permit"/> when the condition is met.
    /// </summary>
    /// <param name="ruleId">The unique identifier of the rule.</param>
    /// <param name="condition">The predicate evaluated against the attribute context.</param>
    /// <param name="description">The optional human-readable description of the rule.</param>
    /// <returns>A new <see cref="AbacRule"/> configured with the permit effect.</returns>
    public static AbacRule PermitIf(string ruleId, Func<AbacContext, bool> condition, string? description = null) =>
        new(ruleId, AbacEffect.Permit, condition, description);

    /// <summary>
    /// Creates a rule that yields <see cref="AbacEffect.Deny"/> when the condition is met.
    /// </summary>
    /// <param name="ruleId">The unique identifier of the rule.</param>
    /// <param name="condition">The predicate evaluated against the attribute context.</param>
    /// <param name="description">The optional human-readable description of the rule.</param>
    /// <returns>A new <see cref="AbacRule"/> configured with the deny effect.</returns>
    public static AbacRule DenyIf(string ruleId, Func<AbacContext, bool> condition, string? description = null) =>
        new(ruleId, AbacEffect.Deny, condition, description);
}
