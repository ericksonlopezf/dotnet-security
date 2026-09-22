// Copyright © Erickson Lopez. MIT License.
using System.Collections.Generic;

namespace EricksonLopez.Security.ZeroTrust;

/// <summary>
/// Defines the policy decision point (PDP) for evaluating ABAC access requests.
/// </summary>
public interface IAbacPolicyEngine
{
    /// <summary>
    /// Evaluates the access request context against the provided set of security policies.
    /// Returns <see cref="AbacDecisionStatus.NotApplicable"/> when no policy matches the context.
    /// </summary>
    /// <param name="context">The contextual attributes of the access request.</param>
    /// <param name="policies">The collection of policies to evaluate.</param>
    /// <returns>The resulting access decision (Permit, Deny, NotApplicable, Indeterminate).</returns>
    /// <exception cref="ArgumentNullException"><paramref name="context"/> or <paramref name="policies"/> is <see langword="null"/></exception>
    AbacDecision Evaluate(AbacContext context, IReadOnlyList<AbacPolicy> policies);

    /// <summary>
    /// Evaluates policies with fail-closed semantics: if no policy applies to the request context,
    /// returns <see cref="AbacDecision.Deny(string?,string?,string?)"/> instead of
    /// <see cref="AbacDecisionStatus.NotApplicable"/>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <strong>Security recommendation</strong>: Prefer <see cref="EvaluateFailClosed"/> over <see cref="Evaluate"/> in
    /// production Policy Enforcement Points (PEPs). A <see cref="AbacDecisionStatus.NotApplicable"/>
    /// result from <see cref="Evaluate"/> means no policy matched — not that access is permitted.
    /// Treating <c>NotApplicable</c> as "allowed" in the PEP creates an authorization bypass when
    /// no policy covers the request.
    /// </para>
    /// <para>
    /// Use <see cref="Evaluate"/> directly only when you explicitly need to distinguish
    /// <c>NotApplicable</c> from <c>Deny</c> for audit logging or policy debugging purposes.
    /// </para>
    /// </remarks>
    /// <param name="context">The contextual attributes of the access request.</param>
    /// <param name="policies">The collection of policies to evaluate.</param>
    /// <returns>
    /// <see cref="AbacDecision.Permit(string?,string?,string?)"/> if access is explicitly granted,
    /// <see cref="AbacDecision.Deny(string?,string?,string?)"/> in all other cases including no matching policy.
    /// </returns>
    /// <exception cref="ArgumentNullException"><paramref name="context"/> or <paramref name="policies"/> is <see langword="null"/></exception>
    AbacDecision EvaluateFailClosed(AbacContext context, IReadOnlyList<AbacPolicy> policies);
}
