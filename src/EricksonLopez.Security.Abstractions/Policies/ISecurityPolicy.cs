// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Abstractions.Policies;

using EricksonLopez.Result;

/// <summary>
/// Defines a contract for deterministic, immutable, and testable security policies.
/// </summary>
/// <typeparam name="T">The target entity or value being evaluated.</typeparam>
public interface ISecurityPolicy<in T>
{
    /// <summary>
    /// Evaluates the policy rules against the target value.
    /// </summary>
    /// <param name="target">The target instance to validate.</param>
    /// <returns>A <see cref="Result"/> indicating success or containing detailed validation error reasons.</returns>
    Result Validate(T target);
}
