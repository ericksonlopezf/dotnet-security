// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Abstractions.Policies;

using System;
using System.Collections.Generic;
using EricksonLopez.Result;
using EricksonLopez.Security.Abstractions.Errors;

/// <summary>
/// Defines password strength rules, length constraints, and complexity requirements.
/// </summary>
/// <param name="MinimumLength">Minimum required password character length (defaults to 12 per NIST SP 800-63B).</param>
/// <param name="MaximumLength">Maximum allowed password length (defaults to 128 to prevent computational DoS).</param>
/// <param name="RequireDigit">Specifies a value indicating whether at least one numeric character ('0'-'9') is required.</param>
/// <param name="RequireUppercase">Specifies a value indicating whether at least one uppercase ASCII letter ('A'-'Z') is required.</param>
/// <param name="RequireLowercase">Specifies a value indicating whether at least one lowercase ASCII letter ('a'-'z') is required.</param>
/// <param name="RequireNonAlphanumeric">Specifies a value indicating whether at least one non-alphanumeric special character is required.</param>
/// <param name="MaxConsecutiveRepeatedChars">Maximum allowed consecutive identical characters (0 disables check).</param>
public sealed record PasswordPolicy(
    int MinimumLength = 12,
    int MaximumLength = 128,
    bool RequireDigit = true,
    bool RequireUppercase = true,
    bool RequireLowercase = true,
    bool RequireNonAlphanumeric = true,
    int MaxConsecutiveRepeatedChars = 3) : ISecurityPolicy<string>, ISecurityPolicy<ReadOnlyMemory<char>>
{
    /// <summary>
    /// Gets the enterprise default high-security password policy.
    /// </summary>
    public static readonly PasswordPolicy Default = new();

    /// <summary>
    /// Gets a strict NIST SP 800-63B aligned password policy focusing on length (min 15 chars).
    /// </summary>
    public static readonly PasswordPolicy NistAligned = new(
        MinimumLength: 15,
        MaximumLength: 128,
        RequireDigit: false,
        RequireUppercase: false,
        RequireLowercase: false,
        RequireNonAlphanumeric: false,
        MaxConsecutiveRepeatedChars: 4);

    /// <inheritdoc />
    public Result Validate(string target)
    {
        if (target is null)
        {
            return SecurityError.SecurityPolicyViolation(nameof(PasswordPolicy), "Password cannot be null.");
        }

        return Validate(target.AsSpan());
    }

    /// <inheritdoc />
    public Result Validate(ReadOnlyMemory<char> target) => Validate(target.Span);

    /// <summary>
    /// Validates password rules against a character span without heap allocations.
    /// </summary>
    /// <param name="password">The password character span.</param>
    /// <returns>A <see cref="Result"/> indicating pass or policy violation.</returns>
    public Result Validate(ReadOnlySpan<char> password)
    {
        if (password.Length < MinimumLength)
        {
            return SecurityError.SecurityPolicyViolation(
                nameof(PasswordPolicy),
                $"Password length ({password.Length}) is less than required minimum ({MinimumLength}).");
        }

        if (password.Length > MaximumLength)
        {
            return SecurityError.SecurityPolicyViolation(
                nameof(PasswordPolicy),
                $"Password length ({password.Length}) exceeds maximum allowed ({MaximumLength}).");
        }

        bool hasDigit = false;
        bool hasUpper = false;
        bool hasLower = false;
        bool hasSpecial = false;
        int consecutiveRepeated = 1;
        char prevChar = '\0';

        for (int i = 0; i < password.Length; i++)
        {
            char c = password[i];

            if (char.IsDigit(c))
            {
                hasDigit = true;
            }
            else if (char.IsUpper(c))
            {
                hasUpper = true;
            }
            else if (char.IsLower(c))
            {
                hasLower = true;
            }
            else
            {
                hasSpecial = true;
            }

            if (MaxConsecutiveRepeatedChars > 0 && i > 0)
            {
                if (c == prevChar)
                {
                    consecutiveRepeated++;
                    if (consecutiveRepeated > MaxConsecutiveRepeatedChars)
                    {
                        return SecurityError.SecurityPolicyViolation(
                            nameof(PasswordPolicy),
                            $"Password contains more than {MaxConsecutiveRepeatedChars} consecutive repeated characters ('{c}').");
                    }
                }
                else
                {
                    consecutiveRepeated = 1;
                }
            }

            prevChar = c;
        }

        if (RequireDigit && !hasDigit)
        {
            return SecurityError.SecurityPolicyViolation(nameof(PasswordPolicy), "Password must contain at least one numeric digit.");
        }

        if (RequireUppercase && !hasUpper)
        {
            return SecurityError.SecurityPolicyViolation(nameof(PasswordPolicy), "Password must contain at least one uppercase letter.");
        }

        if (RequireLowercase && !hasLower)
        {
            return SecurityError.SecurityPolicyViolation(nameof(PasswordPolicy), "Password must contain at least one lowercase letter.");
        }

        if (RequireNonAlphanumeric && !hasSpecial)
        {
            return SecurityError.SecurityPolicyViolation(nameof(PasswordPolicy), "Password must contain at least one special character.");
        }

        return Result.Success();
    }
}
