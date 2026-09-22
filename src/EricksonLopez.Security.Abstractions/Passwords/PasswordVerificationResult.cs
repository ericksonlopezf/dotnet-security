// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Abstractions.Passwords;

/// <summary>
/// Specifies the result of a password verification check.
/// </summary>
public enum PasswordVerificationResult
{
    /// <summary>
    /// Indicates that password verification succeeded and the stored hash uses current algorithmic parameters.
    /// </summary>
    Success = 1,

    /// <summary>
    /// Indicates that password verification succeeded, but the stored hash uses outdated parameters and should be regenerated.
    /// </summary>
    SuccessRehashNeeded = 2,

    /// <summary>
    /// Indicates that password verification failed due to incorrect password or corrupted hash.
    /// </summary>
    Failed = 3
}
