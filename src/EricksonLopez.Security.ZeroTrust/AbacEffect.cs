// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.ZeroTrust;

/// <summary>
/// Specifies the intended effect when an ABAC rule condition evaluates to <see langword="true"/>.
/// </summary>
public enum AbacEffect
{
    /// <summary>
    /// Specifies that access is granted to the requested operation or resource.
    /// </summary>
    Permit = 1,

    /// <summary>
    /// Specifies that access is denied to the requested operation or resource.
    /// </summary>
    Deny = 2
}
