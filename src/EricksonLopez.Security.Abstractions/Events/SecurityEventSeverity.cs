// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Abstractions.Events;

/// <summary>
/// Specifies the severity level of a domain or application security event.
/// </summary>
public enum SecurityEventSeverity
{
    /// <summary>
    /// Specifies a routine security lifecycle event (e.g. key rotation, secret creation).
    /// </summary>
    Informational = 1,

    /// <summary>
    /// Specifies a notable security condition requiring attention (e.g. rehash required, key approaching expiration).
    /// </summary>
    Warning = 2,

    /// <summary>
    /// Specifies a high-impact security event (e.g. key revocation due to suspected compromise, policy violation).
    /// </summary>
    High = 3,

    /// <summary>
    /// Specifies a critical security event (e.g. active tampering detected, authentication tag mismatch attack).
    /// </summary>
    Critical = 4
}
