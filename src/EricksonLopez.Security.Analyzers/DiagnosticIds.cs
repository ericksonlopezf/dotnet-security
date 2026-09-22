// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Analyzers;

/// <summary>
/// Provides diagnostic identifier constants for the EricksonLopez.Security Roslyn analyzers.
/// </summary>
public static class DiagnosticIds
{
    // ELS0001 – ELS0099: Security Misuse

    /// <summary>
    /// Represents the diagnostic identifier reported when string or sequence equality comparisons are performed without constant-time guarantees (ELS0001).
    /// </summary>
    public const string NonConstantTimeComparison = "ELS0001";

    /// <summary>
    /// Represents the diagnostic identifier reported when a secret buffer is instantiated without proper disposal (ELS0002).
    /// </summary>
    public const string UndisposedSecretBuffer = "ELS0002";

    /// <summary>
    /// Represents the diagnostic identifier reported when hardcoded cryptographic keys or secrets are detected in source code (ELS0003).
    /// </summary>
    public const string HardcodedSecret = "ELS0003";

    /// <summary>
    /// Represents the diagnostic identifier reported when insecure or deprecated password hashing algorithms are utilized (ELS0004).
    /// </summary>
    public const string InsecurePasswordAlgorithm = "ELS0004";

    /// <summary>
    /// Represents the diagnostic identifier reported when sensitive cryptographic material is passed unredacted to logging sinks (ELS0005).
    /// </summary>
    public const string LoggingRawSecret = "ELS0005";
}
