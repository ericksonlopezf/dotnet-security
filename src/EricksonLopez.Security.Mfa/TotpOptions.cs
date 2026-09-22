// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Mfa;

/// <summary>
/// Specifies configuration options for TOTP code generation and verification.
/// </summary>
public sealed class TotpOptions
{
    /// <summary>
    /// Gets or sets the number of digits in the generated code (typically 6 or 8). Default is 6.
    /// </summary>
    public int Digits { get; set; } = 6;

    /// <summary>
    /// Gets or sets the time step period in seconds. Default is 30 seconds.
    /// </summary>
    public int PeriodSeconds { get; set; } = 30;

    /// <summary>
    /// Gets or sets the hash algorithm. Default is <see cref="TotpHashAlgorithm.Sha1"/>.
    /// </summary>
    public TotpHashAlgorithm Algorithm { get; set; } = TotpHashAlgorithm.Sha1;

    /// <summary>
    /// Gets or sets the number of drift time steps allowed before/after the current time step. Default is 1 (±30 seconds).
    /// </summary>
    public int AllowedDriftSteps { get; set; } = 1;

    /// <summary>
    /// Gets or sets a value indicating whether to prevent replay attacks by rejecting already consumed codes
    /// within their validity time step window (RFC 6238 Section 5.2). Default is <see langword="true"/>.
    /// </summary>
    public bool PreventReplay { get; set; } = true;
}
