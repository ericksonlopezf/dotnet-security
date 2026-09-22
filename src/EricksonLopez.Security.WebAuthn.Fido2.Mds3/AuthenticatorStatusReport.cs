// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.WebAuthn.Fido2.Mds3;

using System;

/// <summary>
/// Represents a status report for an authenticator from the FIDO Alliance MDS3.
/// </summary>
public sealed record AuthenticatorStatusReport
{
    /// <summary>Gets the status of the authenticator.</summary>
    public AuthenticatorStatus Status { get; init; }

    /// <summary>Gets the date of the status report (ISO 8601 date).</summary>
    public string EffectiveDate { get; init; }

    /// <summary>Gets an optional URL with more information about the status.</summary>
    public string? Url { get; init; }

    /// <summary>Gets an optional certificate for FIDO_CERTIFIED reports.</summary>
    public string? Certificate { get; init; }

    /// <summary>Gets the FIDO certification level if applicable.</summary>
    public string? CertificationLevel { get; init; }

    /// <summary>
    /// Initializes a new instance of the <see cref="AuthenticatorStatusReport"/> class.
    /// </summary>
    /// <param name="status">The current certification or operational status of the authenticator.</param>
    /// <param name="effectiveDate">The ISO 8601 date when the status became effective.</param>
    /// <param name="url">The optional URL pointing to additional information or advisory details.</param>
    /// <param name="certificate">The optional base64 certificate payload for certification reports.</param>
    /// <param name="certificationLevel">The optional FIDO certification level.</param>
    /// <exception cref="ArgumentNullException"><paramref name="effectiveDate"/> is <see langword="null"/></exception>
    public AuthenticatorStatusReport(AuthenticatorStatus status, string effectiveDate, string? url = null, string? certificate = null, string? certificationLevel = null)
    {
        Status = status;
        EffectiveDate = effectiveDate ?? throw new ArgumentNullException(nameof(effectiveDate));
        Url = url;
        Certificate = certificate;
        CertificationLevel = certificationLevel;
    }
}
