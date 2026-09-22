// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.WebAuthn.Fido2.Mds3;

using System;
using System.Collections.Generic;
using EricksonLopez.Result;

/// <summary>
/// Represents cached metadata for a single authenticator as retrieved from the FIDO Alliance MDS3.
/// </summary>
public sealed record AuthenticatorMetadata
{
    /// <summary>
    /// Gets the Authenticator Attestation GUID (AAGUID), uniquely identifying the authenticator model.
    /// <see langword="null"/> for FIDO-U2F authenticators which use KeyIdentifier instead.
    /// </summary>
    public Guid? Aaguid { get; init; }

    /// <summary>
    /// Gets the human-readable description of the authenticator (e.g. "YubiKey 5 NFC").
    /// </summary>
    public string Description { get; init; }

    /// <summary>
    /// Gets the status reports for this authenticator from the FIDO Alliance.
    /// Consumers SHOULD reject authenticators with status NOT_FIDO_CERTIFIED, REVOKED, or USER_VERIFICATION_BYPASS.
    /// </summary>
    public IReadOnlyList<AuthenticatorStatusReport> StatusReports { get; init; }

    /// <summary>
    /// Gets the attestation root certificates for this authenticator in DER-encoded form
    /// that validate whether the attestation certificate chain belongs to the expected manufacturer.
    /// </summary>
    public IReadOnlyList<byte[]> AttestationRootCertificates { get; init; }

    /// <summary>
    /// Gets the UTC timestamp when this entry was last updated in MDS3.
    /// </summary>
    public DateTimeOffset TimeOfLastStatusChange { get; init; }

    /// <summary>
    /// Initializes a new instance of the <see cref="AuthenticatorMetadata"/> class with the specified metadata details.
    /// </summary>
    /// <param name="description">The human-readable description of the authenticator model.</param>
    /// <param name="statusReports">The collection of status reports associated with this authenticator.</param>
    /// <param name="attestationRootCertificates">The collection of trusted root certificates for verifying attestation statements.</param>
    /// <param name="timeOfLastStatusChange">The timestamp when this entry was last updated in MDS3.</param>
    /// <param name="aaguid">The optional Authenticator Attestation GUID identifying this authenticator model.</param>
    /// <exception cref="ArgumentNullException"><paramref name="description"/>, <paramref name="statusReports"/>, or <paramref name="attestationRootCertificates"/> is <see langword="null"/></exception>
    public AuthenticatorMetadata(
        string description,
        IReadOnlyList<AuthenticatorStatusReport> statusReports,
        IReadOnlyList<byte[]> attestationRootCertificates,
        DateTimeOffset timeOfLastStatusChange,
        Guid? aaguid = null)
    {
        Description = description ?? throw new ArgumentNullException(nameof(description));
        StatusReports = statusReports ?? throw new ArgumentNullException(nameof(statusReports));
        AttestationRootCertificates = attestationRootCertificates ?? throw new ArgumentNullException(nameof(attestationRootCertificates));
        TimeOfLastStatusChange = timeOfLastStatusChange;
        Aaguid = aaguid;
    }
}
