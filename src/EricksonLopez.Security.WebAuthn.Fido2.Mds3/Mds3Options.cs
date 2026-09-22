// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.WebAuthn.Fido2.Mds3;

using System;

/// <summary>
/// Specifies configuration options for the FIDO Alliance MDS3 metadata service.
/// </summary>
public sealed class Mds3Options
{
    /// <summary>
    /// Gets or sets the URL of the FIDO Alliance MDS3 BLOB endpoint.
    /// Default: <c>https://mds3.fidoalliance.org/</c>.
    /// </summary>
    public string MetadataBlobUrl { get; set; } = "https://mds3.fidoalliance.org/";

    /// <summary>
    /// Gets or sets the duration to cache the MDS3 BLOB in memory before re-fetching.
    /// Default: 24 hours.
    /// </summary>
    public TimeSpan CacheDuration { get; set; } = TimeSpan.FromHours(24);

    /// <summary>
    /// Gets or sets a value indicating whether to validate the MDS3 BLOB JWT signature against the FIDO Alliance root certificate.
    /// </summary>
    public bool ValidateJwtSignature { get; set; } = true;

    /// <summary>
    /// Gets or sets the set of <see cref="AuthenticatorStatus"/> values that cause authenticator validation to fail.
    /// </summary>
    public AuthenticatorStatus[] DisallowedStatuses { get; set; } =
    [
        AuthenticatorStatus.Revoked,
        AuthenticatorStatus.AttestationKeyCompromise,
        AuthenticatorStatus.UserVerificationBypass,
        AuthenticatorStatus.UserKeyRemoteCompromise,
        AuthenticatorStatus.UserKeyPhysicalCompromise,
    ];

    /// <summary>
    /// Gets or sets a value indicating whether authenticators not found in the MDS3 metadata blob are permitted.
    /// </summary>
    public bool AllowUnknownAuthenticators { get; set; } = true;
}
