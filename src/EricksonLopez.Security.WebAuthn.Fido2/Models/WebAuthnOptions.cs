// Copyright © Erickson Lopez. MIT License.

using System;
using System.Collections.Generic;
using EricksonLopez.Security.WebAuthn.Fido2.Enums;

namespace EricksonLopez.Security.WebAuthn.Fido2.Models;

/// <summary>
/// Specifies global configuration options for the WebAuthn / FIDO2 Relying Party engine.
/// </summary>
public sealed class WebAuthnOptions
{
    /// <summary>
    /// Gets or sets the Relying Party identifier (domain name, e.g. "example.com" or "localhost").
    /// </summary>
    public string RpId { get; set; } = "localhost";

    /// <summary>
    /// Gets or sets the Relying Party display name.
    /// </summary>
    public string RpName { get; set; } = "EricksonLopez Platform";

    /// <summary>
    /// Gets or sets the expected application origins (e.g. "https://example.com", "http://localhost:5000").
    /// </summary>
    public ISet<string> AllowedOrigins { get; set; } = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "https://localhost",
        "https://localhost:5001",
        "http://localhost:5000"
    };

    /// <summary>
    /// Gets or sets the supported cryptographic algorithms in order of preference.
    /// </summary>
    public IList<CoseAlgorithmIdentifier> SupportedAlgorithms { get; set; } = new List<CoseAlgorithmIdentifier>
    {
        CoseAlgorithmIdentifier.ES256,
        CoseAlgorithmIdentifier.EdDSA,
        CoseAlgorithmIdentifier.ES384,
        CoseAlgorithmIdentifier.ES512,
        CoseAlgorithmIdentifier.RS256
    };

    /// <summary>
    /// Gets or sets the ceremony timeout in milliseconds.
    /// </summary>
    public ulong CeremonyTimeoutMilliseconds { get; set; } = 60000;

    /// <summary>
    /// Gets or sets the challenge length in bytes (minimum 32 bytes).
    /// </summary>
    public int ChallengeLengthBytes { get; set; } = 32;

    /// <summary>
    /// Gets or sets the default user verification requirement.
    /// </summary>
    public UserVerificationRequirement DefaultUserVerification { get; set; } = UserVerificationRequirement.Preferred;

    /// <summary>
    /// Gets or sets the default resident key requirement.
    /// </summary>
    public ResidentKeyRequirement DefaultResidentKey { get; set; } = ResidentKeyRequirement.Preferred;
}
