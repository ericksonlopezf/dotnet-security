// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Saml2.Models;

using System;
using System.Security.Cryptography.X509Certificates;
using EricksonLopez.Security.Saml2.Enums;

/// <summary>
/// Specifies configuration options for SAML 2.0 Service Provider operations.
/// </summary>
public sealed class Saml2Options
{
    /// <summary>
    /// Gets or sets the Service Provider Entity ID (URI).
    /// </summary>
    public string SpEntityId { get; set; } = "https://localhost/saml2/sp";

    /// <summary>
    /// Gets or sets the Identity Provider Entity ID (URI).
    /// </summary>
    public string IdpEntityId { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the Identity Provider Single Sign-On (SSO) destination URL.
    /// </summary>
    public string IdpSingleSignOnUrl { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the Assertion Consumer Service (ACS) callback URL on this Service Provider.
    /// </summary>
    public string AssertionConsumerServiceUrl { get; set; } = "https://localhost/saml2/acs";

    /// <summary>
    /// Gets or sets the protocol binding for AuthnRequests (default is HttpRedirect).
    /// </summary>
    public Saml2Binding AuthnRequestBinding { get; set; } = Saml2Binding.HttpRedirect;

    /// <summary>
    /// Gets or sets the requested NameID format.
    /// </summary>
    public Saml2NameIdFormat DefaultNameIdFormat { get; set; } = Saml2NameIdFormat.EmailAddress;

    /// <summary>
    /// Gets or sets the IdP signing certificate for verifying digital signatures on responses and assertions.
    /// </summary>
    public X509Certificate2? IdpSigningCertificate { get; set; }

    /// <summary>
    /// Gets or sets the SP decryption certificate for decrypting <c>&lt;saml:EncryptedAssertion&gt;</c> payloads.
    /// </summary>
    public X509Certificate2? SpDecryptionCertificate { get; set; }

    /// <summary>
    /// Gets or sets the SP signing certificate for signing outgoing <c>AuthnRequest</c> messages.
    /// </summary>
    public X509Certificate2? SpSigningCertificate { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether outgoing AuthnRequests must be digitally signed.
    /// </summary>
    public bool SignAuthnRequests { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether inbound assertions or responses must be signed.
    /// </summary>
    public bool RequireSignedMessages { get; set; } = true;

    /// <summary>
    /// Gets or sets the allowable clock skew for assertion timestamp verification.
    /// </summary>
    public TimeSpan AllowedClockSkew { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// Gets or sets a value indicating whether assertion conditions must strictly contain a NotOnOrAfter expiration attribute.
    /// </summary>
    /// <remarks>
    /// The default is <see langword="true"/> per SAML 2.0 Core Section 2.5.1.2.
    /// </remarks>
    public bool RequireAssertionExpiration { get; set; } = true;

    /// <summary>
    /// Gets or sets the claim type for mapping the NameID (default is ClaimTypes.NameIdentifier).
    /// </summary>
    public string NameIdClaimType { get; set; } = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier";

    // ── Single Logout (SLO) ────────────────────────────────────────────────────

    /// <summary>
    /// Gets or sets the Identity Provider Single Logout Service (SLS) URL.
    /// Required when using <c>CreateLogoutRequest()</c> to initiate SP-initiated SLO.
    /// </summary>
    public string? IdpSingleLogoutUrl { get; set; }

    /// <summary>
    /// Gets or sets the Service Provider Single Logout Service (SLS) callback URL.
    /// This is where the IdP sends the <c>&lt;samlp:LogoutResponse&gt;</c>.
    /// </summary>
    public string? SpSingleLogoutUrl { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether outgoing <c>&lt;samlp:LogoutRequest&gt;</c> messages must be digitally signed.
    /// </summary>
    /// <remarks>
    /// Requires <see cref="SpSigningCertificate"/> to be configured.
    /// </remarks>
    public bool SignLogoutRequests { get; set; }

    // ── IdP-Initiated SSO ──────────────────────────────────────────────────────

    /// <summary>
    /// Gets or sets a value indicating whether IdP-initiated SSO responses (responses without <c>InResponseTo</c>) are accepted.
    /// </summary>
    /// <remarks>
    /// Disabled by default for security. When enabled, assertion replay protection is enforced via an assertion ID cache.
    /// </remarks>
    public bool AllowIdpInitiatedSso { get; set; }

    /// <summary>
    /// Gets or sets the maximum age of an assertion that is acceptable for IdP-initiated SSO.
    /// Used as the replay cache TTL window. Default is 5 minutes.
    /// </summary>
    public TimeSpan IdpInitiatedSsoMaxAssertionAge { get; set; } = TimeSpan.FromMinutes(5);
}
