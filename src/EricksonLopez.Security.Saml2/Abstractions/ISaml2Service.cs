// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Saml2.Abstractions;

using System.Threading;
using System.Threading.Tasks;
using EricksonLopez.Result;
using EricksonLopez.Security.Saml2.Models;

/// <summary>
/// Defines a service that orchestrates SAML 2.0 Web Browser Single Sign-On and Single Logout operations.
/// </summary>
public interface ISaml2Service
{
    // ── SP-Initiated SSO ───────────────────────────────────────────────────────

    /// <summary>
    /// Generates a signed or unsigned <c>Saml2AuthnRequest</c> XML message to initiate SP-initiated SSO.
    /// </summary>
    /// <param name="relayState">The optional opaque RelayState string.</param>
    /// <returns>A new <see cref="Saml2AuthnRequest"/> model.</returns>
    Saml2AuthnRequest CreateAuthnRequest(string? relayState = null);

    /// <summary>
    /// Validates an incoming SAML 2.0 Response XML string against XSW attacks, signature verification,
    /// timestamp validity, and assertion decryption.
    /// </summary>
    /// <param name="samlResponseXml">The raw XML or Base64-encoded SAML Response string.</param>
    /// <param name="expectedInResponseTo">The expected request ID for SP-initiated flows (must not be null for SP-initiated SSO).</param>
    /// <param name="cancellationToken">A token that can be used to cancel the asynchronous operation.</param>
    /// <returns>
    /// A task representing the asynchronous operation. The task result contains a result containing the authenticated principal and assertion on success.
    /// </returns>
    Task<Result<Saml2AuthenticationResult>> ProcessResponseAsync(
        string samlResponseXml,
        string? expectedInResponseTo = null,
        CancellationToken cancellationToken = default);

    // ── IdP-Initiated SSO ──────────────────────────────────────────────────────

    /// <summary>
    /// Processes an IdP-initiated SAML 2.0 Response (unsolicited response without <c>InResponseTo</c>).
    /// </summary>
    /// <remarks>
    /// Security note: IdP-initiated SSO is inherently less secure than SP-initiated SSO because
    /// there is no request correlation. Enforces assertion ID replay protection to
    /// prevent assertion reuse attacks. <see cref="Saml2Options.AllowIdpInitiatedSso"/> must be
    /// set to <see langword="true"/> to enable this flow.
    /// </remarks>
    /// <param name="samlResponseXml">The raw XML or Base64-encoded SAML Response string from the IdP.</param>
    /// <param name="cancellationToken">A token that can be used to cancel the asynchronous operation.</param>
    /// <returns>
    /// A task representing the asynchronous operation. The task result contains a result containing the authenticated principal and assertion on success.
    /// </returns>
    Task<Result<Saml2AuthenticationResult>> ProcessIdpInitiatedResponseAsync(
        string samlResponseXml,
        CancellationToken cancellationToken = default);

    // ── Single Logout (SLO) ────────────────────────────────────────────────────

    /// <summary>
    /// Creates a <c>&lt;samlp:LogoutRequest&gt;</c> XML message to initiate SP-initiated Single Logout.
    /// </summary>
    /// <param name="nameId">The NameID of the principal whose session should be terminated.</param>
    /// <param name="sessionIndex">The optional SessionIndex from the original assertion's AuthnStatement.</param>
    /// <param name="relayState">The optional opaque RelayState string.</param>
    /// <returns>A new <see cref="Saml2LogoutRequest"/> model.</returns>
    Saml2LogoutRequest CreateLogoutRequest(
        Saml2NameId nameId,
        string? sessionIndex = null,
        string? relayState = null);

    /// <summary>
    /// Validates an incoming <c>&lt;samlp:LogoutResponse&gt;</c> from the Identity Provider.
    /// Verifies signature, status code, and <c>InResponseTo</c> correlation.
    /// </summary>
    /// <param name="samlLogoutResponseXml">The raw XML or Base64-encoded LogoutResponse string.</param>
    /// <param name="expectedInResponseTo">The ID of the <see cref="Saml2LogoutRequest"/> this is a response to.</param>
    /// <param name="cancellationToken">A token that can be used to cancel the asynchronous operation.</param>
    /// <returns>
    /// A task representing the asynchronous operation. The task result contains a result containing the parsed <see cref="Saml2LogoutResponse"/> on success.
    /// </returns>
    Task<Result<Saml2LogoutResponse>> ProcessLogoutResponseAsync(
        string samlLogoutResponseXml,
        string expectedInResponseTo,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Creates a <c>&lt;samlp:LogoutResponse&gt;</c> XML message in response to an IdP-initiated
    /// <c>&lt;samlp:LogoutRequest&gt;</c> (for SP-side SLO response).
    /// </summary>
    /// <param name="inResponseTo">The ID of the incoming IdP LogoutRequest.</param>
    /// <param name="destination">The IdP's SLO response URL.</param>
    /// <param name="success">A value indicating whether the SP successfully terminated the local session.</param>
    /// <returns>A <see cref="Saml2LogoutResponse"/> model containing the SP's SLO response XML.</returns>
    Saml2LogoutResponse CreateLogoutResponse(
        string inResponseTo,
        string destination,
        bool success = true);

    // ── SP Metadata ────────────────────────────────────────────────────────────

    /// <summary>
    /// Generates an SP Metadata XML document that describes the Service Provider endpoints,
    /// capabilities, and certificates to federate with Identity Providers.
    /// </summary>
    /// <returns>
    /// A well-formed <c>&lt;md:EntityDescriptor&gt;</c> XML string compliant with the
    /// SAML 2.0 Metadata Specification (saml-metadata-2.0-os).
    /// </returns>
    string GenerateSpMetadata();
}

