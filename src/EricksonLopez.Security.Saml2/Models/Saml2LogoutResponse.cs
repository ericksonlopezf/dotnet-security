// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Saml2.Models;

using System;

/// <summary>
/// Represents the result of processing a SAML 2.0 Single Logout Response from the Identity Provider.
/// </summary>
public sealed record Saml2LogoutResponse
{
    /// <summary>Gets the unique message identifier of the logout response.</summary>
    public string Id { get; init; }

    /// <summary>Gets the issuer Entity ID of the response (IdP Entity ID).</summary>
    public string Issuer { get; init; }

    /// <summary>Gets the issue timestamp.</summary>
    public DateTimeOffset IssueInstant { get; init; }

    /// <summary>
    /// Gets the InResponseTo attribute value, which must match the ID of the
    /// <see cref="Saml2LogoutRequest"/> that triggered this response.
    /// </summary>
    public string InResponseTo { get; init; }

    /// <summary>Gets the SAML status code URI (e.g., urn:oasis:names:tc:SAML:2.0:status:Success).</summary>
    public string StatusCode { get; init; }

    /// <summary>
    /// Gets a value indicating whether the logout was successful.
    /// <see langword="true"/> when <see cref="StatusCode"/> ends with "Success"; otherwise, <see langword="false"/>.
    /// </summary>
    public bool IsSuccess => StatusCode.EndsWith("Success", StringComparison.OrdinalIgnoreCase);

    /// <summary>Gets an optional status message from the IdP.</summary>
    public string? StatusMessage { get; init; }

    /// <summary>Gets the raw XML of the logout response.</summary>
    public string RawXml { get; init; }

    /// <summary>
    /// Initializes a new instance of the <see cref="Saml2LogoutResponse"/> record with the specified response data.
    /// </summary>
    /// <param name="id">The unique message identifier of the logout response.</param>
    /// <param name="issuer">The issuer Entity ID of the response.</param>
    /// <param name="issueInstant">The timestamp when the response was issued.</param>
    /// <param name="inResponseTo">The identifier of the original logout request that triggered this response.</param>
    /// <param name="statusCode">The SAML status code URI.</param>
    /// <param name="rawXml">The raw XML string representation of the logout response.</param>
    /// <param name="statusMessage">The optional status message returned by the Identity Provider.</param>
    /// <exception cref="ArgumentException"><paramref name="id"/>, <paramref name="issuer"/>, <paramref name="inResponseTo"/>, <paramref name="statusCode"/>, or <paramref name="rawXml"/> is <see langword="null"/>, empty, or whitespace</exception>
    public Saml2LogoutResponse(
        string id,
        string issuer,
        DateTimeOffset issueInstant,
        string inResponseTo,
        string statusCode,
        string rawXml,
        string? statusMessage = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(id);
        ArgumentException.ThrowIfNullOrWhiteSpace(issuer);
        ArgumentException.ThrowIfNullOrWhiteSpace(inResponseTo);
        ArgumentException.ThrowIfNullOrWhiteSpace(statusCode);
        ArgumentException.ThrowIfNullOrWhiteSpace(rawXml);

        Id = id;
        Issuer = issuer;
        IssueInstant = issueInstant;
        InResponseTo = inResponseTo;
        StatusCode = statusCode;
        StatusMessage = statusMessage;
        RawXml = rawXml;
    }
}
