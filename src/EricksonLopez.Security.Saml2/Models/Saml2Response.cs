// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Saml2.Models;

using System;
using System.Collections.Generic;

/// <summary>
/// Represents a parsed SAML 2.0 Response message.
/// </summary>
public sealed record Saml2Response
{
    /// <summary>
    /// Gets the unique ID of the SAML response.
    /// </summary>
    public string Id { get; init; }

    /// <summary>
    /// Gets the optional ID of the request to which this is a response (InResponseTo).
    /// </summary>
    public string? InResponseTo { get; init; }

    /// <summary>
    /// Gets the issue instant of the response.
    /// </summary>
    public DateTimeOffset IssueInstant { get; init; }

    /// <summary>
    /// Gets the intended recipient destination URI of the response.
    /// </summary>
    public string? Destination { get; init; }

    /// <summary>
    /// Gets the Entity ID of the issuing Identity Provider.
    /// </summary>
    public string Issuer { get; init; }

    /// <summary>
    /// Gets the status code and message.
    /// </summary>
    public Saml2Status Status { get; init; }

    /// <summary>
    /// Gets the collection of unencrypted assertions contained in the response.
    /// </summary>
    public IReadOnlyList<Saml2Assertion> Assertions { get; init; }

    /// <summary>
    /// Gets the raw XML string of the response.
    /// </summary>
    public string RawXml { get; init; }

    /// <summary>
    /// Initializes a new instance of the <see cref="Saml2Response"/> record with the specified response data.
    /// </summary>
    /// <param name="id">The unique identifier of the SAML response.</param>
    /// <param name="issueInstant">The timestamp when the response was issued.</param>
    /// <param name="issuer">The Entity ID of the issuing Identity Provider.</param>
    /// <param name="status">The status code and message.</param>
    /// <param name="rawXml">The raw XML string representation of the response.</param>
    /// <param name="inResponseTo">The optional identifier of the request to which this is a response.</param>
    /// <param name="destination">The optional intended recipient destination URI.</param>
    /// <param name="assertions">The optional collection of unencrypted assertions contained in the response.</param>
    /// <exception cref="ArgumentNullException"><paramref name="status"/> is <see langword="null"/></exception>
    /// <exception cref="ArgumentException"><paramref name="id"/>, <paramref name="issuer"/>, or <paramref name="rawXml"/> is <see langword="null"/>, empty, or whitespace</exception>
    public Saml2Response(
        string id,
        DateTimeOffset issueInstant,
        string issuer,
        Saml2Status status,
        string rawXml,
        string? inResponseTo = null,
        string? destination = null,
        IReadOnlyList<Saml2Assertion>? assertions = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(id);
        ArgumentException.ThrowIfNullOrWhiteSpace(issuer);
        ArgumentNullException.ThrowIfNull(status);
        ArgumentException.ThrowIfNullOrWhiteSpace(rawXml);

        Id = id;
        IssueInstant = issueInstant;
        Issuer = issuer;
        Status = status;
        RawXml = rawXml;
        InResponseTo = inResponseTo;
        Destination = destination;
        Assertions = assertions ?? Array.Empty<Saml2Assertion>();
    }
}
