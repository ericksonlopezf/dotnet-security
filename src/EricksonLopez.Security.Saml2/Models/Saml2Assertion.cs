// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Saml2.Models;

using System;
using System.Collections.Generic;

/// <summary>
/// Represents a validated, unencrypted SAML 2.0 Assertion.
/// </summary>
public sealed record Saml2Assertion
{
    /// <summary>
    /// Gets the unique ID of the assertion.
    /// </summary>
    public string Id { get; init; }

    /// <summary>
    /// Gets the issue instant of the assertion.
    /// </summary>
    public DateTimeOffset IssueInstant { get; init; }

    /// <summary>
    /// Gets the Entity ID of the issuing Identity Provider.
    /// </summary>
    public string Issuer { get; init; }

    /// <summary>
    /// Gets the authenticated Subject.
    /// </summary>
    public Saml2Subject Subject { get; init; }

    /// <summary>
    /// Gets the validity conditions and audience restrictions.
    /// </summary>
    public Saml2Conditions? Conditions { get; init; }

    /// <summary>
    /// Gets the authentication statement details.
    /// </summary>
    public Saml2AuthnStatement? AuthnStatement { get; init; }

    /// <summary>
    /// Gets the collection of user attributes.
    /// </summary>
    public IReadOnlyList<Saml2Attribute> Attributes { get; init; }

    /// <summary>
    /// Gets the raw XML string of the assertion.
    /// </summary>
    public string RawXml { get; init; }

    /// <summary>
    /// Initializes a new instance of the <see cref="Saml2Assertion"/> record with the specified assertion data.
    /// </summary>
    /// <param name="id">The unique identifier of the assertion.</param>
    /// <param name="issueInstant">The timestamp when the assertion was issued.</param>
    /// <param name="issuer">The Entity ID of the issuing Identity Provider.</param>
    /// <param name="subject">The authenticated security principal subject.</param>
    /// <param name="rawXml">The raw XML string representation of the assertion.</param>
    /// <param name="conditions">The optional validity conditions and audience restrictions.</param>
    /// <param name="authnStatement">The optional authentication statement details.</param>
    /// <param name="attributes">The optional collection of user attributes.</param>
    /// <exception cref="ArgumentNullException"><paramref name="subject"/> is <see langword="null"/></exception>
    /// <exception cref="ArgumentException"><paramref name="id"/>, <paramref name="issuer"/>, or <paramref name="rawXml"/> is <see langword="null"/>, empty, or whitespace</exception>
    public Saml2Assertion(
        string id,
        DateTimeOffset issueInstant,
        string issuer,
        Saml2Subject subject,
        string rawXml,
        Saml2Conditions? conditions = null,
        Saml2AuthnStatement? authnStatement = null,
        IReadOnlyList<Saml2Attribute>? attributes = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(id);
        ArgumentException.ThrowIfNullOrWhiteSpace(issuer);
        ArgumentNullException.ThrowIfNull(subject);
        ArgumentException.ThrowIfNullOrWhiteSpace(rawXml);

        Id = id;
        IssueInstant = issueInstant;
        Issuer = issuer;
        Subject = subject;
        RawXml = rawXml;
        Conditions = conditions;
        AuthnStatement = authnStatement;
        Attributes = attributes ?? Array.Empty<Saml2Attribute>();
    }
}
