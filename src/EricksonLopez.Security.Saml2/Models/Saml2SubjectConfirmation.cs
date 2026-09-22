// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Saml2.Models;

using System;

/// <summary>
/// Represents a SAML 2.0 SubjectConfirmation element defining the mechanism for verifying the subject.
/// </summary>
public sealed record Saml2SubjectConfirmation
{
    /// <summary>
    /// Gets the confirmation method URI (e.g. <c>urn:oasis:names:tc:SAML:2.0:cm:bearer</c>).
    /// </summary>
    public string Method { get; init; }

    /// <summary>
    /// Gets the optional Recipient URL (Assertion Consumer Service URL).
    /// </summary>
    public string? Recipient { get; init; }

    /// <summary>
    /// Gets the optional InResponseTo request ID.
    /// </summary>
    public string? InResponseTo { get; init; }

    /// <summary>
    /// Gets the optional NotOnOrAfter timestamp limit.
    /// </summary>
    public DateTimeOffset? NotOnOrAfter { get; init; }

    /// <summary>
    /// Initializes a new instance of the <see cref="Saml2SubjectConfirmation"/> record with the specified confirmation method and optional constraints.
    /// </summary>
    /// <param name="method">The confirmation method URI (e.g., bearer).</param>
    /// <param name="recipient">The optional recipient URL.</param>
    /// <param name="inResponseTo">The optional InResponseTo request identifier.</param>
    /// <param name="notOnOrAfter">The optional timestamp limit after which the confirmation is invalid.</param>
    /// <exception cref="ArgumentException"><paramref name="method"/> is <see langword="null"/>, empty, or whitespace</exception>
    public Saml2SubjectConfirmation(
        string method,
        string? recipient = null,
        string? inResponseTo = null,
        DateTimeOffset? notOnOrAfter = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(method);
        Method = method;
        Recipient = recipient;
        InResponseTo = inResponseTo;
        NotOnOrAfter = notOnOrAfter;
    }
}
