// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Saml2.Models;

using System;

/// <summary>
/// Represents a SAML 2.0 Subject containing the principal identifier and confirmation data.
/// </summary>
public sealed record Saml2Subject
{
    /// <summary>
    /// Gets the subject's NameID identifier.
    /// </summary>
    public Saml2NameId NameId { get; init; }

    /// <summary>
    /// Gets the subject confirmation details (typically bearer confirmation).
    /// </summary>
    public Saml2SubjectConfirmation? Confirmation { get; init; }

    /// <summary>
    /// Initializes a new instance of the <see cref="Saml2Subject"/> record with the specified NameID and optional confirmation.
    /// </summary>
    /// <param name="nameId">The subject's NameID identifier.</param>
    /// <param name="confirmation">The optional subject confirmation details.</param>
    /// <exception cref="ArgumentNullException"><paramref name="nameId"/> is <see langword="null"/></exception>
    public Saml2Subject(Saml2NameId nameId, Saml2SubjectConfirmation? confirmation = null)
    {
        NameId = nameId ?? throw new ArgumentNullException(nameof(nameId));
        Confirmation = confirmation;
    }
}
