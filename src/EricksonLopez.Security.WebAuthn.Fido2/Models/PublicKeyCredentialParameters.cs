// Copyright © Erickson Lopez. MIT License.

using EricksonLopez.Security.WebAuthn.Fido2.Enums;

namespace EricksonLopez.Security.WebAuthn.Fido2.Models;

/// <summary>
/// Specifies the desired credential properties (type and cryptographic algorithm).
/// </summary>
public sealed record PublicKeyCredentialParameters
{
    /// <summary>
    /// Gets the credential type (always <see cref="PublicKeyCredentialType.PublicKey"/>).
    /// </summary>
    public PublicKeyCredentialType Type { get; init; } = PublicKeyCredentialType.PublicKey;

    /// <summary>
    /// Gets the cryptographic algorithm identifier (e.g. ES256 = -7, RS256 = -257).
    /// </summary>
    public CoseAlgorithmIdentifier Alg { get; init; }

    /// <summary>
    /// Initializes a new instance of the <see cref="PublicKeyCredentialParameters"/> record.
    /// </summary>
    /// <param name="alg">The COSE algorithm identifier.</param>
    public PublicKeyCredentialParameters(CoseAlgorithmIdentifier alg)
    {
        Alg = alg;
    }
}
