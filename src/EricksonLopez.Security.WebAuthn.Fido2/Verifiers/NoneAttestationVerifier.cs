// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.WebAuthn.Fido2.Verifiers;

using EricksonLopez.Result;
using EricksonLopez.Security.Abstractions.Errors;
using EricksonLopez.Security.WebAuthn.Fido2.Abstractions;
using EricksonLopez.Security.WebAuthn.Fido2.Models;

/// <summary>
/// Verifies the "none" attestation statement format (standard for privacy-preserving authenticators and passkeys).
/// </summary>
public sealed class NoneAttestationVerifier : IAttestationVerifier
{
    /// <summary>
    /// Gets the attestation statement format identifier ("none").
    /// </summary>
    public string Format => "none";

    /// <inheritdoc />
    public Result Verify(AttestationStatement statement, AuthenticatorData authData, byte[] clientDataHash)
    {
        if (statement.Signature is not null && statement.Signature.Length > 0)
        {
            return Result.Failure(SecurityError.InvalidToken("Attestation format 'none' must not contain a signature."));
        }

        if (statement.X5c is not null && statement.X5c.Count > 0)
        {
            return Result.Failure(SecurityError.InvalidToken("Attestation format 'none' must not contain an x5c certificate chain."));
        }

        return Result.Success();
    }
}
