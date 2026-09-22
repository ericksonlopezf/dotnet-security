// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.WebAuthn.Fido2.Abstractions;

using EricksonLopez.Result;
using EricksonLopez.Security.WebAuthn.Fido2.Models;

/// <summary>
/// Defines the contract for verifying a specific WebAuthn attestation statement format.
/// </summary>
public interface IAttestationVerifier
{
    /// <summary>
    /// Gets the format string handled by this verifier (e.g. "none", "packed", "fido-u2f").
    /// </summary>
    string Format { get; }

    /// <summary>
    /// Verifies the attestation statement against the authenticator data and client data hash.
    /// </summary>
    /// <param name="statement">The parsed attestation statement.</param>
    /// <param name="authData">The parsed authenticator data.</param>
    /// <param name="clientDataHash">The SHA-256 hash of clientDataJSON.</param>
    /// <returns>A result indicating success or a verification error.</returns>
    Result Verify(AttestationStatement statement, AuthenticatorData authData, byte[] clientDataHash);
}
