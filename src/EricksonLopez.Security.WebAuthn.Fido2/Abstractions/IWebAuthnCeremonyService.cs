// Copyright © Erickson Lopez. MIT License.

using System.Threading;
using System.Threading.Tasks;
using EricksonLopez.Result;
using EricksonLopez.Security.WebAuthn.Fido2.Models;

namespace EricksonLopez.Security.WebAuthn.Fido2.Abstractions;

/// <summary>
/// Defines the contract for orchestrating WebAuthn Level 2/3 registration and authentication ceremonies.
/// </summary>
public interface IWebAuthnCeremonyService
{
    /// <summary>
    /// Generates the options payload required to initiate a credential creation ceremony.
    /// </summary>
    /// <param name="user">The user entity creating the credential.</param>
    /// <param name="customOptions">Optional overrides for default options.</param>
    /// <returns>A new <see cref="CredentialCreateOptions"/> instance containing a fresh cryptographic challenge.</returns>
    CredentialCreateOptions CreateRegistrationOptions(
        PublicKeyCredentialUserEntity user,
        CredentialCreateOptions? customOptions = null);

    /// <summary>
    /// Validates an authenticator attestation response during registration.
    /// </summary>
    /// <param name="response">The raw attestation response received from the browser.</param>
    /// <param name="expectedChallenge">The expected challenge issued to the client.</param>
    /// <param name="userHandle">The expected user handle.</param>
    /// <param name="cancellationToken">A token that can be used to cancel the asynchronous operation.</param>
    /// <returns>A task representing the asynchronous operation. The task result contains a result indicating whether registration verification succeeded, containing the verified credential registration model.</returns>
    Task<Result<VerifiedCredentialRegistration>> VerifyRegistrationAsync(
        AuthenticatorAttestationRawResponse response,
        byte[] expectedChallenge,
        byte[] userHandle,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Generates the options payload required to initiate a credential assertion (authentication) ceremony.
    /// </summary>
    /// <param name="customOptions">Optional overrides for default options.</param>
    /// <returns>A new <see cref="CredentialRequestOptions"/> instance containing a fresh cryptographic challenge.</returns>
    CredentialRequestOptions CreateAuthenticationOptions(CredentialRequestOptions? customOptions = null);

    /// <summary>
    /// Validates an authenticator assertion response during authentication.
    /// </summary>
    /// <param name="response">The raw assertion response received from the browser.</param>
    /// <param name="expectedChallenge">The expected challenge issued to the client.</param>
    /// <param name="storedPublicKey">The credential's stored COSE public key.</param>
    /// <param name="storedSignCount">The last recorded signature counter for the credential.</param>
    /// <param name="userVerificationRequired">A value indicating whether user verification is strictly required.</param>
    /// <param name="cancellationToken">A token that can be used to cancel the asynchronous operation.</param>
    /// <returns>A task representing the asynchronous operation. The task result contains a result indicating whether authentication verification succeeded, containing the verified credential assertion model.</returns>
    Task<Result<VerifiedCredentialAssertion>> VerifyAuthenticationAsync(
        AuthenticatorAssertionRawResponse response,
        byte[] expectedChallenge,
        CosePublicKey storedPublicKey,
        uint storedSignCount,
        bool userVerificationRequired = false,
        CancellationToken cancellationToken = default);
}
