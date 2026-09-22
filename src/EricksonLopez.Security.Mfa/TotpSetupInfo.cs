// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Mfa;

/// <summary>
/// Encapsulates the configuration details and URI required to enroll a user in TOTP multi-factor authentication.
/// </summary>
/// <param name="SecretKey">The Base32 encoded secret key.</param>
/// <param name="FormattedSecretKey">The secret key formatted in 4-character chunks for manual entry.</param>
/// <param name="AuthenticatorUri">The standard <c>otpauth://</c> URI for generating QR codes.</param>
public sealed record TotpSetupInfo(
    string SecretKey,
    string FormattedSecretKey,
    string AuthenticatorUri);
