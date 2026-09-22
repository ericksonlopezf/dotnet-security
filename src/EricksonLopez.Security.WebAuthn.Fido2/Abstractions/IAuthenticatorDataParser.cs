// Copyright © Erickson Lopez. MIT License.

using System;
using EricksonLopez.Result;
using EricksonLopez.Security.WebAuthn.Fido2.Models;

namespace EricksonLopez.Security.WebAuthn.Fido2.Abstractions;

/// <summary>
/// Defines the contract for parsing binary Authenticator Data byte sequences.
/// </summary>
public interface IAuthenticatorDataParser
{
    /// <summary>
    /// Parses an Authenticator Data structure from a byte span.
    /// </summary>
    /// <param name="authDataBytes">The binary authenticatorData span.</param>
    /// <returns>A result containing the parsed <see cref="AuthenticatorData"/> or an error.</returns>
    Result<AuthenticatorData> Parse(ReadOnlySpan<byte> authDataBytes);
}
