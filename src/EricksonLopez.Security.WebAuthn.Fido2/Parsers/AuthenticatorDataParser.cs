// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.WebAuthn.Fido2.Parsers;

using System;
using System.Buffers.Binary;
using EricksonLopez.Result;
using EricksonLopez.Security.Abstractions.Errors;
using EricksonLopez.Security.WebAuthn.Fido2.Abstractions;
using EricksonLopez.Security.WebAuthn.Fido2.Enums;
using EricksonLopez.Security.WebAuthn.Fido2.Models;

/// <summary>
/// Parses binary WebAuthn Authenticator Data byte sequences.
/// </summary>
public sealed class AuthenticatorDataParser : IAuthenticatorDataParser
{
    private readonly ICoseKeyParser _coseKeyParser;

    /// <summary>
    /// Initializes a new instance of the <see cref="AuthenticatorDataParser"/> class.
    /// </summary>
    /// <param name="coseKeyParser">The COSE key parser implementation.</param>
    /// <exception cref="ArgumentNullException"><paramref name="coseKeyParser"/> is <see langword="null"/></exception>
    public AuthenticatorDataParser(ICoseKeyParser coseKeyParser)
    {
        _coseKeyParser = coseKeyParser ?? throw new ArgumentNullException(nameof(coseKeyParser));
    }

    /// <inheritdoc />
    public Result<AuthenticatorData> Parse(ReadOnlySpan<byte> authDataBytes)
    {
        if (authDataBytes.Length < 37)
        {
            return Result<AuthenticatorData>.Failure(
                SecurityError.InvalidToken($"AuthenticatorData too short: expected at least 37 bytes, got {authDataBytes.Length}."));
        }

        var rpIdHash = authDataBytes.Slice(0, 32).ToArray();
        var flags = (AuthenticatorDataFlags)authDataBytes[32];
        var signCount = BinaryPrimitives.ReadUInt32BigEndian(authDataBytes.Slice(33, 4));

        AttestedCredentialData? attestedData = null;
        byte[]? extensionData = null;
        var offset = 37;

        if (flags.HasFlag(AuthenticatorDataFlags.AttestedCredentialData))
        {
            if (authDataBytes.Length < offset + 18) // 16 bytes AAGUID + 2 bytes CredentialIdLength
            {
                return Result<AuthenticatorData>.Failure(
                    SecurityError.InvalidToken("AuthenticatorData has AT flag set but payload is truncated before AAGUID / CredentialIdLength."));
            }

            var aaguidBytes = authDataBytes.Slice(offset, 16);
            var aaguid = new Guid(aaguidBytes, bigEndian: true);
            offset += 16;

            var credIdLength = BinaryPrimitives.ReadUInt16BigEndian(authDataBytes.Slice(offset, 2));
            offset += 2;

            if (authDataBytes.Length < offset + credIdLength)
            {
                return Result<AuthenticatorData>.Failure(
                    SecurityError.InvalidToken($"AuthenticatorData payload truncated: expected {credIdLength} bytes for CredentialId."));
            }

            var credentialId = authDataBytes.Slice(offset, credIdLength).ToArray();
            offset += credIdLength;

            // The remaining bytes up to extension data represent the COSE public key CBOR map
            var coseBytes = authDataBytes.Slice(offset);
            var coseResult = _coseKeyParser.Parse(coseBytes);

            if (coseResult.IsFailure)
            {
                return Result<AuthenticatorData>.Failure(coseResult.Error);
            }

            var coseKey = coseResult.Value;
            var attestedRawBytes = authDataBytes.Slice(37, 18 + credIdLength + coseKey.RawBytes.Length).ToArray();
            attestedData = new AttestedCredentialData(aaguid, credentialId, coseKey, attestedRawBytes);

            offset += coseKey.RawBytes.Length;
        }

        if (flags.HasFlag(AuthenticatorDataFlags.ExtensionData) && offset < authDataBytes.Length)
        {
            extensionData = authDataBytes.Slice(offset).ToArray();
        }

        var result = new AuthenticatorData(
            rpIdHash,
            flags,
            signCount,
            authDataBytes.ToArray(),
            attestedData,
            extensionData);

        return Result<AuthenticatorData>.Success(result);
    }
}
