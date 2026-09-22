// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.WebAuthn.Fido2.Tests;

using System;
using System.Buffers.Binary;
using System.Formats.Cbor;
using System.Security.Cryptography;
using System.Text;
using EricksonLopez.Security.WebAuthn.Fido2.Abstractions;
using EricksonLopez.Security.WebAuthn.Fido2.Enums;
using EricksonLopez.Security.WebAuthn.Fido2.Models;
using EricksonLopez.Security.WebAuthn.Fido2.Parsers;
using EricksonLopez.Security.WebAuthn.Fido2.Services;
using EricksonLopez.Security.WebAuthn.Fido2.Verifiers;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

internal static class WebAuthnTestContext
{
    public static (WebAuthnCeremonyService Service, WebAuthnOptions Options) CreateService(
        Action<WebAuthnOptions>? configure = null,
        Microsoft.Extensions.Logging.ILogger<WebAuthnCeremonyService>? logger = null)
    {
        var options = new WebAuthnOptions
        {
            RpId = "localhost",
            RpName = "Test RP",
            AllowedOrigins = { "https://localhost:5001" },
            ChallengeLengthBytes = 32,
            CeremonyTimeoutMilliseconds = 60000,
            DefaultResidentKey = ResidentKeyRequirement.Preferred,
            DefaultUserVerification = UserVerificationRequirement.Preferred
        };
        configure?.Invoke(options);

        var coseParser = new CoseKeyParser();
        var authDataParser = new AuthenticatorDataParser(coseParser);
        var verifiers = new IAttestationVerifier[]
        {
            new NoneAttestationVerifier(),
            new PackedAttestationVerifier(),
            new FidoU2FAttestationVerifier(),
            new AndroidSafetyNetAttestationVerifier(),
            new TpmAttestationVerifier()
        };

        var service = new WebAuthnCeremonyService(
            Options.Create(options),
            authDataParser,
            verifiers,
            logger ?? NullLogger<WebAuthnCeremonyService>.Instance);

        return (service, options);
    }

    public static byte[] CreateAuthDataBuffer(string rpId = "localhost")
    {
        var authDataBuffer = new byte[37 + 16 + 2 + 1 + 10];
        var rpIdHash = SHA256.HashData(Encoding.UTF8.GetBytes(rpId));
        Buffer.BlockCopy(rpIdHash, 0, authDataBuffer, 0, 32);
        authDataBuffer[32] = (byte)(AuthenticatorDataFlags.UserPresent | AuthenticatorDataFlags.AttestedCredentialData);

        var aaguid = Guid.NewGuid();
        Buffer.BlockCopy(aaguid.ToByteArray(bigEndian: true), 0, authDataBuffer, 37, 16);
        BinaryPrimitives.WriteUInt16BigEndian(authDataBuffer.AsSpan(53, 2), 1);
        authDataBuffer[55] = 0x01;

        var writer = new CborWriter(CborConformanceMode.Lax);
        writer.WriteStartMap(2);
        writer.WriteInt32(1);
        writer.WriteInt32((int)CoseKeyType.Ec2);
        writer.WriteInt32(3);
        writer.WriteInt32((int)CoseAlgorithmIdentifier.ES256);
        writer.WriteEndMap();
        Buffer.BlockCopy(writer.Encode(), 0, authDataBuffer, 56, writer.Encode().Length);
        return authDataBuffer;
    }
}
