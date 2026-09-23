// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.WebAuthn.Fido2.Tests;

using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Formats.Cbor;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using AwesomeAssertions;
using EricksonLopez.Security.Testing.Builders;
using EricksonLopez.Security.WebAuthn.Fido2.Abstractions;
using EricksonLopez.Security.WebAuthn.Fido2.Enums;
using EricksonLopez.Security.WebAuthn.Fido2.Models;
using EricksonLopez.Security.WebAuthn.Fido2.Parsers;
using EricksonLopez.Security.WebAuthn.Fido2.Services;
using EricksonLopez.Security.WebAuthn.Fido2.Verifiers;
using Microsoft.Extensions.Options;
using Xunit;

[Trait("Category", "Unit")]
public sealed class WebAuthnRegistrationCeremonyTests
{
    private readonly WebAuthnCeremonyService _service;
    private readonly WebAuthnOptions _options;

    public WebAuthnRegistrationCeremonyTests()
    {
        (_service, _options) = WebAuthnTestContext.CreateService();
    }

    [Fact]
    public void Constructor_NullArguments_ThrowsArgumentNullException()
    {
        var opts = Options.Create(new WebAuthnOptions());
        var parser = new AuthenticatorDataParser(new CoseKeyParser());
        var verifiers = new IAttestationVerifier[] { new NoneAttestationVerifier() };

        var exOpts = Assert.Throws<ArgumentNullException>(() => new WebAuthnCeremonyService(null!, parser, verifiers));
        exOpts.ParamName.Should().Be("options");

        var exParser = Assert.Throws<ArgumentNullException>(() => new WebAuthnCeremonyService(opts, null!, verifiers));
        exParser.ParamName.Should().Be("authDataParser");

        var exVerifiers = Assert.Throws<ArgumentNullException>(() => new WebAuthnCeremonyService(opts, parser, null!));
        exVerifiers.ParamName.Should().Be("attestationVerifiers");

        var serviceWithNullLogger = new WebAuthnCeremonyService(opts, parser, verifiers, logger: null);
        serviceWithNullLogger.Should().NotBeNull();
    }

    [Fact]
    public void CreateRegistrationOptions_NullUser_ThrowsArgumentNullException()
    {
        var ex = Assert.Throws<ArgumentNullException>(() => _service.CreateRegistrationOptions(null!));
        ex.ParamName.Should().Be("user");
        ex.StackTrace.Should().NotContain("CredentialCreateOptions..ctor");
    }

    [Fact]
    public void CreateRegistrationOptions_GeneratesValidChallengeAndRp()
    {
        var user = new PublicKeyCredentialUserEntity(
            id: [1, 2, 3, 4],
            name: "test@example.com",
            displayName: "Test User");

        var options = _service.CreateRegistrationOptions(user);

        options.Challenge.Should().NotBeNull();
        options.Challenge.Length.Should().Be(32);
        options.Challenge.Should().NotEqual(new byte[32]);
        options.Rp.Id.Should().Be("localhost");
        options.Rp.Name.Should().Be("Test RP");
        options.User.Name.Should().Be("test@example.com");
        options.TimeoutMilliseconds.Should().Be(60000);
        options.ResidentKey.Should().Be(ResidentKeyRequirement.Preferred);
        options.UserVerification.Should().Be(UserVerificationRequirement.Preferred);
        options.Attestation.Should().Be(AttestationConveyancePreference.None);
        options.PubKeyCredParams.Should().NotBeEmpty();

        var custom = new CredentialCreateOptions(new RelyingPartyIdentity("custom.com", "Custom RP"), user, new byte[16], new List<PublicKeyCredentialParameters>());
        var customResult = _service.CreateRegistrationOptions(user, custom);
        customResult.Rp.Id.Should().Be("custom.com");
        customResult.Challenge.Length.Should().Be(32);
    }


    [Fact]
    public async Task VerifyRegistrationAsync_ValidNoneAttestation_ReturnsSuccess()
    {
        var challenge = new byte[32];
        RandomNumberGenerator.Fill(challenge);
        var userHandle = new byte[] { 1, 2, 3, 4 };
        var credId = new byte[] { 10, 20, 30, 40 };

        var (rawResponse, _) = new Fido2AttestationTestBuilder()
            .WithFormat("none")
            .WithCredentialId(credId)
            .WithFlags(AuthenticatorDataFlags.UserPresent | AuthenticatorDataFlags.BackupEligibility | AuthenticatorDataFlags.BackupState)
            .BuildRawAttestationResponse(challenge);

        var result = await _service.VerifyRegistrationAsync(rawResponse, challenge, userHandle);

        result.IsSuccess.Should().BeTrue();
        result.Value.CredentialId.Should().Equal(credId);
        result.Value.UserHandle.Should().Equal(userHandle);
        result.Value.AttestationFormat.Should().Be("none");
        result.Value.IsBackupEligible.Should().BeTrue();
        result.Value.IsBackedUp.Should().BeTrue();
        result.Value.PublicKey.KeyType.Should().Be(CoseKeyType.Ec2);
    }

    [Fact]
    public async Task VerifyRegistrationAsync_InvalidClientDataType_ReturnsFailure()
    {
        var challenge = new byte[32];
        var challengeB64 = Convert.ToBase64String(challenge).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var clientDataJson = Encoding.UTF8.GetBytes(
            $"{{\"type\":\"webauthn.get\",\"challenge\":\"{challengeB64}\",\"origin\":\"https://localhost:5001\"}}");

        var rawResponse = new AuthenticatorAttestationRawResponse(
            id: "id",
            rawId: [1],
            clientDataJson: clientDataJson,
            attestationObject: [1]);

        var result = await _service.VerifyRegistrationAsync(rawResponse, challenge, [1]);
        result.IsFailure.Should().BeTrue();
        result.Error.Description.Should().Contain("Invalid clientData type");

        var clientDataNoType = Encoding.UTF8.GetBytes(
            $"{{\"challenge\":\"{challengeB64}\",\"origin\":\"https://localhost:5001\"}}");
        var rawResponseNoType = new AuthenticatorAttestationRawResponse(
            id: "id",
            rawId: [1],
            clientDataJson: clientDataNoType,
            attestationObject: [1]);
        var resultNoType = await _service.VerifyRegistrationAsync(rawResponseNoType, challenge, [1]);
        resultNoType.IsFailure.Should().BeTrue();
        resultNoType.Error.Description.Should().Contain("Invalid clientData type");
    }

    [Fact]
    public async Task VerifyRegistrationAsync_ChallengeMismatch_ReturnsFailure()
    {
        var challenge = new byte[32];
        var wrongChallenge = new byte[32];
        Array.Fill(wrongChallenge, (byte)0x99);
        var challengeB64 = Convert.ToBase64String(wrongChallenge).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var clientDataJson = Encoding.UTF8.GetBytes(
            $"{{\"type\":\"webauthn.create\",\"challenge\":\"{challengeB64}\",\"origin\":\"https://localhost:5001\"}}");

        var rawResponse = new AuthenticatorAttestationRawResponse(
            id: "id",
            rawId: [1],
            clientDataJson: clientDataJson,
            attestationObject: [1]);

        var result = await _service.VerifyRegistrationAsync(rawResponse, challenge, [1]);
        result.IsFailure.Should().BeTrue();
        result.Error.Description.Should().Contain("Client challenge mismatch");
    }

    [Fact]
    public async Task VerifyRegistrationAsync_UnauthorizedOrigin_ReturnsFailure()
    {
        var challenge = new byte[32];
        var challengeB64 = Convert.ToBase64String(challenge).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var clientDataJson = Encoding.UTF8.GetBytes(
            $"{{\"type\":\"webauthn.create\",\"challenge\":\"{challengeB64}\",\"origin\":\"https://evil-attacker.com\"}}");

        var rawResponse = new AuthenticatorAttestationRawResponse(
            id: "id",
            rawId: [1],
            clientDataJson: clientDataJson,
            attestationObject: [1]);

        var result = await _service.VerifyRegistrationAsync(rawResponse, challenge, [1]);
        result.IsFailure.Should().BeTrue();
        result.Error.Description.Should().Contain("WebAuthn.Origin");
        result.Error.Description.Should().Contain("is not authorized");

        var clientDataEmptyOrigin = Encoding.UTF8.GetBytes(
            $"{{\"type\":\"webauthn.create\",\"challenge\":\"{challengeB64}\",\"origin\":\"\"}}");
        var rawResponseEmptyOrigin = new AuthenticatorAttestationRawResponse(
            id: "id",
            rawId: [1],
            clientDataJson: clientDataEmptyOrigin,
            attestationObject: [1]);
        var resultEmptyOrigin = await _service.VerifyRegistrationAsync(rawResponseEmptyOrigin, challenge, [1]);
        resultEmptyOrigin.IsFailure.Should().BeTrue();
        resultEmptyOrigin.Error.Description.Should().Contain("WebAuthn.Origin");
        resultEmptyOrigin.Error.Description.Should().Contain("is not authorized");
    }

    [Fact]
    public async Task VerifyRegistrationAsync_UnsupportedAttestationFormat_ReturnsFailure()
    {
        var challenge = new byte[32];
        var challengeB64 = Convert.ToBase64String(challenge).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var clientDataJson = Encoding.UTF8.GetBytes(
            $"{{\"type\":\"webauthn.create\",\"challenge\":\"{challengeB64}\",\"origin\":\"https://localhost:5001\"}}");

        var authDataBuffer = WebAuthnTestContext.CreateAuthDataBuffer("localhost");

        var attWriter = new CborWriter(CborConformanceMode.Lax);
        attWriter.WriteStartMap(3);
        attWriter.WriteTextString("fmt");
        attWriter.WriteTextString("unknown-custom-fmt");
        attWriter.WriteTextString("attStmt");
        attWriter.WriteStartMap(0);
        attWriter.WriteEndMap();
        attWriter.WriteTextString("authData");
        attWriter.WriteByteString(authDataBuffer);
        attWriter.WriteEndMap();

        var rawResponse = new AuthenticatorAttestationRawResponse(
            id: "id",
            rawId: [1],
            clientDataJson: clientDataJson,
            attestationObject: attWriter.Encode());

        var result = await _service.VerifyRegistrationAsync(rawResponse, challenge, [1]);
        result.IsFailure.Should().BeTrue();
        result.Error.Description.Should().Contain("Unsupported attestation statement format");
    }

    [Fact]
    public async Task VerifyRegistrationAsync_NullArguments_ThrowsArgumentNullException()
    {
        var rawResponse = new AuthenticatorAttestationRawResponse("1", [1], [1], [1]);
        await Assert.ThrowsAsync<ArgumentNullException>(() => _service.VerifyRegistrationAsync(null!, [1], [1]));
        await Assert.ThrowsAsync<ArgumentNullException>(() => _service.VerifyRegistrationAsync(rawResponse, null!, [1]));
        await Assert.ThrowsAsync<ArgumentNullException>(() => _service.VerifyRegistrationAsync(rawResponse, [1], null!));
    }

    [Fact]
    public async Task VerifyRegistrationAsync_UserPresentFalse_ReturnsFailure()
    {
        var challenge = new byte[32];
        var challengeB64 = Convert.ToBase64String(challenge).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var clientDataJson = Encoding.UTF8.GetBytes(
            $"{{\"type\":\"webauthn.create\",\"challenge\":\"{challengeB64}\",\"origin\":\"https://localhost:5001\"}}");

        var authDataBuffer = new byte[37 + 16 + 2 + 1 + 10];
        var rpIdHash = SHA256.HashData(Encoding.UTF8.GetBytes("localhost"));
        Buffer.BlockCopy(rpIdHash, 0, authDataBuffer, 0, 32);
        authDataBuffer[32] = (byte)AuthenticatorDataFlags.AttestedCredentialData; // UP is NOT set

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

        var attWriter = new CborWriter(CborConformanceMode.Lax);
        attWriter.WriteStartMap(3);
        attWriter.WriteTextString("fmt");
        attWriter.WriteTextString("none");
        attWriter.WriteTextString("attStmt");
        attWriter.WriteStartMap(0);
        attWriter.WriteEndMap();
        attWriter.WriteTextString("authData");
        attWriter.WriteByteString(authDataBuffer);
        attWriter.WriteEndMap();

        var rawResponse = new AuthenticatorAttestationRawResponse("1", [1], clientDataJson, attWriter.Encode());
        var result = await _service.VerifyRegistrationAsync(rawResponse, challenge, [1]);

        result.IsFailure.Should().BeTrue();
        result.Error.Description.Should().Contain("User Present (UP) bit was not set");
    }

    [Fact]
    public async Task VerifyRegistrationAsync_RpIdMismatch_ReturnsFailure()
    {
        var challenge = new byte[32];
        var challengeB64 = Convert.ToBase64String(challenge).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var clientDataJson = Encoding.UTF8.GetBytes(
            $"{{\"type\":\"webauthn.create\",\"challenge\":\"{challengeB64}\",\"origin\":\"https://localhost:5001\"}}");

        var credId = new byte[] { 1, 2, 3, 4 };
        var writer = new CborWriter(CborConformanceMode.Lax);
        writer.WriteStartMap(2);
        writer.WriteInt32(1);
        writer.WriteInt32((int)CoseKeyType.Ec2);
        writer.WriteInt32(3);
        writer.WriteInt32((int)CoseAlgorithmIdentifier.ES256);
        writer.WriteEndMap();
        var coseBytes = writer.Encode();

        var authDataBuffer = new byte[37 + 16 + 2 + credId.Length + coseBytes.Length];
        var wrongRpIdHash = SHA256.HashData(Encoding.UTF8.GetBytes("wrong.rp.com"));
        Buffer.BlockCopy(wrongRpIdHash, 0, authDataBuffer, 0, 32);
        authDataBuffer[32] = (byte)(AuthenticatorDataFlags.UserPresent | AuthenticatorDataFlags.AttestedCredentialData);

        var aaguid = Guid.NewGuid();
        Buffer.BlockCopy(aaguid.ToByteArray(bigEndian: true), 0, authDataBuffer, 37, 16);
        BinaryPrimitives.WriteUInt16BigEndian(authDataBuffer.AsSpan(53, 2), (ushort)credId.Length);
        Buffer.BlockCopy(credId, 0, authDataBuffer, 55, credId.Length);
        Buffer.BlockCopy(coseBytes, 0, authDataBuffer, 55 + credId.Length, coseBytes.Length);

        var attWriter = new CborWriter(CborConformanceMode.Lax);
        attWriter.WriteStartMap(3);
        attWriter.WriteTextString("fmt");
        attWriter.WriteTextString("none");
        attWriter.WriteTextString("attStmt");
        attWriter.WriteStartMap(0);
        attWriter.WriteEndMap();
        attWriter.WriteTextString("authData");
        attWriter.WriteByteString(authDataBuffer);
        attWriter.WriteEndMap();

        var rawResponse = new AuthenticatorAttestationRawResponse("1", [1], clientDataJson, attWriter.Encode());
        var result = await _service.VerifyRegistrationAsync(rawResponse, challenge, [1]);

        result.IsFailure.Should().BeTrue();
        result.Error.Description.Should().Contain("RP ID hash in authenticatorData does not match");
    }

    [Fact]
    public async Task VerifyRegistrationAsync_InvalidAttestationCbor_ReturnsFailure()
    {
        var challenge = new byte[32];
        var challengeB64 = Convert.ToBase64String(challenge).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var clientDataJson = Encoding.UTF8.GetBytes(
            $"{{\"type\":\"webauthn.create\",\"challenge\":\"{challengeB64}\",\"origin\":\"https://localhost:5001\"}}");

        var rawResponse = new AuthenticatorAttestationRawResponse("1", [1], clientDataJson, [0xFF, 0x00]);
        var result = await _service.VerifyRegistrationAsync(rawResponse, challenge, [1]);

        result.IsFailure.Should().BeTrue();
        result.Error.Description.Should().Contain("Failed to parse attestationObject CBOR");
    }

    [Fact]
    public async Task VerifyRegistrationAsync_AttestedCredentialDataMissing_ReturnsFailure()
    {
        var challenge = new byte[32];
        var challengeB64 = Convert.ToBase64String(challenge).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var clientDataJson = Encoding.UTF8.GetBytes(
            $"{{\"type\":\"webauthn.create\",\"challenge\":\"{challengeB64}\",\"origin\":\"https://localhost:5001\"}}");

        var authDataBuffer = new byte[37];
        var rpIdHash = SHA256.HashData(Encoding.UTF8.GetBytes("localhost"));
        Buffer.BlockCopy(rpIdHash, 0, authDataBuffer, 0, 32);
        authDataBuffer[32] = (byte)AuthenticatorDataFlags.UserPresent;

        var attWriter = new CborWriter(CborConformanceMode.Lax);
        attWriter.WriteStartMap(3);
        attWriter.WriteTextString("fmt");
        attWriter.WriteTextString("none");
        attWriter.WriteTextString("attStmt");
        attWriter.WriteStartMap(0);
        attWriter.WriteEndMap();
        attWriter.WriteTextString("authData");
        attWriter.WriteByteString(authDataBuffer);
        attWriter.WriteEndMap();

        var rawResponse = new AuthenticatorAttestationRawResponse("1", [1], clientDataJson, attWriter.Encode());
        var result = await _service.VerifyRegistrationAsync(rawResponse, challenge, [1]);

        result.IsFailure.Should().BeTrue();
        result.Error.Description.Should().Contain("Attested Credential Data missing from registration authenticatorData");
    }

    [Fact]
    public async Task VerifyRegistrationAsync_AttStmtWithResponseByteString_Succeeds()
    {
        var challenge = new byte[32];
        var challengeB64 = Convert.ToBase64String(challenge).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var clientDataJson = Encoding.UTF8.GetBytes(
            $"{{\"type\":\"webauthn.create\",\"challenge\":\"{challengeB64}\",\"origin\":\"https://localhost:5001\"}}");

        var authDataBuffer = WebAuthnTestContext.CreateAuthDataBuffer("localhost");

        var attWriter = new CborWriter(CborConformanceMode.Lax);
        attWriter.WriteStartMap(3);
        attWriter.WriteTextString("fmt");
        attWriter.WriteTextString("none");
        attWriter.WriteTextString("attStmt");
        attWriter.WriteStartMap(1);
        attWriter.WriteTextString("response");
        attWriter.WriteByteString([1, 2, 3]);
        attWriter.WriteEndMap();
        attWriter.WriteTextString("authData");
        attWriter.WriteByteString(authDataBuffer);
        attWriter.WriteEndMap();

        var rawResponse = new AuthenticatorAttestationRawResponse("1", [1], clientDataJson, attWriter.Encode());
        var result = await _service.VerifyRegistrationAsync(rawResponse, challenge, [1]);

        result.IsSuccess.Should().BeTrue();
    }

    [Fact]
    public void CreateOptions_WithCustomWebAuthnOptions_HonorsCustomValues()
    {
        var customOpts = new WebAuthnOptions
        {
            CeremonyTimeoutMilliseconds = 12345,
            DefaultResidentKey = ResidentKeyRequirement.Required,
            DefaultUserVerification = UserVerificationRequirement.Required
        };
        var parser = new AuthenticatorDataParser(new CoseKeyParser());
        var verifiers = new IAttestationVerifier[] { new NoneAttestationVerifier() };
        var service = new WebAuthnCeremonyService(Options.Create(customOpts), parser, verifiers);

        var user = new PublicKeyCredentialUserEntity([1], "name", "display");
        var reg = service.CreateRegistrationOptions(user);
        reg.TimeoutMilliseconds.Should().Be(12345);
        reg.ResidentKey.Should().Be(ResidentKeyRequirement.Required);
        reg.UserVerification.Should().Be(UserVerificationRequirement.Required);

        var auth = service.CreateAuthenticationOptions();
        auth.TimeoutMilliseconds.Should().Be(12345);
        auth.UserVerification.Should().Be(UserVerificationRequirement.Required);
    }

    [Fact]
    public async Task VerifyRegistrationAsync_WhenCrossOriginIsTrue_ReturnsExpectedResult()
    {
        var challenge = new byte[32];
        var challengeB64 = Convert.ToBase64String(challenge).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var clientDataJson = Encoding.UTF8.GetBytes(
            $"{{\"type\":\"webauthn.create\",\"challenge\":\"{challengeB64}\",\"origin\":\"https://localhost:5001\",\"crossOrigin\":true}}");

        var clientDataRes = _service.ParseAndValidateClientData(clientDataJson, "webauthn.create", challenge);
        clientDataRes.IsSuccess.Should().BeTrue();
        clientDataRes.Value.CrossOrigin.Should().BeTrue();

        var authDataBuffer = WebAuthnTestContext.CreateAuthDataBuffer();
        var attWriter = new CborWriter(CborConformanceMode.Lax);
        attWriter.WriteStartMap(3);
        attWriter.WriteTextString("fmt");
        attWriter.WriteTextString("none");
        attWriter.WriteTextString("attStmt");
        attWriter.WriteStartMap(0);
        attWriter.WriteEndMap();
        attWriter.WriteTextString("authData");
        attWriter.WriteByteString(authDataBuffer);
        attWriter.WriteEndMap();

        var rawResponse = new AuthenticatorAttestationRawResponse("1", [1], clientDataJson, attWriter.Encode());
        var result = await _service.VerifyRegistrationAsync(rawResponse, challenge, [1]);
        result.IsSuccess.Should().BeTrue();
    }

    [Fact]
    public async Task VerifyRegistrationAsync_UntrustedOrigin_ReturnsSecurityPolicyViolation()
    {
        var challenge = new byte[32];
        RandomNumberGenerator.Fill(challenge);
        var challengeB64 = Convert.ToBase64String(challenge).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var clientDataJson = Encoding.UTF8.GetBytes(
            $"{{\"type\":\"webauthn.create\",\"challenge\":\"{challengeB64}\",\"origin\":\"https://evil-unauthorized.com\"}}");

        var authDataBuffer = WebAuthnTestContext.CreateAuthDataBuffer();
        var attWriter = new CborWriter(CborConformanceMode.Lax);
        attWriter.WriteStartMap(3);
        attWriter.WriteTextString("fmt");
        attWriter.WriteTextString("none");
        attWriter.WriteTextString("attStmt");
        attWriter.WriteStartMap(0);
        attWriter.WriteEndMap();
        attWriter.WriteTextString("authData");
        attWriter.WriteByteString(authDataBuffer);
        attWriter.WriteEndMap();

        var rawResponse = new AuthenticatorAttestationRawResponse("1", [1], clientDataJson, attWriter.Encode());
        var result = await _service.VerifyRegistrationAsync(rawResponse, challenge, [1]);
        result.IsFailure.Should().BeTrue();
        result.Error.Code.Should().Be("Security.PolicyViolation");
        result.Error.Description.Should().Contain("WebAuthn.Origin");
        result.Error.Description.Should().Contain("Origin 'https://evil-unauthorized.com' is not authorized.");
    }
}
