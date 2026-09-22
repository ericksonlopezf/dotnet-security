// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.WebAuthn.Fido2.Tests;

using System;
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using AwesomeAssertions;
using EricksonLopez.Security.Testing.Logging;
using EricksonLopez.Security.WebAuthn.Fido2.Enums;
using EricksonLopez.Security.WebAuthn.Fido2.Models;
using EricksonLopez.Security.WebAuthn.Fido2.Services;
using Xunit;

[Trait("Category", "Unit")]
public sealed class WebAuthnAuthenticationCeremonyTests
{
    private readonly WebAuthnCeremonyService _service;
    private readonly WebAuthnOptions _options;

    public WebAuthnAuthenticationCeremonyTests()
    {
        (_service, _options) = WebAuthnTestContext.CreateService();
    }

    [Fact]
    public void CreateAuthenticationOptions_GeneratesValidChallenge()
    {
        var options = _service.CreateAuthenticationOptions();

        options.Challenge.Should().NotBeNull();
        options.Challenge.Length.Should().Be(32);
        options.Challenge.Should().NotEqual(new byte[32]);
        options.RpId.Should().Be("localhost");
        options.TimeoutMilliseconds.Should().Be(60000);
        options.UserVerification.Should().Be(UserVerificationRequirement.Preferred);
    }

    [Fact]
    public void CreateAuthenticationOptions_WithCustomOptions_ReturnsCustomOptionsWithNewChallenge()
    {
        var custom = new CredentialRequestOptions(new byte[] { 1, 2, 3 }, "custom-rp")
        {
            TimeoutMilliseconds = 12345,
            UserVerification = UserVerificationRequirement.Required
        };

        var result = _service.CreateAuthenticationOptions(custom);

        result.RpId.Should().Be("custom-rp");
        result.TimeoutMilliseconds.Should().Be(12345);
        result.UserVerification.Should().Be(UserVerificationRequirement.Required);
        result.Challenge.Should().NotBeNull();
        result.Challenge.Length.Should().Be(32);
        result.Challenge.Should().NotEqual(new byte[] { 1, 2, 3 });
    }

    [Fact]
    public async Task VerifyAuthenticationAsync_ValidSignature_ReturnsSuccessAndDetectsClones()
    {
        var challenge = new byte[32];
        RandomNumberGenerator.Fill(challenge);
        var credId = new byte[] { 10, 20, 30, 40 };

        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var ecParams = ecdsa.ExportParameters(false);

        var coseKey = new CosePublicKey(
            CoseKeyType.Ec2,
            CoseAlgorithmIdentifier.ES256,
            Array.Empty<byte>(),
            CoseEllipticCurve.P256,
            x: ecParams.Q.X,
            y: ecParams.Q.Y);

        var challengeB64 = Convert.ToBase64String(challenge).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var clientDataJson = Encoding.UTF8.GetBytes(
            $"{{\"type\":\"webauthn.get\",\"challenge\":\"{challengeB64}\",\"origin\":\"https://localhost:5001\"}}");
        var clientDataHash = SHA256.HashData(clientDataJson);

        var authDataBuffer = new byte[37];
        var rpIdHash = SHA256.HashData(Encoding.UTF8.GetBytes("localhost"));
        Buffer.BlockCopy(rpIdHash, 0, authDataBuffer, 0, 32);
        authDataBuffer[32] = (byte)(AuthenticatorDataFlags.UserPresent | AuthenticatorDataFlags.UserVerified | AuthenticatorDataFlags.BackupState);
        BinaryPrimitives.WriteUInt32BigEndian(authDataBuffer.AsSpan(33, 4), 5);

        var signedPayload = new byte[authDataBuffer.Length + clientDataHash.Length];
        Buffer.BlockCopy(authDataBuffer, 0, signedPayload, 0, authDataBuffer.Length);
        Buffer.BlockCopy(clientDataHash, 0, signedPayload, authDataBuffer.Length, clientDataHash.Length);

        var signature = ecdsa.SignData(signedPayload, HashAlgorithmName.SHA256);

        var rawResponse = new AuthenticatorAssertionRawResponse(
            id: Convert.ToBase64String(credId),
            rawId: credId,
            clientDataJson: clientDataJson,
            authenticatorData: authDataBuffer,
            signature: signature,
            userHandle: [1, 2, 3]);

        var successResult = await _service.VerifyAuthenticationAsync(rawResponse, challenge, coseKey, storedSignCount: 4, userVerificationRequired: true);

        successResult.IsSuccess.Should().BeTrue();
        successResult.Value.UpdatedSignCount.Should().Be(5u);
        successResult.Value.UserPresent.Should().BeTrue();
        successResult.Value.UserVerified.Should().BeTrue();
        successResult.Value.IsBackedUp.Should().BeTrue();
        successResult.Value.UserHandle.Should().Equal([1, 2, 3]);

        var cloneResult = await _service.VerifyAuthenticationAsync(rawResponse, challenge, coseKey, storedSignCount: 5);

        cloneResult.IsFailure.Should().BeTrue();
        cloneResult.Error.Description.Should().Contain("Authenticator clone detected");
    }

    [Fact]
    public async Task VerifyAuthenticationAsync_UserVerificationRequired_NotVerified_ReturnsFailure()
    {
        var challenge = new byte[32];
        var challengeB64 = Convert.ToBase64String(challenge).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var clientDataJson = Encoding.UTF8.GetBytes(
            $"{{\"type\":\"webauthn.get\",\"challenge\":\"{challengeB64}\",\"origin\":\"https://localhost:5001\"}}");

        var authDataBuffer = new byte[37];
        var rpIdHash = SHA256.HashData(Encoding.UTF8.GetBytes("localhost"));
        Buffer.BlockCopy(rpIdHash, 0, authDataBuffer, 0, 32);
        authDataBuffer[32] = (byte)AuthenticatorDataFlags.UserPresent;

        var coseKey = new CosePublicKey(CoseKeyType.Ec2, CoseAlgorithmIdentifier.ES256, Array.Empty<byte>());
        var rawResponse = new AuthenticatorAssertionRawResponse(
            id: "id",
            rawId: [1],
            clientDataJson: clientDataJson,
            authenticatorData: authDataBuffer,
            signature: [1]);

        var result = await _service.VerifyAuthenticationAsync(rawResponse, challenge, coseKey, storedSignCount: 0, userVerificationRequired: true);

        result.IsFailure.Should().BeTrue();
        result.Error.Description.Should().Contain("User Verification (UV) was required");
    }

    [Fact]
    public async Task VerifyAuthenticationAsync_RsaKey_VerifiesSuccessfully()
    {
        var challenge = new byte[32];
        RandomNumberGenerator.Fill(challenge);
        var credId = new byte[] { 1, 2, 3 };

        using var rsa = RSA.Create(2048);
        var rsaParams = rsa.ExportParameters(false);

        var coseKey = new CosePublicKey(
            CoseKeyType.Rsa,
            CoseAlgorithmIdentifier.RS256,
            Array.Empty<byte>(),
            modulus: rsaParams.Modulus,
            exponent: rsaParams.Exponent);

        var challengeB64 = Convert.ToBase64String(challenge).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var clientDataJson = Encoding.UTF8.GetBytes(
            $"{{\"type\":\"webauthn.get\",\"challenge\":\"{challengeB64}\",\"origin\":\"https://localhost:5001\"}}");
        var clientDataHash = SHA256.HashData(clientDataJson);

        var authDataBuffer = new byte[37];
        var rpIdHash = SHA256.HashData(Encoding.UTF8.GetBytes("localhost"));
        Buffer.BlockCopy(rpIdHash, 0, authDataBuffer, 0, 32);
        authDataBuffer[32] = (byte)AuthenticatorDataFlags.UserPresent;

        var signedPayload = new byte[authDataBuffer.Length + clientDataHash.Length];
        Buffer.BlockCopy(authDataBuffer, 0, signedPayload, 0, authDataBuffer.Length);
        Buffer.BlockCopy(clientDataHash, 0, signedPayload, authDataBuffer.Length, clientDataHash.Length);

        var signature = rsa.SignData(signedPayload, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        var rawResponse = new AuthenticatorAssertionRawResponse(
            id: "id",
            rawId: credId,
            clientDataJson: clientDataJson,
            authenticatorData: authDataBuffer,
            signature: signature);

        var result = await _service.VerifyAuthenticationAsync(rawResponse, challenge, coseKey, storedSignCount: 0);

        result.IsSuccess.Should().BeTrue();
    }

    [Theory]
    [InlineData(CoseEllipticCurve.P384, CoseAlgorithmIdentifier.ES384)]
    [InlineData(CoseEllipticCurve.P521, CoseAlgorithmIdentifier.ES512)]
    public async Task VerifyAuthenticationAsync_Ec2Curves384And512_VerifiesSuccessfully(CoseEllipticCurve curve, CoseAlgorithmIdentifier alg)
    {
        var namedCurve = curve == CoseEllipticCurve.P384 ? ECCurve.NamedCurves.nistP384 : ECCurve.NamedCurves.nistP521;
        using var ecdsa = ECDsa.Create(namedCurve);
        var ecParams = ecdsa.ExportParameters(false);

        var coseKey = new CosePublicKey(
            CoseKeyType.Ec2,
            alg,
            Array.Empty<byte>(),
            curve,
            x: ecParams.Q.X,
            y: ecParams.Q.Y);

        var challenge = new byte[32];
        var challengeB64 = Convert.ToBase64String(challenge).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var clientDataJson = Encoding.UTF8.GetBytes(
            $"{{\"type\":\"webauthn.get\",\"challenge\":\"{challengeB64}\",\"origin\":\"https://localhost:5001\"}}");
        var clientDataHash = SHA256.HashData(clientDataJson);

        var authDataBuffer = new byte[37];
        var rpIdHash = SHA256.HashData(Encoding.UTF8.GetBytes("localhost"));
        Buffer.BlockCopy(rpIdHash, 0, authDataBuffer, 0, 32);
        authDataBuffer[32] = (byte)AuthenticatorDataFlags.UserPresent;

        var signedPayload = new byte[authDataBuffer.Length + clientDataHash.Length];
        Buffer.BlockCopy(authDataBuffer, 0, signedPayload, 0, authDataBuffer.Length);
        Buffer.BlockCopy(clientDataHash, 0, signedPayload, authDataBuffer.Length, clientDataHash.Length);

        var hashAlg = alg == CoseAlgorithmIdentifier.ES384 ? HashAlgorithmName.SHA384 : HashAlgorithmName.SHA512;
        var signature = ecdsa.SignData(signedPayload, hashAlg);

        var rawResponse = new AuthenticatorAssertionRawResponse(
            id: "id",
            rawId: [1],
            clientDataJson: clientDataJson,
            authenticatorData: authDataBuffer,
            signature: signature);

        var result = await _service.VerifyAuthenticationAsync(rawResponse, challenge, coseKey, storedSignCount: 0);
        result.IsSuccess.Should().BeTrue();
    }

    [Fact]
    public async Task VerifyAuthenticationAsync_UserPresentFalse_ReturnsFailure()
    {
        var challenge = new byte[32];
        var challengeB64 = Convert.ToBase64String(challenge).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var clientDataJson = Encoding.UTF8.GetBytes(
            $"{{\"type\":\"webauthn.get\",\"challenge\":\"{challengeB64}\",\"origin\":\"https://localhost:5001\"}}");

        var authDataBuffer = new byte[37];
        var rpIdHash = SHA256.HashData(Encoding.UTF8.GetBytes("localhost"));
        Buffer.BlockCopy(rpIdHash, 0, authDataBuffer, 0, 32);
        authDataBuffer[32] = 0;

        var coseKey = new CosePublicKey(CoseKeyType.Ec2, CoseAlgorithmIdentifier.ES256, Array.Empty<byte>());
        var rawResponse = new AuthenticatorAssertionRawResponse("id", [1], clientDataJson, authDataBuffer, [1]);

        var result = await _service.VerifyAuthenticationAsync(rawResponse, challenge, coseKey, storedSignCount: 0);

        result.IsFailure.Should().BeTrue();
        result.Error.Description.Should().Contain("User Present (UP) bit was not set");
    }

    [Fact]
    public async Task VerifyAuthenticationAsync_NullArguments_ThrowsArgumentNullException()
    {
        var rawResponse = new AuthenticatorAssertionRawResponse("id", [1], [1], [1], [1]);
        var key = new CosePublicKey(CoseKeyType.Ec2, CoseAlgorithmIdentifier.ES256, []);

        await Assert.ThrowsAsync<ArgumentNullException>(() => _service.VerifyAuthenticationAsync(null!, [1], key, 0));
        await Assert.ThrowsAsync<ArgumentNullException>(() => _service.VerifyAuthenticationAsync(rawResponse, null!, key, 0));
        await Assert.ThrowsAsync<ArgumentNullException>(() => _service.VerifyAuthenticationAsync(rawResponse, [1], null!, 0));
    }

    [Fact]
    public async Task VerifyAuthenticationAsync_SignCountZeroWithStoredPositive_ReturnsCloneDetected()
    {
        var fakeLogger = new FakeLogger<WebAuthnCeremonyService>();
        var (service, _) = WebAuthnTestContext.CreateService(logger: fakeLogger);

        var challenge = new byte[32];
        var challengeB64 = Convert.ToBase64String(challenge).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var clientDataJson = Encoding.UTF8.GetBytes(
            $"{{\"type\":\"webauthn.get\",\"challenge\":\"{challengeB64}\",\"origin\":\"https://localhost:5001\"}}");

        var authDataBuffer = new byte[37];
        var rpIdHash = SHA256.HashData(Encoding.UTF8.GetBytes("localhost"));
        Buffer.BlockCopy(rpIdHash, 0, authDataBuffer, 0, 32);
        authDataBuffer[32] = (byte)AuthenticatorDataFlags.UserPresent;
        BinaryPrimitives.WriteUInt32BigEndian(authDataBuffer.AsSpan(33, 4), 0);

        var coseKey = new CosePublicKey(CoseKeyType.Ec2, CoseAlgorithmIdentifier.ES256, []);
        var rawResponse = new AuthenticatorAssertionRawResponse("id", [1], clientDataJson, authDataBuffer, [1]);

        var result = await service.VerifyAuthenticationAsync(rawResponse, challenge, coseKey, storedSignCount: 10);
        result.IsFailure.Should().BeTrue();
        result.Error.Description.Should().Contain("Authenticator clone detected");
        fakeLogger.Messages.Should().Contain(m => m.Contains("AUTHENTICATOR_CLONE_DETECTED") && m.Contains("is not greater than stored"));
    }

    [Fact]
    public async Task VerifyAuthenticationAsync_CancellationToken_ThrowsOperationCanceledException()
    {
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        var rawResponse = new AuthenticatorAssertionRawResponse("id", [1], [1], [1], [1]);
        var coseKey = new CosePublicKey(CoseKeyType.Ec2, CoseAlgorithmIdentifier.ES256, Array.Empty<byte>());

        await Assert.ThrowsAsync<OperationCanceledException>(() =>
            _service.VerifyAuthenticationAsync(rawResponse, new byte[32], coseKey, 0, cancellationToken: cts.Token));

        var regResponse = new AuthenticatorAttestationRawResponse("id", [1], [1], [1]);
        await Assert.ThrowsAsync<OperationCanceledException>(() =>
            _service.VerifyRegistrationAsync(regResponse, new byte[32], [1], cancellationToken: cts.Token));
    }

    [Fact]
    public async Task VerifyAuthenticationAsync_ClientDataInvalidOrAuthDataInvalid_ReturnsFailure()
    {
        var challenge = new byte[32];
        var coseKey = new CosePublicKey(CoseKeyType.Ec2, CoseAlgorithmIdentifier.ES256, Array.Empty<byte>());

        var rawBadClientJson = new AuthenticatorAssertionRawResponse("id", [1], Encoding.UTF8.GetBytes("{bad json"), new byte[37], [1]);
        var res1 = await _service.VerifyAuthenticationAsync(rawBadClientJson, challenge, coseKey, 0);
        res1.IsFailure.Should().BeTrue();
        res1.Error.Description.Should().Contain("Invalid clientDataJSON");

        var rawNoChallenge = new AuthenticatorAssertionRawResponse("id", [1], Encoding.UTF8.GetBytes("{\"type\":\"webauthn.get\",\"origin\":\"https://localhost:5001\"}"), new byte[37], [1]);
        var res2 = await _service.VerifyAuthenticationAsync(rawNoChallenge, challenge, coseKey, 0);
        res2.IsFailure.Should().BeTrue();
        res2.Error.Description.Should().Contain("Missing challenge in clientData");

        var rawEmptyChallenge = new AuthenticatorAssertionRawResponse("id", [1], Encoding.UTF8.GetBytes("{\"type\":\"webauthn.get\",\"challenge\":\"\",\"origin\":\"https://localhost:5001\"}"), new byte[37], [1]);
        var res3 = await _service.VerifyAuthenticationAsync(rawEmptyChallenge, challenge, coseKey, 0);
        res3.IsFailure.Should().BeTrue();
        res3.Error.Description.Should().Contain("Empty challenge in clientData");

        var challengeB64 = Convert.ToBase64String(challenge).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var rawNoOrigin = new AuthenticatorAssertionRawResponse("id", [1], Encoding.UTF8.GetBytes($"{{\"type\":\"webauthn.get\",\"challenge\":\"{challengeB64}\"}}"), new byte[37], [1]);
        var res4 = await _service.VerifyAuthenticationAsync(rawNoOrigin, challenge, coseKey, 0);
        res4.IsFailure.Should().BeTrue();
        res4.Error.Description.Should().Contain("Missing origin in clientData");

        var rawBadOrigin = new AuthenticatorAssertionRawResponse("id", [1], Encoding.UTF8.GetBytes($"{{\"type\":\"webauthn.get\",\"challenge\":\"{challengeB64}\",\"origin\":\"https://evil.com\"}}"), new byte[37], [1]);
        var res5 = await _service.VerifyAuthenticationAsync(rawBadOrigin, challenge, coseKey, 0);
        res5.IsFailure.Should().BeTrue();
        res5.Error.Description.Should().Contain("WebAuthn.Origin");
        res5.Error.Description.Should().Contain("is not authorized");

        var validClientJson = Encoding.UTF8.GetBytes($"{{\"type\":\"webauthn.get\",\"challenge\":\"{challengeB64}\",\"origin\":\"https://localhost:5001\"}}");
        var rawShortAuthData = new AuthenticatorAssertionRawResponse("id", [1], validClientJson, new byte[10], [1]);
        var res6 = await _service.VerifyAuthenticationAsync(rawShortAuthData, challenge, coseKey, 0);
        res6.IsFailure.Should().BeTrue();

        var authDataBuffer = new byte[37];
        authDataBuffer[32] = (byte)AuthenticatorDataFlags.UserPresent;
        var rawRpMismatch = new AuthenticatorAssertionRawResponse("id", [1], validClientJson, authDataBuffer, [1]);
        var res7 = await _service.VerifyAuthenticationAsync(rawRpMismatch, challenge, coseKey, 0);
        res7.IsFailure.Should().BeTrue();
        res7.Error.Description.Should().Contain("RP ID hash in authenticatorData does not match");
    }

    [Fact]
    public async Task VerifyAuthenticationAsync_UserVerificationAndSignCountClone_ReturnsFailure()
    {
        var challenge = new byte[32];
        var challengeB64 = Convert.ToBase64String(challenge).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var clientDataJson = Encoding.UTF8.GetBytes(
            $"{{\"type\":\"webauthn.get\",\"challenge\":\"{challengeB64}\",\"origin\":\"https://localhost:5001\"}}");

        var authDataBuffer = new byte[37];
        var rpIdHash = SHA256.HashData(Encoding.UTF8.GetBytes("localhost"));
        Buffer.BlockCopy(rpIdHash, 0, authDataBuffer, 0, 32);
        authDataBuffer[32] = (byte)AuthenticatorDataFlags.UserPresent;
        BinaryPrimitives.WriteUInt32BigEndian(authDataBuffer.AsSpan(33, 4), 10);

        var coseKey = new CosePublicKey(CoseKeyType.Ec2, CoseAlgorithmIdentifier.ES256, Array.Empty<byte>());
        var rawResponse = new AuthenticatorAssertionRawResponse("id", [1], clientDataJson, authDataBuffer, [1]);

        var resUv = await _service.VerifyAuthenticationAsync(rawResponse, challenge, coseKey, storedSignCount: 5, userVerificationRequired: true);
        resUv.IsFailure.Should().BeTrue();
        resUv.Error.Description.Should().Contain("User Verification (UV) was required but not performed");

        authDataBuffer[32] = (byte)(AuthenticatorDataFlags.UserPresent | AuthenticatorDataFlags.UserVerified);
        var resClone = await _service.VerifyAuthenticationAsync(rawResponse, challenge, coseKey, storedSignCount: 10, userVerificationRequired: false);
        resClone.IsFailure.Should().BeTrue();
        resClone.Error.Description.Should().Contain("Authenticator clone detected: signCount has not advanced");
    }

    [Fact]
    public async Task VerifyAuthenticationAsync_WithEc2AndRsaCurves_VerifiesSuccessfully()
    {
        var challenge = new byte[32];
        var challengeB64 = Convert.ToBase64String(challenge).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var clientDataJson = Encoding.UTF8.GetBytes(
            $"{{\"type\":\"webauthn.get\",\"challenge\":\"{challengeB64}\",\"origin\":\"https://localhost:5001\"}}");

        var rpIdHash = SHA256.HashData(Encoding.UTF8.GetBytes("localhost"));
        var authDataBuffer = new byte[37];
        Buffer.BlockCopy(rpIdHash, 0, authDataBuffer, 0, 32);
        authDataBuffer[32] = (byte)AuthenticatorDataFlags.UserPresent;

        var clientDataHash = SHA256.HashData(clientDataJson);
        var signedData = new byte[authDataBuffer.Length + clientDataHash.Length];
        Buffer.BlockCopy(authDataBuffer, 0, signedData, 0, authDataBuffer.Length);
        Buffer.BlockCopy(clientDataHash, 0, signedData, authDataBuffer.Length, clientDataHash.Length);

        using var ec384 = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        var ec384Params = ec384.ExportParameters(false);
        var ec384Sig = ec384.SignData(signedData, HashAlgorithmName.SHA384);
        var key384 = new CosePublicKey(CoseKeyType.Ec2, CoseAlgorithmIdentifier.ES384, [], CoseEllipticCurve.P384, ec384Params.Q.X, ec384Params.Q.Y);
        var res384 = await _service.VerifyAuthenticationAsync(new AuthenticatorAssertionRawResponse("id", [1], clientDataJson, authDataBuffer, ec384Sig), challenge, key384, 0);
        res384.IsSuccess.Should().BeTrue();

        using var ec521 = ECDsa.Create(ECCurve.NamedCurves.nistP521);
        var ec521Params = ec521.ExportParameters(false);
        var ec521Sig = ec521.SignData(signedData, HashAlgorithmName.SHA512);
        var key521 = new CosePublicKey(CoseKeyType.Ec2, CoseAlgorithmIdentifier.ES512, [], CoseEllipticCurve.P521, ec521Params.Q.X, ec521Params.Q.Y);
        var res521 = await _service.VerifyAuthenticationAsync(new AuthenticatorAssertionRawResponse("id", [1], clientDataJson, authDataBuffer, ec521Sig), challenge, key521, 0);
        res521.IsSuccess.Should().BeTrue();

        var badEc521Sig = new byte[64];
        var badRes521 = await _service.VerifyAuthenticationAsync(new AuthenticatorAssertionRawResponse("id", [1], clientDataJson, authDataBuffer, badEc521Sig), challenge, key521, 0);
        badRes521.IsFailure.Should().BeTrue();
        badRes521.Error.Description.Should().Contain("ECDSA signature verification failed");

        using var rsa = RSA.Create(2048);
        var rsaParams = rsa.ExportParameters(false);
        var ps256Sig = rsa.SignData(signedData, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        var keyPs256 = new CosePublicKey(CoseKeyType.Rsa, CoseAlgorithmIdentifier.PS256, [], null, null, null, rsaParams.Modulus, rsaParams.Exponent);
        var resPs256 = await _service.VerifyAuthenticationAsync(new AuthenticatorAssertionRawResponse("id", [1], clientDataJson, authDataBuffer, ps256Sig), challenge, keyPs256, 0);
        resPs256.IsSuccess.Should().BeTrue();

        var badPs256Sig = new byte[256];
        var badResPs256 = await _service.VerifyAuthenticationAsync(new AuthenticatorAssertionRawResponse("id", [1], clientDataJson, authDataBuffer, badPs256Sig), challenge, keyPs256, 0);
        badResPs256.IsFailure.Should().BeTrue();
        badResPs256.Error.Description.Should().Contain("RSA signature verification failed");

        var keyOkp = new CosePublicKey(CoseKeyType.Okp, CoseAlgorithmIdentifier.EdDSA, []);
        var resOkp = await _service.VerifyAuthenticationAsync(new AuthenticatorAssertionRawResponse("id", [1], clientDataJson, authDataBuffer, [1, 2, 3]), challenge, keyOkp, 0);
        resOkp.IsFailure.Should().BeTrue();
        resOkp.Error.Description.Should().Contain("Unsupported key type");

        var keyCorrupted = new CosePublicKey(CoseKeyType.Ec2, CoseAlgorithmIdentifier.ES256, [], CoseEllipticCurve.P256, [1, 2], [3, 4]);
        var resEx = await _service.VerifyAuthenticationAsync(new AuthenticatorAssertionRawResponse("id", [1], clientDataJson, authDataBuffer, [1, 2]), challenge, keyCorrupted, 0);
        resEx.IsFailure.Should().BeTrue();
        resEx.Error.Description.Should().Contain("Signature verification failed");
    }

    [Fact]
    public async Task VerifyAuthenticationAsync_DerSignatureFallback_ReturnsSuccess()
    {
        var challenge = new byte[32];
        var challengeB64 = Convert.ToBase64String(challenge).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var clientDataJson = Encoding.UTF8.GetBytes(
            $"{{\"type\":\"webauthn.get\",\"challenge\":\"{challengeB64}\",\"origin\":\"https://localhost:5001\"}}");

        var rpIdHash = SHA256.HashData(Encoding.UTF8.GetBytes("localhost"));
        var authDataBuffer = new byte[37];
        Buffer.BlockCopy(rpIdHash, 0, authDataBuffer, 0, 32);
        authDataBuffer[32] = (byte)AuthenticatorDataFlags.UserPresent;

        var clientDataHash = SHA256.HashData(clientDataJson);
        var signedData = new byte[authDataBuffer.Length + clientDataHash.Length];
        Buffer.BlockCopy(authDataBuffer, 0, signedData, 0, authDataBuffer.Length);
        Buffer.BlockCopy(clientDataHash, 0, signedData, authDataBuffer.Length, clientDataHash.Length);

        using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var ecParams = ec.ExportParameters(false);
        var derSig = ec.SignData(signedData, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
        var key = new CosePublicKey(CoseKeyType.Ec2, CoseAlgorithmIdentifier.ES256, [], CoseEllipticCurve.P256, ecParams.Q.X, ecParams.Q.Y);

        var res = await _service.VerifyAuthenticationAsync(new AuthenticatorAssertionRawResponse("id", [1], clientDataJson, authDataBuffer, derSig), challenge, key, 0);
        res.IsSuccess.Should().BeTrue();
    }

    [Fact]
    public async Task VerifyAuthenticationAsync_ChallengeLengthMod4Equals2_DecodesSuccessfully()
    {
        var challenge = new byte[34];
        var challengeB64 = Convert.ToBase64String(challenge).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var clientDataJson = Encoding.UTF8.GetBytes(
            $"{{\"type\":\"webauthn.get\",\"challenge\":\"{challengeB64}\",\"origin\":\"https://localhost:5001\"}}");

        var rpIdHash = SHA256.HashData(Encoding.UTF8.GetBytes("localhost"));
        var authDataBuffer = new byte[37];
        Buffer.BlockCopy(rpIdHash, 0, authDataBuffer, 0, 32);
        authDataBuffer[32] = (byte)AuthenticatorDataFlags.UserPresent;

        var clientDataHash = SHA256.HashData(clientDataJson);
        var signedData = new byte[authDataBuffer.Length + clientDataHash.Length];
        Buffer.BlockCopy(authDataBuffer, 0, signedData, 0, authDataBuffer.Length);
        Buffer.BlockCopy(clientDataHash, 0, signedData, authDataBuffer.Length, clientDataHash.Length);

        using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var ecParams = ec.ExportParameters(false);
        var sig = ec.SignData(signedData, HashAlgorithmName.SHA256);
        var key = new CosePublicKey(CoseKeyType.Ec2, CoseAlgorithmIdentifier.ES256, [], CoseEllipticCurve.P256, ecParams.Q.X, ecParams.Q.Y);

        var res = await _service.VerifyAuthenticationAsync(new AuthenticatorAssertionRawResponse("id", [1], clientDataJson, authDataBuffer, sig), challenge, key, 0);
        res.IsSuccess.Should().BeTrue();
    }

    [Fact]
    public void VerifyAssertionSignature_WithDirectKeys_VerifiesSuccessfully()
    {
        var signedData = new byte[] { 1, 2, 3, 4 };

        var ecNullX = new CosePublicKey(CoseKeyType.Ec2, CoseAlgorithmIdentifier.ES256, [], CoseEllipticCurve.P256, null, [1, 2]);
        WebAuthnCeremonyService.VerifyAssertionSignature(ecNullX, signedData, [1]).IsFailure.Should().BeTrue();

        var ecNullY = new CosePublicKey(CoseKeyType.Ec2, CoseAlgorithmIdentifier.ES256, [], CoseEllipticCurve.P256, [1, 2], null);
        WebAuthnCeremonyService.VerifyAssertionSignature(ecNullY, signedData, [1]).IsFailure.Should().BeTrue();

        var rsaNullMod = new CosePublicKey(CoseKeyType.Rsa, CoseAlgorithmIdentifier.RS256, [], null, null, null, null, [1, 2]);
        var resRsaNullMod = WebAuthnCeremonyService.VerifyAssertionSignature(rsaNullMod, signedData, [1]);
        resRsaNullMod.IsFailure.Should().BeTrue();
        resRsaNullMod.Error.Code.Should().Be("Security.InvalidKey");
        resRsaNullMod.Error.Description.Should().Be("Unsupported key type: Rsa");

        var rsaNullExp = new CosePublicKey(CoseKeyType.Rsa, CoseAlgorithmIdentifier.RS256, [], null, null, null, [1, 2], null);
        var resRsaNullExp = WebAuthnCeremonyService.VerifyAssertionSignature(rsaNullExp, signedData, [1]);
        resRsaNullExp.IsFailure.Should().BeTrue();
        resRsaNullExp.Error.Code.Should().Be("Security.InvalidKey");
        resRsaNullExp.Error.Description.Should().Be("Unsupported key type: Rsa");

        using var rsa = RSA.Create(2048);
        var rsaParams = rsa.ExportParameters(false);
        var rs256Sig = rsa.SignData(signedData, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var rsaKey = new CosePublicKey(CoseKeyType.Rsa, CoseAlgorithmIdentifier.RS256, [], null, null, null, rsaParams.Modulus, rsaParams.Exponent);
        var rs256Result = WebAuthnCeremonyService.VerifyAssertionSignature(rsaKey, signedData, rs256Sig);
        rs256Result.IsSuccess.Should().BeTrue();

        var okpY = new CosePublicKey(CoseKeyType.Okp, CoseAlgorithmIdentifier.EdDSA, [], CoseEllipticCurve.Ed25519, [1, 2], [3, 4]);
        var resOkpY = WebAuthnCeremonyService.VerifyAssertionSignature(okpY, signedData, [1]);
        resOkpY.IsFailure.Should().BeTrue();
        resOkpY.Error.Code.Should().Be("Security.InvalidKey");
        resOkpY.Error.Description.Should().Contain("Unsupported key type");

        var rsaX = new CosePublicKey(CoseKeyType.Rsa, CoseAlgorithmIdentifier.RS256, [], null, [1, 2], null, null, null);
        var resRsaX = WebAuthnCeremonyService.VerifyAssertionSignature(rsaX, signedData, [1]);
        resRsaX.IsFailure.Should().BeTrue();
        resRsaX.Error.Code.Should().Be("Security.InvalidKey");

        var okpExp = new CosePublicKey(CoseKeyType.Okp, CoseAlgorithmIdentifier.EdDSA, [], null, null, null, [1, 2], null);
        var resOkpExp = WebAuthnCeremonyService.VerifyAssertionSignature(okpExp, signedData, [1]);
        resOkpExp.IsFailure.Should().BeTrue();
        resOkpExp.Error.Code.Should().Be("Security.InvalidKey");

        var okpMod = new CosePublicKey(CoseKeyType.Okp, CoseAlgorithmIdentifier.EdDSA, [], null, null, null, null, [1, 2]);
        var resOkpMod = WebAuthnCeremonyService.VerifyAssertionSignature(okpMod, signedData, [1]);
        resOkpMod.IsFailure.Should().BeTrue();
        resOkpMod.Error.Code.Should().Be("Security.InvalidKey");
    }

    [Fact]
    public async Task VerifyAuthenticationAsync_UntrustedOrigin_ReturnsSecurityPolicyViolation()
    {
        var challenge = new byte[32];
        var challengeB64 = Convert.ToBase64String(challenge).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var clientDataJson = Encoding.UTF8.GetBytes(
            $"{{\"type\":\"webauthn.get\",\"challenge\":\"{challengeB64}\",\"origin\":\"https://evil-unauthorized.com\"}}");

        var authDataBuffer = new byte[37];
        var rpIdHash = SHA256.HashData(Encoding.UTF8.GetBytes("localhost"));
        Buffer.BlockCopy(rpIdHash, 0, authDataBuffer, 0, 32);
        authDataBuffer[32] = (byte)AuthenticatorDataFlags.UserPresent;
        BinaryPrimitives.WriteUInt32BigEndian(authDataBuffer.AsSpan(33, 4), 1);

        var coseKey = new CosePublicKey(CoseKeyType.Ec2, CoseAlgorithmIdentifier.ES256, []);
        var rawResponse = new AuthenticatorAssertionRawResponse("id", [1], clientDataJson, authDataBuffer, [1]);

        var result = await _service.VerifyAuthenticationAsync(rawResponse, challenge, coseKey, storedSignCount: 0);
        result.IsFailure.Should().BeTrue();
        result.Error.Code.Should().Be("Security.PolicyViolation");
        result.Error.Description.Should().Contain("WebAuthn.Origin");
        result.Error.Description.Should().Contain("Origin 'https://evil-unauthorized.com' is not authorized.");
    }
}
