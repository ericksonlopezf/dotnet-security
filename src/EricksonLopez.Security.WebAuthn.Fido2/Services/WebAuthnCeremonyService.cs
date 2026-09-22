// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.WebAuthn.Fido2.Services;

using System;
using System.Collections.Generic;
using System.Formats.Cbor;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using EricksonLopez.Result;
using EricksonLopez.Security.Abstractions.Errors;
using EricksonLopez.Security.WebAuthn.Fido2.Abstractions;
using EricksonLopez.Security.WebAuthn.Fido2.Enums;
using EricksonLopez.Security.WebAuthn.Fido2.Models;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

/// <summary>
/// Coordinates WebAuthn Level 2/3 and FIDO2 Relying Party registration and authentication ceremonies.
/// </summary>
public sealed class WebAuthnCeremonyService : IWebAuthnCeremonyService
{
    private readonly WebAuthnOptions _options;
    private readonly IAuthenticatorDataParser _authDataParser;
    private readonly IEnumerable<IAttestationVerifier> _attestationVerifiers;
    private readonly ILogger<WebAuthnCeremonyService> _logger;

    /// <summary>
    /// Initializes a new instance of the <see cref="WebAuthnCeremonyService"/> class with required parsers and verifiers.
    /// </summary>
    /// <param name="options">The configured WebAuthn options.</param>
    /// <param name="authDataParser">The authenticator data parser.</param>
    /// <param name="attestationVerifiers">The collection of registered attestation statement verifiers.</param>
    /// <param name="logger">The optional logger instance.</param>
    /// <exception cref="ArgumentNullException"><paramref name="options"/>, <paramref name="authDataParser"/>, or <paramref name="attestationVerifiers"/> is <see langword="null"/></exception>
    public WebAuthnCeremonyService(
        IOptions<WebAuthnOptions> options,
        IAuthenticatorDataParser authDataParser,
        IEnumerable<IAttestationVerifier> attestationVerifiers,
        ILogger<WebAuthnCeremonyService>? logger = null)
    {
        _options = options?.Value ?? throw new ArgumentNullException(nameof(options));
        _authDataParser = authDataParser ?? throw new ArgumentNullException(nameof(authDataParser));
        _attestationVerifiers = attestationVerifiers ?? throw new ArgumentNullException(nameof(attestationVerifiers));
        _logger = logger ?? NullLogger<WebAuthnCeremonyService>.Instance;
    }

    /// <inheritdoc />
    public CredentialCreateOptions CreateRegistrationOptions(
        PublicKeyCredentialUserEntity user,
        CredentialCreateOptions? customOptions = null)
    {
        ArgumentNullException.ThrowIfNull(user);

        var challenge = new byte[_options.ChallengeLengthBytes];
        RandomNumberGenerator.Fill(challenge);

        var pubKeyCredParams = _options.SupportedAlgorithms
            .Select(alg => new PublicKeyCredentialParameters(alg))
            .ToList();

        var rp = new RelyingPartyIdentity(_options.RpId, _options.RpName);

        if (customOptions is not null)
        {
            return customOptions with { Challenge = challenge };
        }

        return new CredentialCreateOptions(rp, user, challenge, pubKeyCredParams)
        {
            TimeoutMilliseconds = _options.CeremonyTimeoutMilliseconds,
            ResidentKey = _options.DefaultResidentKey,
            UserVerification = _options.DefaultUserVerification,
            Attestation = AttestationConveyancePreference.None
        };
    }

    /// <inheritdoc />
    public Task<Result<VerifiedCredentialRegistration>> VerifyRegistrationAsync(
        AuthenticatorAttestationRawResponse response,
        byte[] expectedChallenge,
        byte[] userHandle,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(response);
        ArgumentNullException.ThrowIfNull(expectedChallenge);
        ArgumentNullException.ThrowIfNull(userHandle);

        cancellationToken.ThrowIfCancellationRequested();

        // 1. Parse and validate clientDataJSON
        var clientDataResult = ParseAndValidateClientData(response.ClientDataJson, "webauthn.create", expectedChallenge);
        if (clientDataResult.IsFailure)
        {
            return Task.FromResult(Result<VerifiedCredentialRegistration>.Failure(clientDataResult.Error));
        }

        var clientData = clientDataResult.Value;
        var clientDataHash = SHA256.HashData(clientData.RawClientDataJson);

        // 2. Parse attestationObject (CBOR map: fmt, authData, attStmt)
        var attestationResult = ParseAttestationObject(response.AttestationObject);
        if (attestationResult.IsFailure)
        {
            return Task.FromResult(Result<VerifiedCredentialRegistration>.Failure(attestationResult.Error));
        }

        var attestationObject = attestationResult.Value;
        var authData = attestationObject.AuthenticatorData;

        // 3. Verify RP ID Hash: SHA256(rpId) == authData.rpIdHash
        var expectedRpIdHash = SHA256.HashData(Encoding.UTF8.GetBytes(_options.RpId));
        if (!CryptographicOperations.FixedTimeEquals(authData.RpIdHash, expectedRpIdHash))
        {
            return Task.FromResult(Result<VerifiedCredentialRegistration>.Failure(
                SecurityError.InvalidToken("RP ID hash in authenticatorData does not match expected RP ID.")));
        }

        // 4. Verify User Present (UP) flag
        if (!authData.UserPresent)
        {
            return Task.FromResult(Result<VerifiedCredentialRegistration>.Failure(
                SecurityError.DecryptionFailed("User Present (UP) bit was not set in registration authenticatorData.")));
        }

        // 5. Verify Attested Credential Data is present
        if (authData.AttestedCredentialData is null)
        {
            return Task.FromResult(Result<VerifiedCredentialRegistration>.Failure(
                SecurityError.InvalidToken("Attested Credential Data missing from registration authenticatorData.")));
        }

        // 6. Verify Attestation Statement with matching verifier
        var verifier = _attestationVerifiers.FirstOrDefault(v => string.Equals(v.Format, attestationObject.Format, StringComparison.OrdinalIgnoreCase));
        if (verifier is null)
        {
            return Task.FromResult(Result<VerifiedCredentialRegistration>.Failure(
                SecurityError.UnsupportedAlgorithm(attestationObject.Format, $"Unsupported attestation statement format '{attestationObject.Format}'.")));
        }

        var verificationResult = verifier.Verify(attestationObject.Statement, authData, clientDataHash);
        if (verificationResult.IsFailure)
        {
            return Task.FromResult(Result<VerifiedCredentialRegistration>.Failure(verificationResult.Error));
        }

        var attestedCred = authData.AttestedCredentialData;
        var verified = new VerifiedCredentialRegistration(
            credentialId: attestedCred.CredentialId,
            userHandle: userHandle,
            publicKey: attestedCred.PublicKey,
            signCount: authData.SignCount,
            aaguid: attestedCred.Aaguid,
            isBackupEligible: authData.BackupEligibility,
            isBackedUp: authData.BackupState,
            attestationFormat: attestationObject.Format);

        return Task.FromResult(Result<VerifiedCredentialRegistration>.Success(verified));
    }

    /// <inheritdoc />
    public CredentialRequestOptions CreateAuthenticationOptions(CredentialRequestOptions? customOptions = null)
    {
        var challenge = new byte[_options.ChallengeLengthBytes];
        RandomNumberGenerator.Fill(challenge);

        if (customOptions is not null)
        {
            return customOptions with { Challenge = challenge };
        }

        return new CredentialRequestOptions(challenge, _options.RpId)
        {
            TimeoutMilliseconds = _options.CeremonyTimeoutMilliseconds,
            UserVerification = _options.DefaultUserVerification
        };
    }

    /// <inheritdoc />
    public Task<Result<VerifiedCredentialAssertion>> VerifyAuthenticationAsync(
        AuthenticatorAssertionRawResponse response,
        byte[] expectedChallenge,
        CosePublicKey storedPublicKey,
        uint storedSignCount,
        bool userVerificationRequired = false,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(response);
        ArgumentNullException.ThrowIfNull(expectedChallenge);
        ArgumentNullException.ThrowIfNull(storedPublicKey);

        cancellationToken.ThrowIfCancellationRequested();

        // 1. Parse and validate clientDataJSON
        var clientDataResult = ParseAndValidateClientData(response.ClientDataJson, "webauthn.get", expectedChallenge);
        if (clientDataResult.IsFailure)
        {
            return Task.FromResult(Result<VerifiedCredentialAssertion>.Failure(clientDataResult.Error));
        }

        var clientData = clientDataResult.Value;
        var clientDataHash = SHA256.HashData(clientData.RawClientDataJson);

        // 2. Parse authenticatorData
        var authDataResult = _authDataParser.Parse(response.AuthenticatorData);
        if (authDataResult.IsFailure)
        {
            return Task.FromResult(Result<VerifiedCredentialAssertion>.Failure(authDataResult.Error));
        }

        var authData = authDataResult.Value;

        // 3. Verify RP ID Hash: SHA256(rpId) == authData.rpIdHash
        var expectedRpIdHash = SHA256.HashData(Encoding.UTF8.GetBytes(_options.RpId));
        if (!CryptographicOperations.FixedTimeEquals(authData.RpIdHash, expectedRpIdHash))
        {
            return Task.FromResult(Result<VerifiedCredentialAssertion>.Failure(
                SecurityError.InvalidToken("RP ID hash in authenticatorData does not match expected RP ID.")));
        }

        // 4. Verify User Present (UP) flag
        if (!authData.UserPresent)
        {
            return Task.FromResult(Result<VerifiedCredentialAssertion>.Failure(
                SecurityError.DecryptionFailed("User Present (UP) bit was not set during authentication.")));
        }

        // 5. Verify User Verified (UV) flag if required
        if (userVerificationRequired && !authData.UserVerified)
        {
            return Task.FromResult(Result<VerifiedCredentialAssertion>.Failure(
                SecurityError.DecryptionFailed("User Verification (UV) was required but not performed by authenticator.")));
        }

        // 6. Verify Signature Counter (Replay / Cloned Authenticator Protection)
        if (storedSignCount > 0)
        {
            if (authData.SignCount <= storedSignCount)
            {
                _logger.LogWarning(
                    "AUTHENTICATOR_CLONE_DETECTED: Received SignCount {Current} is not greater than stored {Stored}.",
                    authData.SignCount,
                    storedSignCount);

                return Task.FromResult(Result<VerifiedCredentialAssertion>.Failure(
                    SecurityError.DecryptionFailed("Authenticator clone detected: signCount has not advanced.")));
            }
        }

        // 7. Verify Signature: sign(authData.RawBytes || clientDataHash)
        var signedData = new byte[authData.RawBytes.Length + clientDataHash.Length];
        Buffer.BlockCopy(authData.RawBytes, 0, signedData, 0, authData.RawBytes.Length);
        Buffer.BlockCopy(clientDataHash, 0, signedData, authData.RawBytes.Length, clientDataHash.Length);

        var signatureValid = VerifyAssertionSignature(storedPublicKey, signedData, response.Signature);
        if (signatureValid.IsFailure)
        {
            return Task.FromResult(Result<VerifiedCredentialAssertion>.Failure(signatureValid.Error));
        }

        var verified = new VerifiedCredentialAssertion(
            credentialId: response.RawId,
            updatedSignCount: authData.SignCount,
            userVerified: authData.UserVerified,
            userPresent: authData.UserPresent,
            isBackedUp: authData.BackupState,
            userHandle: response.UserHandle);

        return Task.FromResult(Result<VerifiedCredentialAssertion>.Success(verified));
    }

    internal Result<CollectedClientData> ParseAndValidateClientData(
        byte[] rawJsonBytes,
        string expectedType,
        byte[] expectedChallenge)
    {
        try
        {
            using var doc = JsonDocument.Parse(rawJsonBytes);
            var root = doc.RootElement;

            if (!root.TryGetProperty("type", out var typeElem) || !string.Equals(typeElem.GetString(), expectedType, StringComparison.Ordinal))
            {
                return Result<CollectedClientData>.Failure(
                    SecurityError.InvalidToken($"Invalid clientData type: expected '{expectedType}'."));
            }

            if (!root.TryGetProperty("challenge", out var challengeElem))
            {
                return Result<CollectedClientData>.Failure(SecurityError.InvalidToken("Missing challenge in clientData."));
            }

            var challengeStr = challengeElem.GetString();
            if (string.IsNullOrEmpty(challengeStr))
            {
                return Result<CollectedClientData>.Failure(SecurityError.InvalidToken("Empty challenge in clientData."));
            }

            var receivedChallenge = Base64UrlDecode(challengeStr);
            if (!CryptographicOperations.FixedTimeEquals(receivedChallenge, expectedChallenge))
            {
                return Result<CollectedClientData>.Failure(SecurityError.DecryptionFailed("Client challenge mismatch."));
            }

            if (!root.TryGetProperty("origin", out var originElem))
            {
                return Result<CollectedClientData>.Failure(SecurityError.InvalidToken("Missing origin in clientData."));
            }

            var originStr = originElem.GetString();
            if (string.IsNullOrEmpty(originStr) || !_options.AllowedOrigins.Contains(originStr))
            {
                return Result<CollectedClientData>.Failure(
                    SecurityError.SecurityPolicyViolation("WebAuthn.Origin", $"Origin '{originStr}' is not authorized."));
            }

            bool? crossOrigin = null;
            if (root.TryGetProperty("crossOrigin", out var crossElem))
            {
                crossOrigin = crossElem.GetBoolean();
            }

            var clientData = new CollectedClientData(expectedType, challengeStr, originStr, rawJsonBytes, crossOrigin);
            return Result<CollectedClientData>.Success(clientData);
        }
        catch (Exception ex)
        {
            return Result<CollectedClientData>.Failure(SecurityError.InvalidToken($"Invalid clientDataJSON: {ex.Message}"));
        }
    }

    internal Result<AttestationObject> ParseAttestationObject(byte[] attestationCbor)
    {
        try
        {
            var reader = new CborReader(attestationCbor, CborConformanceMode.Lax);
            reader.ReadStartMap();

            string? fmt = null;
            byte[]? authDataBytes = null;
            byte[]? attStmtBytes = null;
            byte[]? sig = null;
            long? alg = null;
            List<byte[]>? x5c = null;

            while (reader.PeekState() != CborReaderState.EndMap)
            {
                var key = reader.ReadTextString();
                switch (key)
                {
                    case "fmt":
                        fmt = reader.ReadTextString();
                        break;

                    case "authData":
                        authDataBytes = reader.ReadByteString();
                        break;

                    case "attStmt":
                        var stmtMapLen = reader.ReadStartMap();
                        byte[]? rawStatementPayload = null;
                        var stmtReader = reader;
                        while (stmtReader.PeekState() != CborReaderState.EndMap)
                        {
                            var stmtKey = stmtReader.ReadTextString();
                            switch (stmtKey)
                            {
                                case "sig":
                                    sig = stmtReader.ReadByteString();
                                    break;
                                case "alg":
                                    alg = stmtReader.ReadInt64();
                                    break;
                                case "x5c":
                                    x5c = new List<byte[]>();
                                    var certsLen = stmtReader.ReadStartArray();
                                    while (stmtReader.PeekState() != CborReaderState.EndArray)
                                    {
                                        x5c.Add(stmtReader.ReadByteString());
                                    }
                                    stmtReader.ReadEndArray();
                                    break;
                                case "response":
                                    if (stmtReader.PeekState() == CborReaderState.ByteString)
                                    {
                                        rawStatementPayload = stmtReader.ReadByteString();
                                    }
                                    else if (stmtReader.PeekState() == CborReaderState.TextString)
                                    {
                                        rawStatementPayload = Encoding.UTF8.GetBytes(stmtReader.ReadTextString());
                                    }
                                    break;
                                case "certInfo":
                                    rawStatementPayload = stmtReader.ReadByteString();
                                    break;
                                default:
                                    stmtReader.SkipValue();
                                    break;
                            }
                        }
                        stmtReader.ReadEndMap();
                        if (rawStatementPayload is not null)
                        {
                            attStmtBytes = rawStatementPayload;
                        }
                        break;

                    default:
                        reader.SkipValue();
                        break;
                }
            }

            reader.ReadEndMap();
            if (reader.BytesRemaining > 0)
            {
                return Result<AttestationObject>.Failure(SecurityError.InvalidToken("Unexpected trailing data in attestationObject CBOR."));
            }

            if (string.IsNullOrEmpty(fmt))
            {
                return Result<AttestationObject>.Failure(SecurityError.InvalidToken("Missing 'fmt' in attestationObject."));
            }

            if (authDataBytes is null || authDataBytes.Length == 0)
            {
                return Result<AttestationObject>.Failure(SecurityError.InvalidToken("Missing or empty 'authData' in attestationObject."));
            }

            var authDataResult = _authDataParser.Parse(authDataBytes);
            if (authDataResult.IsFailure)
            {
                return Result<AttestationObject>.Failure(authDataResult.Error);
            }

            var statement = new AttestationStatement(fmt, attStmtBytes ?? Array.Empty<byte>(), sig, alg, x5c);
            var attestationObj = new AttestationObject(authDataResult.Value, statement, attestationCbor);

            return Result<AttestationObject>.Success(attestationObj);
        }
        catch (Exception ex)
        {
            return Result<AttestationObject>.Failure(SecurityError.InvalidToken($"Failed to parse attestationObject CBOR: {ex.Message}"));
        }
    }

    internal static Result VerifyAssertionSignature(CosePublicKey pubKey, byte[] signedData, byte[] signature)
    {
        try
        {
            if (pubKey.KeyType == CoseKeyType.Ec2 && pubKey.X is not null && pubKey.Y is not null)
            {
                var curve = pubKey.Curve == CoseEllipticCurve.P384 ? ECCurve.NamedCurves.nistP384
                    : pubKey.Curve == CoseEllipticCurve.P521 ? ECCurve.NamedCurves.nistP521
                    : ECCurve.NamedCurves.nistP256;

                var ecParams = new ECParameters
                {
                    Curve = curve,
                    Q = new ECPoint { X = pubKey.X, Y = pubKey.Y }
                };

                using var ecdsa = ECDsa.Create(ecParams);
                var hashAlg = pubKey.Algorithm == CoseAlgorithmIdentifier.ES384 ? HashAlgorithmName.SHA384
                    : pubKey.Algorithm == CoseAlgorithmIdentifier.ES512 ? HashAlgorithmName.SHA512
                    : HashAlgorithmName.SHA256;

                var valid = ecdsa.VerifyData(signedData, signature, hashAlg);
                if (!valid)
                {
                    valid = ecdsa.VerifyData(signedData, signature, hashAlg, DSASignatureFormat.Rfc3279DerSequence);
                }

                return valid
                    ? Result.Success()
                    : Result.Failure(SecurityError.DecryptionFailed("WebAuthn assertion ECDSA signature verification failed."));
            }

            if (pubKey.KeyType == CoseKeyType.Rsa && pubKey.Modulus is not null && pubKey.Exponent is not null)
            {
                var rsaParams = new RSAParameters
                {
                    Modulus = pubKey.Modulus,
                    Exponent = pubKey.Exponent
                };

                using var rsa = RSA.Create(rsaParams);
                var padding = pubKey.Algorithm == CoseAlgorithmIdentifier.PS256 ? RSASignaturePadding.Pss : RSASignaturePadding.Pkcs1;
                var valid = rsa.VerifyData(signedData, signature, HashAlgorithmName.SHA256, padding);

                return valid
                    ? Result.Success()
                    : Result.Failure(SecurityError.DecryptionFailed("WebAuthn assertion RSA signature verification failed."));
            }

            return Result.Failure(SecurityError.InvalidKey($"Unsupported key type: {pubKey.KeyType}"));
        }
        catch (Exception ex)
        {
            return Result.Failure(SecurityError.DecryptionFailed($"Signature verification failed: {ex.Message}"));
        }
    }

    private static byte[] Base64UrlDecode(string input)
    {
        var output = input.Replace('-', '+').Replace('_', '/');
        switch (output.Length % 4)
        {
            case 2: output += "=="; break;
            case 3: output += "="; break;
        }
        return Convert.FromBase64String(output);
    }
}
