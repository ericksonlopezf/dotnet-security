// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Testing.Builders;

using System;
using System.Buffers.Binary;
using System.Formats.Cbor;
using System.Security.Cryptography;
using System.Text;
using EricksonLopez.Security.WebAuthn.Fido2.Enums;
using EricksonLopez.Security.WebAuthn.Fido2.Models;

/// <summary>
/// Provides a fluent test builder for constructing synthetic FIDO2/WebAuthn attestation payloads, keys, and statements.
/// </summary>
public sealed class Fido2AttestationTestBuilder
{
    private CoseEllipticCurve _curve = CoseEllipticCurve.P256;
    private CoseAlgorithmIdentifier _algorithm = CoseAlgorithmIdentifier.ES256;
    private bool _isRsa;
    private AuthenticatorDataFlags _flags = AuthenticatorDataFlags.UserPresent;
    private uint _signCount;
    private Guid _aaguid = Guid.NewGuid();
    private byte[] _credentialId = [1, 2, 3, 4, 5, 6, 7, 8];
    private byte[] _clientDataHash = new byte[32];
    private string _format = "packed";

    /// <summary>Sets the signature counter.</summary>
    /// <param name="signCount">The signature counter value.</param>
    /// <returns>The builder instance.</returns>
    public Fido2AttestationTestBuilder WithSignCount(uint signCount)
    {
        _signCount = signCount;
        return this;
    }

    /// <summary>Sets the AAGUID.</summary>
    /// <param name="aaguid">The authenticator attestation GUID.</param>
    /// <returns>The builder instance.</returns>
    public Fido2AttestationTestBuilder WithAaguid(Guid aaguid)
    {
        _aaguid = aaguid;
        return this;
    }

    /// <summary>Sets the credential identifier.</summary>
    /// <param name="credentialId">The credential identifier bytes.</param>
    /// <returns>The builder instance.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="credentialId"/> is <see langword="null"/></exception>
    public Fido2AttestationTestBuilder WithCredentialId(byte[] credentialId)
    {
        _credentialId = credentialId ?? throw new ArgumentNullException(nameof(credentialId));
        return this;
    }

    /// <summary>Configures the key as EC2 with specified curve and algorithm.</summary>
    /// <param name="curve">The COSE elliptic curve.</param>
    /// <param name="algorithm">The COSE algorithm identifier.</param>
    /// <returns>The builder instance.</returns>
    public Fido2AttestationTestBuilder WithEc2Key(CoseEllipticCurve curve, CoseAlgorithmIdentifier algorithm)
    {
        _isRsa = false;
        _curve = curve;
        _algorithm = algorithm;
        return this;
    }

    /// <summary>Configures the key as RSA with specified algorithm.</summary>
    /// <param name="algorithm">The COSE algorithm identifier.</param>
    /// <returns>The builder instance.</returns>
    public Fido2AttestationTestBuilder WithRsaKey(CoseAlgorithmIdentifier algorithm)
    {
        _isRsa = true;
        _algorithm = algorithm;
        return this;
    }

    /// <summary>Sets the format name.</summary>
    /// <param name="format">The attestation format string.</param>
    /// <returns>The builder instance.</returns>
    public Fido2AttestationTestBuilder WithFormat(string format)
    {
        _format = format;
        return this;
    }

    /// <summary>Sets the authenticator flags.</summary>
    /// <param name="flags">The authenticator flags.</param>
    /// <returns>The builder instance.</returns>
    public Fido2AttestationTestBuilder WithFlags(AuthenticatorDataFlags flags)
    {
        _flags = flags;
        return this;
    }

    /// <summary>Sets the client data hash.</summary>
    /// <param name="clientDataHash">The client data hash bytes.</param>
    /// <returns>The builder instance.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="clientDataHash"/> is <see langword="null"/></exception>
    public Fido2AttestationTestBuilder WithClientDataHash(byte[] clientDataHash)
    {
        _clientDataHash = clientDataHash ?? throw new ArgumentNullException(nameof(clientDataHash));
        return this;
    }

    /// <summary>Builds the signed attestation statement, authenticator data, and client data hash.</summary>
    /// <returns>A tuple containing the attestation statement, authenticator data, and client data hash.</returns>
    public (AttestationStatement Statement, AuthenticatorData AuthData, byte[] ClientDataHash) Build()
    {
        CosePublicKey coseKey;
        byte[] signature;
        var authDataBytes = new byte[37];

        if (_isRsa)
        {
            using var rsa = RSA.Create(2048);
            var rsaParams = rsa.ExportParameters(false);
            coseKey = new CosePublicKey(
                CoseKeyType.Rsa,
                _algorithm,
                Array.Empty<byte>(),
                modulus: rsaParams.Modulus,
                exponent: rsaParams.Exponent);

            var credData = new AttestedCredentialData(_aaguid, _credentialId, coseKey, Array.Empty<byte>());
            var authData = new AuthenticatorData(new byte[32], _flags, _signCount, authDataBytes, credData);

            var signedData = new byte[authDataBytes.Length + _clientDataHash.Length];
            Buffer.BlockCopy(authDataBytes, 0, signedData, 0, authDataBytes.Length);
            Buffer.BlockCopy(_clientDataHash, 0, signedData, authDataBytes.Length, _clientDataHash.Length);

            signature = _algorithm switch
            {
                CoseAlgorithmIdentifier.PS256 => rsa.SignData(signedData, HashAlgorithmName.SHA256, RSASignaturePadding.Pss),
                _ => rsa.SignData(signedData, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
            };

            var statement = new AttestationStatement(_format, Array.Empty<byte>(), signature: signature, algorithm: (long)_algorithm);
            return (statement, authData, _clientDataHash);
        }
        else
        {
            var namedCurve = _curve switch
            {
                CoseEllipticCurve.P384 => ECCurve.NamedCurves.nistP384,
                CoseEllipticCurve.P521 => ECCurve.NamedCurves.nistP521,
                _ => ECCurve.NamedCurves.nistP256
            };

            using var ecdsa = ECDsa.Create(namedCurve);
            var ecParams = ecdsa.ExportParameters(false);
            coseKey = new CosePublicKey(
                CoseKeyType.Ec2,
                _algorithm,
                Array.Empty<byte>(),
                _curve,
                x: ecParams.Q.X,
                y: ecParams.Q.Y);

            var credData = new AttestedCredentialData(_aaguid, _credentialId, coseKey, Array.Empty<byte>());
            var authData = new AuthenticatorData(new byte[32], _flags, _signCount, authDataBytes, credData);

            var signedData = new byte[authDataBytes.Length + _clientDataHash.Length];
            Buffer.BlockCopy(authDataBytes, 0, signedData, 0, authDataBytes.Length);
            Buffer.BlockCopy(_clientDataHash, 0, signedData, authDataBytes.Length, _clientDataHash.Length);

            var hashAlg = _algorithm switch
            {
                CoseAlgorithmIdentifier.ES384 => HashAlgorithmName.SHA384,
                CoseAlgorithmIdentifier.ES512 => HashAlgorithmName.SHA512,
                _ => HashAlgorithmName.SHA256
            };

            signature = ecdsa.SignData(signedData, hashAlg, DSASignatureFormat.Rfc3279DerSequence);
            var statement = new AttestationStatement(_format, Array.Empty<byte>(), signature: signature, algorithm: (long)_algorithm);
            return (statement, authData, _clientDataHash);
        }
    }

    /// <summary>Builds a full synthetic AuthenticatorAttestationRawResponse for ceremony testing.</summary>
    /// <param name="challenge">The challenge bytes.</param>
    /// <param name="rpId">The relying party ID.</param>
    /// <param name="origin">The expected origin.</param>
    /// <returns>A tuple of raw attestation response and public key.</returns>
    public (AuthenticatorAttestationRawResponse RawResponse, CosePublicKey PublicKey) BuildRawAttestationResponse(
        byte[] challenge,
        string rpId = "localhost",
        string origin = "https://localhost:5001")
    {
        var challengeB64 = Convert.ToBase64String(challenge).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var clientDataJson = Encoding.UTF8.GetBytes(
            $"{{\"type\":\"webauthn.create\",\"challenge\":\"{challengeB64}\",\"origin\":\"{origin}\",\"crossOrigin\":false}}");

        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var ecParams = ecdsa.ExportParameters(false);

        var coseWriter = new CborWriter(CborConformanceMode.Lax);
        coseWriter.WriteStartMap(5);
        coseWriter.WriteInt32(1);
        coseWriter.WriteInt32((int)CoseKeyType.Ec2);
        coseWriter.WriteInt32(3);
        coseWriter.WriteInt32((int)CoseAlgorithmIdentifier.ES256);
        coseWriter.WriteInt32(-1);
        coseWriter.WriteInt32((int)CoseEllipticCurve.P256);
        coseWriter.WriteInt32(-2);
        coseWriter.WriteByteString(ecParams.Q.X!);
        coseWriter.WriteInt32(-3);
        coseWriter.WriteByteString(ecParams.Q.Y!);
        coseWriter.WriteEndMap();
        var coseBytes = coseWriter.Encode();

        var authDataBuffer = new byte[37 + 16 + 2 + _credentialId.Length + coseBytes.Length];
        var rpIdHash = SHA256.HashData(Encoding.UTF8.GetBytes(rpId));
        Buffer.BlockCopy(rpIdHash, 0, authDataBuffer, 0, 32);
        authDataBuffer[32] = (byte)(_flags | AuthenticatorDataFlags.AttestedCredentialData);
        BinaryPrimitives.WriteUInt32BigEndian(authDataBuffer.AsSpan(33, 4), _signCount);

        Buffer.BlockCopy(_aaguid.ToByteArray(bigEndian: true), 0, authDataBuffer, 37, 16);
        BinaryPrimitives.WriteUInt16BigEndian(authDataBuffer.AsSpan(53, 2), (ushort)_credentialId.Length);
        Buffer.BlockCopy(_credentialId, 0, authDataBuffer, 55, _credentialId.Length);
        Buffer.BlockCopy(coseBytes, 0, authDataBuffer, 55 + _credentialId.Length, coseBytes.Length);

        var attWriter = new CborWriter(CborConformanceMode.Lax);
        attWriter.WriteStartMap(3);
        attWriter.WriteTextString("fmt");
        attWriter.WriteTextString(_format);
        attWriter.WriteTextString("attStmt");
        attWriter.WriteStartMap(0);
        attWriter.WriteEndMap();
        attWriter.WriteTextString("authData");
        attWriter.WriteByteString(authDataBuffer);
        attWriter.WriteEndMap();
        var attestationObject = attWriter.Encode();

        var coseKey = new CosePublicKey(
            CoseKeyType.Ec2,
            CoseAlgorithmIdentifier.ES256,
            Array.Empty<byte>(),
            CoseEllipticCurve.P256,
            x: ecParams.Q.X,
            y: ecParams.Q.Y);

        var rawResponse = new AuthenticatorAttestationRawResponse(
            id: Convert.ToBase64String(_credentialId),
            rawId: _credentialId,
            clientDataJson: clientDataJson,
            attestationObject: attestationObject);

        return (rawResponse, coseKey);
    }

    /// <summary>
    /// Builds a full synthetic AuthenticatorAssertionRawResponse for ceremony authentication testing.
    /// </summary>
    /// <param name="challenge">The challenge bytes.</param>
    /// <param name="rpId">The relying party ID.</param>
    /// <param name="origin">The expected origin.</param>
    /// <param name="userHandle">The optional user handle.</param>
    /// <returns>A tuple of raw assertion response and public key.</returns>
    public (AuthenticatorAssertionRawResponse RawResponse, CosePublicKey PublicKey) BuildRawAssertionResponse(
        byte[] challenge,
        string rpId = "localhost",
        string origin = "https://localhost:5001",
        byte[]? userHandle = null)
    {
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
            $"{{\"type\":\"webauthn.get\",\"challenge\":\"{challengeB64}\",\"origin\":\"{origin}\"}}");
        var clientDataHash = SHA256.HashData(clientDataJson);

        var authDataBuffer = new byte[37];
        var rpIdHash = SHA256.HashData(Encoding.UTF8.GetBytes(rpId));
        Buffer.BlockCopy(rpIdHash, 0, authDataBuffer, 0, 32);
        authDataBuffer[32] = (byte)_flags;
        BinaryPrimitives.WriteUInt32BigEndian(authDataBuffer.AsSpan(33, 4), _signCount);

        var signedPayload = new byte[authDataBuffer.Length + clientDataHash.Length];
        Buffer.BlockCopy(authDataBuffer, 0, signedPayload, 0, authDataBuffer.Length);
        Buffer.BlockCopy(clientDataHash, 0, signedPayload, authDataBuffer.Length, clientDataHash.Length);

        var signature = ecdsa.SignData(signedPayload, HashAlgorithmName.SHA256);

        var rawResponse = new AuthenticatorAssertionRawResponse(
            id: Convert.ToBase64String(_credentialId),
            rawId: _credentialId,
            clientDataJson: clientDataJson,
            authenticatorData: authDataBuffer,
            signature: signature,
            userHandle: userHandle);

        return (rawResponse, coseKey);
    }

    /// <summary>Builds a CBOR-encoded attestation object from the given authData and statement writer.</summary>
    /// <param name="authData">The raw authenticator data bytes.</param>
    /// <param name="fmt">The attestation statement format (defaults to "none").</param>
    /// <param name="customAttStmtWriter">The optional custom writer for the attStmt map.</param>
    /// <returns>The CBOR encoded attestation object bytes.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="authData"/> is <see langword="null"/></exception>
    public static byte[] BuildCborAttestationObject(byte[] authData, string fmt = "none", Action<CborWriter>? customAttStmtWriter = null)
    {
        ArgumentNullException.ThrowIfNull(authData);

        var writer = new CborWriter();
        writer.WriteStartMap(3);
        writer.WriteTextString("fmt");
        writer.WriteTextString(fmt);
        writer.WriteTextString("authData");
        writer.WriteByteString(authData);
        writer.WriteTextString("attStmt");
        if (customAttStmtWriter is not null)
        {
            customAttStmtWriter(writer);
        }
        else
        {
            writer.WriteStartMap(0);
            writer.WriteEndMap();
        }
        writer.WriteEndMap();
        return writer.Encode();
    }
}
