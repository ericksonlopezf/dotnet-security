// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.WebAuthn.Fido2.Tests;

using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using AwesomeAssertions;
using EricksonLopez.Security.WebAuthn.Fido2.Enums;
using EricksonLopez.Security.WebAuthn.Fido2.Models;
using EricksonLopez.Security.Testing.Builders;
using EricksonLopez.Security.WebAuthn.Fido2.Verifiers;
using Xunit;

public sealed class AttestationVerifierTests
{
    // ── NoneAttestationVerifier ─────────────────────────────────────────────

    [Fact]
    public void NoneVerifier_ValidStatement_ReturnsSuccess()
    {
        var verifier = new NoneAttestationVerifier();
        verifier.Format.Should().Be("none");

        var statement = new AttestationStatement("none", Array.Empty<byte>());
        var authData = new AuthenticatorData(new byte[32], AuthenticatorDataFlags.UserPresent, 0, new byte[37]);

        var result = verifier.Verify(statement, authData, new byte[32]);
        result.IsSuccess.Should().BeTrue();

        var statementEmptySig = new AttestationStatement("none", Array.Empty<byte>(), signature: Array.Empty<byte>());
        verifier.Verify(statementEmptySig, authData, new byte[32]).IsSuccess.Should().BeTrue();

        var statementEmptyX5c = new AttestationStatement("none", Array.Empty<byte>(), x5c: new List<byte[]>());
        verifier.Verify(statementEmptyX5c, authData, new byte[32]).IsSuccess.Should().BeTrue();
    }

    [Fact]
    public void NoneVerifier_WithSignatureOrX5c_ReturnsFailure()
    {
        var verifier = new NoneAttestationVerifier();
        var authData = new AuthenticatorData(new byte[32], AuthenticatorDataFlags.UserPresent, 0, new byte[37]);

        var statementWithSig = new AttestationStatement("none", Array.Empty<byte>(), signature: new byte[] { 1, 2, 3 });
        verifier.Verify(statementWithSig, authData, new byte[32]).IsFailure.Should().BeTrue();

        var statementWithX5c = new AttestationStatement("none", Array.Empty<byte>(), x5c: new List<byte[]> { new byte[] { 1 } });
        verifier.Verify(statementWithX5c, authData, new byte[32]).IsFailure.Should().BeTrue();
    }

    // ── PackedAttestationVerifier ───────────────────────────────────────────

    [Theory]
    [InlineData(CoseEllipticCurve.P256, CoseAlgorithmIdentifier.ES256)]
    [InlineData(CoseEllipticCurve.P384, CoseAlgorithmIdentifier.ES384)]
    [InlineData(CoseEllipticCurve.P521, CoseAlgorithmIdentifier.ES512)]
    public void PackedVerifier_SelfAttestation_Ec2Curves_ReturnsSuccess(CoseEllipticCurve curve, CoseAlgorithmIdentifier alg)
    {
        var verifier = new PackedAttestationVerifier();
        verifier.Format.Should().Be("packed");

        var (statement, authData, clientDataHash) = new Fido2AttestationTestBuilder()
            .WithEc2Key(curve, alg)
            .Build();

        var result = verifier.Verify(statement, authData, clientDataHash);
        result.IsSuccess.Should().BeTrue();

        var ecNullX = new CosePublicKey(CoseKeyType.Ec2, CoseAlgorithmIdentifier.ES256, [], CoseEllipticCurve.P256, null, [1, 2]);
        var resEcX = verifier.Verify(new AttestationStatement("packed", [], [1], -7), new AuthenticatorData(new byte[32], AuthenticatorDataFlags.UserPresent, 0, new byte[37], new AttestedCredentialData(Guid.Empty, [1], ecNullX, [])), new byte[32]);
        resEcX.IsFailure.Should().BeTrue();
        resEcX.Error.Code.Should().Be("Security.InvalidKey");

        var ecNullY = new CosePublicKey(CoseKeyType.Ec2, CoseAlgorithmIdentifier.ES256, [], CoseEllipticCurve.P256, [1, 2], null);
        var resEcY = verifier.Verify(new AttestationStatement("packed", [], [1], -7), new AuthenticatorData(new byte[32], AuthenticatorDataFlags.UserPresent, 0, new byte[37], new AttestedCredentialData(Guid.Empty, [1], ecNullY, [])), new byte[32]);
        resEcY.IsFailure.Should().BeTrue();
        resEcY.Error.Code.Should().Be("Security.InvalidKey");

        var rsaNullMod = new CosePublicKey(CoseKeyType.Rsa, CoseAlgorithmIdentifier.RS256, [], null, null, null, null, [1, 2]);
        var resRsaMod = verifier.Verify(new AttestationStatement("packed", [], [1], -257), new AuthenticatorData(new byte[32], AuthenticatorDataFlags.UserPresent, 0, new byte[37], new AttestedCredentialData(Guid.Empty, [1], rsaNullMod, [])), new byte[32]);
        resRsaMod.IsFailure.Should().BeTrue();
        resRsaMod.Error.Code.Should().Be("Security.InvalidKey");

        var rsaNullExp = new CosePublicKey(CoseKeyType.Rsa, CoseAlgorithmIdentifier.RS256, [], null, null, null, [1, 2], null);
        var resRsaExp = verifier.Verify(new AttestationStatement("packed", [], [1], -257), new AuthenticatorData(new byte[32], AuthenticatorDataFlags.UserPresent, 0, new byte[37], new AttestedCredentialData(Guid.Empty, [1], rsaNullExp, [])), new byte[32]);
        resRsaExp.IsFailure.Should().BeTrue();
        resRsaExp.Error.Code.Should().Be("Security.InvalidKey");
    }

    [Theory]
    [InlineData(CoseAlgorithmIdentifier.RS256)]
    [InlineData(CoseAlgorithmIdentifier.PS256)]
    public void PackedVerifier_SelfAttestation_Rsa_ReturnsSuccess(CoseAlgorithmIdentifier alg)
    {
        var verifier = new PackedAttestationVerifier();

        var (statement, authData, clientDataHash) = new Fido2AttestationTestBuilder()
            .WithRsaKey(alg)
            .Build();

        var result = verifier.Verify(statement, authData, clientDataHash);
        result.IsSuccess.Should().BeTrue();

        var badStatement = new AttestationStatement("packed", Array.Empty<byte>(), signature: new byte[256], algorithm: (long)alg);
        var badResult = verifier.Verify(badStatement, authData, clientDataHash);
        badResult.IsFailure.Should().BeTrue();
        badResult.Error.Description.Should().Contain("signature verification failed");
    }

    [Fact]
    public void PackedVerifier_SelfAttestation_InvalidSignature_ReturnsFailure()
    {
        var verifier = new PackedAttestationVerifier();

        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var ecParams = ecdsa.ExportParameters(false);

        var coseKey = new CosePublicKey(
            CoseKeyType.Ec2,
            CoseAlgorithmIdentifier.ES256,
            Array.Empty<byte>(),
            CoseEllipticCurve.P256,
            x: ecParams.Q.X,
            y: ecParams.Q.Y);

        var credData = new AttestedCredentialData(Guid.NewGuid(), new byte[] { 1, 2, 3 }, coseKey, Array.Empty<byte>());
        var authData = new AuthenticatorData(new byte[32], AuthenticatorDataFlags.UserPresent, 0, new byte[37], credData);

        var badSig = new byte[64];
        var statement = new AttestationStatement("packed", Array.Empty<byte>(), signature: badSig, algorithm: -7);

        var result = verifier.Verify(statement, authData, new byte[32]);
        result.IsFailure.Should().BeTrue();
        result.Error.Description.Should().Contain("Self-attestation ECDSA signature verification failed.");
    }

    [Theory]
    [InlineData(CoseAlgorithmIdentifier.RS256)]
    [InlineData(CoseAlgorithmIdentifier.PS256)]
    public void PackedVerifier_X509Attestation_Rsa_ReturnsSuccess(CoseAlgorithmIdentifier alg)
    {
        var verifier = new PackedAttestationVerifier();

        using var rsa = RSA.Create(2048);
        var certReq = new CertificateRequest("CN=WebAuthnAttestationRsa", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = certReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddYears(1));

        var authDataBytes = new byte[37];
        Array.Fill(authDataBytes, (byte)0x11);
        var authData = new AuthenticatorData(new byte[32], AuthenticatorDataFlags.UserPresent, 0, authDataBytes);
        var clientDataHash = new byte[32];
        Array.Fill(clientDataHash, (byte)0x22);

        var signedData = new byte[authDataBytes.Length + clientDataHash.Length];
        Buffer.BlockCopy(authDataBytes, 0, signedData, 0, authDataBytes.Length);
        Buffer.BlockCopy(clientDataHash, 0, signedData, authDataBytes.Length, clientDataHash.Length);

        var padding = alg == CoseAlgorithmIdentifier.PS256 ? RSASignaturePadding.Pss : RSASignaturePadding.Pkcs1;
        var sig = rsa.SignData(signedData, HashAlgorithmName.SHA256, padding);
        var statement = new AttestationStatement(
            "packed",
            Array.Empty<byte>(),
            signature: sig,
            algorithm: (long)alg,
            x5c: new List<byte[]> { cert.RawData });

        var result = verifier.Verify(statement, authData, clientDataHash);
        result.IsSuccess.Should().BeTrue();

        var badStatement = new AttestationStatement("packed", Array.Empty<byte>(), signature: new byte[256], algorithm: (long)alg, x5c: new List<byte[]> { cert.RawData });
        var badResult = verifier.Verify(badStatement, authData, clientDataHash);
        badResult.IsFailure.Should().BeTrue();
        badResult.Error.Description.Should().Contain("signature verification failed");
    }

    [Fact]
    public void PackedVerifier_X509Attestation_Ecdsa_ReturnsSuccess()
    {
        var verifier = new PackedAttestationVerifier();

        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var certReq = new CertificateRequest("CN=WebAuthnAttestation", ecdsa, HashAlgorithmName.SHA256);
        using var cert = certReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddYears(1));

        var authDataBytes = new byte[37];
        Array.Fill(authDataBytes, (byte)0x11);
        var authData = new AuthenticatorData(new byte[32], AuthenticatorDataFlags.UserPresent, 0, authDataBytes);
        var clientDataHash = new byte[32];
        Array.Fill(clientDataHash, (byte)0x22);

        var signedData = new byte[authDataBytes.Length + clientDataHash.Length];
        Buffer.BlockCopy(authDataBytes, 0, signedData, 0, authDataBytes.Length);
        Buffer.BlockCopy(clientDataHash, 0, signedData, authDataBytes.Length, clientDataHash.Length);

        var sig = ecdsa.SignData(signedData, HashAlgorithmName.SHA256);
        var statement = new AttestationStatement(
            "packed",
            Array.Empty<byte>(),
            signature: sig,
            algorithm: (long)CoseAlgorithmIdentifier.ES256,
            x5c: new List<byte[]> { cert.RawData });

        var result = verifier.Verify(statement, authData, clientDataHash);
        result.IsSuccess.Should().BeTrue();

        var badStatement = new AttestationStatement("packed", Array.Empty<byte>(), signature: new byte[64], algorithm: (long)CoseAlgorithmIdentifier.ES256, x5c: new List<byte[]> { cert.RawData });
        var badResult = verifier.Verify(badStatement, authData, clientDataHash);
        badResult.IsFailure.Should().BeTrue();
        badResult.Error.Description.Should().Contain("signature verification failed");
    }

    [Fact]
    public void PackedVerifier_MissingSignatureOrAlg_ReturnsFailure()
    {
        var verifier = new PackedAttestationVerifier();
        var authData = new AuthenticatorData(new byte[32], AuthenticatorDataFlags.UserPresent, 0, new byte[37]);

        var stmtNoSig = new AttestationStatement("packed", Array.Empty<byte>(), signature: null, algorithm: -7);
        var noSigRes = verifier.Verify(stmtNoSig, authData, new byte[32]);
        noSigRes.IsFailure.Should().BeTrue();
        noSigRes.Error.Code.Should().Be("Security.InvalidToken");
        noSigRes.Error.Description.Should().Contain("missing signature");

        var stmtEmptySig = new AttestationStatement("packed", Array.Empty<byte>(), signature: Array.Empty<byte>(), algorithm: -7);
        var emptySigRes = verifier.Verify(stmtEmptySig, authData, new byte[32]);
        emptySigRes.IsFailure.Should().BeTrue();
        emptySigRes.Error.Code.Should().Be("Security.InvalidToken");
        emptySigRes.Error.Description.Should().Contain("missing signature");

        var stmtNoAlg = new AttestationStatement("packed", Array.Empty<byte>(), signature: new byte[] { 1 }, algorithm: null);
        var noAlgRes = verifier.Verify(stmtNoAlg, authData, new byte[32]);
        noAlgRes.IsFailure.Should().BeTrue();
        noAlgRes.Error.Code.Should().Be("Security.InvalidToken");
        noAlgRes.Error.Description.Should().Contain("missing algorithm identifier");

        var stmtSelfNoCredData = new AttestationStatement("packed", Array.Empty<byte>(), signature: new byte[] { 1 }, algorithm: -7);
        verifier.Verify(stmtSelfNoCredData, authData, new byte[32]).IsFailure.Should().BeTrue();
    }

    [Fact]
    public void PackedVerifier_SelfAttestation_EmptyX5c_TreatedAsSelfAttestation()
    {
        var verifier = new PackedAttestationVerifier();
        var (statement, authData, clientDataHash) = new Fido2AttestationTestBuilder()
            .WithEc2Key(CoseEllipticCurve.P256, CoseAlgorithmIdentifier.ES256)
            .Build();

        var stmtEmptyX5c = new AttestationStatement(
            statement.Format,
            statement.RawBytes,
            signature: statement.Signature,
            algorithm: statement.Algorithm,
            x5c: new List<byte[]>());

        var result = verifier.Verify(stmtEmptyX5c, authData, clientDataHash);
        result.IsSuccess.Should().BeTrue();
    }

    // ── FidoU2FAttestationVerifier ──────────────────────────────────────────

    [Fact]
    public void FidoU2FVerifier_ValidAttestation_ReturnsSuccess()
    {
        var verifier = new FidoU2FAttestationVerifier();
        verifier.Format.Should().Be("fido-u2f");

        using var attEcdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var certReq = new CertificateRequest("CN=U2FAttestation", attEcdsa, HashAlgorithmName.SHA256);
        using var cert = certReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddYears(1));

        using var userEcdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var userParams = userEcdsa.ExportParameters(false);

        var coseKey = new CosePublicKey(
            CoseKeyType.Ec2,
            CoseAlgorithmIdentifier.ES256,
            Array.Empty<byte>(),
            CoseEllipticCurve.P256,
            x: userParams.Q.X,
            y: userParams.Q.Y);

        var credId = new byte[] { 1, 2, 3, 4 };
        var credData = new AttestedCredentialData(Guid.NewGuid(), credId, coseKey, Array.Empty<byte>());
        var rpIdHash = new byte[32];
        Array.Fill(rpIdHash, (byte)0x55);
        var authData = new AuthenticatorData(rpIdHash, AuthenticatorDataFlags.UserPresent, 0, new byte[37], credData);
        var clientDataHash = new byte[32];
        Array.Fill(clientDataHash, (byte)0x77);

        // Construct verificationData: 0x00 || rpIdHash (32) || clientDataHash (32) || credentialId || publicKeyU2F (65)
        var u2fPublicKey = new byte[65];
        u2fPublicKey[0] = 0x04;
        userParams.Q.X!.CopyTo(u2fPublicKey, 1);
        userParams.Q.Y!.CopyTo(u2fPublicKey, 33);

        var verificationData = new byte[1 + 32 + clientDataHash.Length + credId.Length + 65];
        int offset = 0;
        verificationData[offset++] = 0x00;
        rpIdHash.CopyTo(verificationData, offset); offset += 32;
        clientDataHash.CopyTo(verificationData, offset); offset += clientDataHash.Length;
        credId.CopyTo(verificationData, offset); offset += credId.Length;
        u2fPublicKey.CopyTo(verificationData, offset);

        var sig = attEcdsa.SignData(verificationData, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);

        var statement = new AttestationStatement(
            "fido-u2f",
            Array.Empty<byte>(),
            signature: sig,
            algorithm: -7,
            x5c: new List<byte[]> { cert.RawData });

        var result = verifier.Verify(statement, authData, clientDataHash);
        result.IsSuccess.Should().BeTrue();
    }

    [Fact]
    public void FidoU2FVerifier_InvalidCurveOrKey_ReturnsFailure()
    {
        var verifier = new FidoU2FAttestationVerifier();

        // RSA key instead of EC2
        var rsaKey = new CosePublicKey(CoseKeyType.Rsa, CoseAlgorithmIdentifier.RS256, Array.Empty<byte>());
        var credDataRsa = new AttestedCredentialData(Guid.NewGuid(), new byte[] { 1 }, rsaKey, Array.Empty<byte>());
        var authDataRsa = new AuthenticatorData(new byte[32], AuthenticatorDataFlags.UserPresent, 0, new byte[37], credDataRsa);

        var stmt = new AttestationStatement("fido-u2f", Array.Empty<byte>(), signature: new byte[] { 1 }, x5c: new List<byte[]> { new byte[] { 1 } });
        verifier.Verify(stmt, authDataRsa, new byte[32]).IsFailure.Should().BeTrue();

        // EC2 with wrong curve
        var ecKeyWrongCurve = new CosePublicKey(CoseKeyType.Ec2, CoseAlgorithmIdentifier.ES384, Array.Empty<byte>(), curve: CoseEllipticCurve.P384, x: new byte[32], y: new byte[32]);
        var credDataCurve = new AttestedCredentialData(Guid.NewGuid(), new byte[] { 1 }, ecKeyWrongCurve, Array.Empty<byte>());
        var authDataCurve = new AuthenticatorData(new byte[32], AuthenticatorDataFlags.UserPresent, 0, new byte[37], credDataCurve);
        verifier.Verify(stmt, authDataCurve, new byte[32]).IsFailure.Should().BeTrue();
    }

    [Fact]
    public void FidoU2FVerifier_MissingX5c_ReturnsFailureWithDescription()
    {
        var verifier = new FidoU2FAttestationVerifier();
        var stmtNoX5c = new AttestationStatement("fido-u2f", Array.Empty<byte>(), signature: new byte[] { 1 }, x5c: null);
        var authData = new AuthenticatorData(new byte[32], AuthenticatorDataFlags.UserPresent, 0, new byte[37]);
        var result = verifier.Verify(stmtNoX5c, authData, new byte[32]);
        result.IsFailure.Should().BeTrue();
        result.Error.Description.Should().Contain("Self-attestation is not defined in the FIDO-U2F format.");
    }

    // ── AndroidSafetyNetAttestationVerifier ─────────────────────────────────

    [Fact]
    public void SafetyNetVerifier_ValidJws_ReturnsSuccess()
    {
        var verifier = new AndroidSafetyNetAttestationVerifier();
        verifier.Format.Should().Be("android-safetynet");

        using var rsa = RSA.Create(2048);
        var certReq = new CertificateRequest("CN=attest.android.com", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = certReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddYears(1));

        var authDataBytes = new byte[37];
        var clientDataHash = new byte[32];
        var nonceData = new byte[authDataBytes.Length + clientDataHash.Length];
        Buffer.BlockCopy(authDataBytes, 0, nonceData, 0, authDataBytes.Length);
        Buffer.BlockCopy(clientDataHash, 0, nonceData, authDataBytes.Length, clientDataHash.Length);
        var nonceHash = SHA256.HashData(nonceData);
        var nonceBase64 = Convert.ToBase64String(nonceHash);

        var headerJson = JsonSerializer.Serialize(new
        {
            alg = "RS256",
            x5c = new[] { Convert.ToBase64String(cert.RawData) }
        });
        var payloadJson = JsonSerializer.Serialize(new
        {
            nonce = nonceBase64,
            ctsProfileMatch = true,
            basicIntegrity = true
        });

        var headerB64Url = Convert.ToBase64String(Encoding.UTF8.GetBytes(headerJson)).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var payloadB64Url = Convert.ToBase64String(Encoding.UTF8.GetBytes(payloadJson)).TrimEnd('=').Replace('+', '-').Replace('/', '_');

        var signingInput = Encoding.UTF8.GetBytes(headerB64Url + "." + payloadB64Url);
        var signature = rsa.SignData(signingInput, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var signatureB64Url = Convert.ToBase64String(signature).TrimEnd('=').Replace('+', '-').Replace('/', '_');

        var jws = $"{headerB64Url}.{payloadB64Url}.{signatureB64Url}";
        var statement = new AttestationStatement("android-safetynet", Encoding.UTF8.GetBytes(jws));

        var authData = new AuthenticatorData(new byte[32], AuthenticatorDataFlags.UserPresent, 0, authDataBytes);
        var result = verifier.Verify(statement, authData, clientDataHash);

        result.IsSuccess.Should().BeTrue();
    }

    [Fact]
    public void SafetyNetVerifier_EcdsaCert_ReturnsSuccess()
    {
        var verifier = new AndroidSafetyNetAttestationVerifier();

        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var certReq = new CertificateRequest("CN=attest.android.com", ecdsa, HashAlgorithmName.SHA256);
        using var cert = certReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddYears(1));

        var authDataBytes = new byte[37];
        var clientDataHash = new byte[32];
        var nonceData = new byte[authDataBytes.Length + clientDataHash.Length];
        Buffer.BlockCopy(authDataBytes, 0, nonceData, 0, authDataBytes.Length);
        Buffer.BlockCopy(clientDataHash, 0, nonceData, authDataBytes.Length, clientDataHash.Length);
        var nonceBase64 = Convert.ToBase64String(SHA256.HashData(nonceData));

        var headerJson = JsonSerializer.Serialize(new
        {
            alg = "ES256",
            x5c = new[] { Convert.ToBase64String(cert.RawData) }
        });
        var payloadJson = JsonSerializer.Serialize(new
        {
            nonce = nonceBase64,
            ctsProfileMatch = true,
            basicIntegrity = true
        });

        var headerB64Url = Convert.ToBase64String(Encoding.UTF8.GetBytes(headerJson)).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var payloadB64Url = Convert.ToBase64String(Encoding.UTF8.GetBytes(payloadJson)).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var signature = ecdsa.SignData(Encoding.UTF8.GetBytes(headerB64Url + "." + payloadB64Url), HashAlgorithmName.SHA256);
        var signatureB64Url = Convert.ToBase64String(signature).TrimEnd('=').Replace('+', '-').Replace('/', '_');

        var jws = $"{headerB64Url}.{payloadB64Url}.{signatureB64Url}";
        var statement = new AttestationStatement("android-safetynet", Encoding.UTF8.GetBytes(jws));

        var authData = new AuthenticatorData(new byte[32], AuthenticatorDataFlags.UserPresent, 0, authDataBytes);
        var result = verifier.Verify(statement, authData, clientDataHash);

        result.IsSuccess.Should().BeTrue();
    }

    [Fact]
    public void SafetyNetVerifier_BasicIntegrityFalse_ReturnsFailure()
    {
        var verifier = new AndroidSafetyNetAttestationVerifier();

        using var rsa = RSA.Create(2048);
        var certReq = new CertificateRequest("CN=attest.android.com", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = certReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddYears(1));

        var authDataBytes = new byte[37];
        var clientDataHash = new byte[32];
        var nonceData = new byte[authDataBytes.Length + clientDataHash.Length];
        Buffer.BlockCopy(authDataBytes, 0, nonceData, 0, authDataBytes.Length);
        Buffer.BlockCopy(clientDataHash, 0, nonceData, authDataBytes.Length, clientDataHash.Length);
        var nonceBase64 = Convert.ToBase64String(SHA256.HashData(nonceData));

        var headerJson = JsonSerializer.Serialize(new { alg = "RS256", x5c = new[] { Convert.ToBase64String(cert.RawData) } });
        var payloadJson = JsonSerializer.Serialize(new { nonce = nonceBase64, ctsProfileMatch = true, basicIntegrity = false });

        var headerB64Url = Convert.ToBase64String(Encoding.UTF8.GetBytes(headerJson)).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var payloadB64Url = Convert.ToBase64String(Encoding.UTF8.GetBytes(payloadJson)).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var signature = rsa.SignData(Encoding.UTF8.GetBytes(headerB64Url + "." + payloadB64Url), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var signatureB64Url = Convert.ToBase64String(signature).TrimEnd('=').Replace('+', '-').Replace('/', '_');

        var jws = $"{headerB64Url}.{payloadB64Url}.{signatureB64Url}";
        var statement = new AttestationStatement("android-safetynet", Encoding.UTF8.GetBytes(jws));

        var authData = new AuthenticatorData(new byte[32], AuthenticatorDataFlags.UserPresent, 0, authDataBytes);
        var result = verifier.Verify(statement, authData, clientDataHash);

        result.IsFailure.Should().BeTrue();
        result.Error.Description.Should().Contain("basicIntegrity is false");
    }

    // ── TpmAttestationVerifier ──────────────────────────────────────────────

    [Fact]
    public void TpmVerifier_ValidCertInfo_Rsa_ReturnsSuccess()
    {
        var verifier = new TpmAttestationVerifier();
        verifier.Format.Should().Be("tpm");

        using var rsa = RSA.Create(2048);
        var certReq = new CertificateRequest("CN=TpmAik", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        certReq.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        certReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        using var cert = certReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddYears(1));

        var authDataBytes = new byte[37];
        var clientDataHash = new byte[32];

        var authDataHash = SHA256.HashData(authDataBytes);
        var attToBeSigned = new byte[authDataHash.Length + clientDataHash.Length];
        Buffer.BlockCopy(authDataHash, 0, attToBeSigned, 0, authDataHash.Length);
        Buffer.BlockCopy(clientDataHash, 0, attToBeSigned, authDataHash.Length, clientDataHash.Length);
        var extraData = SHA256.HashData(attToBeSigned);

        var certInfo = new byte[10 + extraData.Length];
        BinaryPrimitives.WriteUInt32BigEndian(certInfo.AsSpan(0, 4), 0xFF544347);
        BinaryPrimitives.WriteUInt16BigEndian(certInfo.AsSpan(4, 2), 0x8017);
        BinaryPrimitives.WriteUInt16BigEndian(certInfo.AsSpan(6, 2), 0);
        BinaryPrimitives.WriteUInt16BigEndian(certInfo.AsSpan(8, 2), (ushort)extraData.Length);
        Buffer.BlockCopy(extraData, 0, certInfo, 10, extraData.Length);

        var sig = rsa.SignData(certInfo, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        var statement = new AttestationStatement(
            "tpm",
            certInfo,
            signature: sig,
            algorithm: -257,
            x5c: new List<byte[]> { cert.RawData });

        var authData = new AuthenticatorData(new byte[32], AuthenticatorDataFlags.UserPresent, 0, authDataBytes);
        var result = verifier.Verify(statement, authData, clientDataHash);

        result.IsSuccess.Should().BeTrue();
    }

    [Fact]
    public void TpmVerifier_ValidCertInfo_Ecdsa_ReturnsSuccess()
    {
        var verifier = new TpmAttestationVerifier();

        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var certReq = new CertificateRequest("CN=TpmAikEc", ecdsa, HashAlgorithmName.SHA256);
        certReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        using var cert = certReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddYears(1));

        var authDataBytes = new byte[37];
        var clientDataHash = new byte[32];

        var authDataHash = SHA256.HashData(authDataBytes);
        var attToBeSigned = new byte[authDataHash.Length + clientDataHash.Length];
        Buffer.BlockCopy(authDataHash, 0, attToBeSigned, 0, authDataHash.Length);
        Buffer.BlockCopy(clientDataHash, 0, attToBeSigned, authDataHash.Length, clientDataHash.Length);
        var extraData = SHA256.HashData(attToBeSigned);

        var certInfo = new byte[10 + extraData.Length];
        BinaryPrimitives.WriteUInt32BigEndian(certInfo.AsSpan(0, 4), 0xFF544347);
        BinaryPrimitives.WriteUInt16BigEndian(certInfo.AsSpan(4, 2), 0x8017);
        BinaryPrimitives.WriteUInt16BigEndian(certInfo.AsSpan(6, 2), 0);
        BinaryPrimitives.WriteUInt16BigEndian(certInfo.AsSpan(8, 2), (ushort)extraData.Length);
        Buffer.BlockCopy(extraData, 0, certInfo, 10, extraData.Length);

        var sig = ecdsa.SignData(certInfo, HashAlgorithmName.SHA256);

        var statement = new AttestationStatement(
            "tpm",
            certInfo,
            signature: sig,
            algorithm: -7,
            x5c: new List<byte[]> { cert.RawData });

        var authData = new AuthenticatorData(new byte[32], AuthenticatorDataFlags.UserPresent, 0, authDataBytes);
        var result = verifier.Verify(statement, authData, clientDataHash);

        result.IsSuccess.Should().BeTrue();
    }

    [Fact]
    public void TpmVerifier_CaCertificate_ReturnsFailure()
    {
        var verifier = new TpmAttestationVerifier();

        using var rsa = RSA.Create(2048);
        var certReq = new CertificateRequest("CN=TpmAikCa", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        certReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true)); // CA = TRUE (violation)
        using var cert = certReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddYears(1));

        var authDataBytes = new byte[37];
        var clientDataHash = new byte[32];

        var authDataHash = SHA256.HashData(authDataBytes);
        var attToBeSigned = new byte[authDataHash.Length + clientDataHash.Length];
        Buffer.BlockCopy(authDataHash, 0, attToBeSigned, 0, authDataHash.Length);
        Buffer.BlockCopy(clientDataHash, 0, attToBeSigned, authDataHash.Length, clientDataHash.Length);
        var extraData = SHA256.HashData(attToBeSigned);

        var certInfo = new byte[10 + extraData.Length];
        BinaryPrimitives.WriteUInt32BigEndian(certInfo.AsSpan(0, 4), 0xFF544347);
        BinaryPrimitives.WriteUInt16BigEndian(certInfo.AsSpan(4, 2), 0x8017);
        BinaryPrimitives.WriteUInt16BigEndian(certInfo.AsSpan(6, 2), 0);
        BinaryPrimitives.WriteUInt16BigEndian(certInfo.AsSpan(8, 2), (ushort)extraData.Length);
        Buffer.BlockCopy(extraData, 0, certInfo, 10, extraData.Length);

        var sig = rsa.SignData(certInfo, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        var statement = new AttestationStatement(
            "tpm",
            certInfo,
            signature: sig,
            algorithm: -257,
            x5c: new List<byte[]> { cert.RawData });

        var authData = new AuthenticatorData(new byte[32], AuthenticatorDataFlags.UserPresent, 0, authDataBytes);
        var result = verifier.Verify(statement, authData, clientDataHash);

        result.IsFailure.Should().BeTrue();
        result.Error.Description.Should().Contain("must not be a CA certificate");
    }

    [Fact]
    public void TpmVerifier_UnsupportedPublicKey_ReturnsFailure()
    {
        var verifier = new TpmAttestationVerifier();

        using var issuerRsa = RSA.Create(2048);
        var issuerReq = new CertificateRequest("CN=Issuer", issuerRsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var issuerCert = issuerReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddYears(1));

        var dummyPubKey = new PublicKey(
            new Oid("1.2.840.10040.4.1"),
            new AsnEncodedData(new byte[] { 0x05, 0x00 }),
            new AsnEncodedData(new byte[] { 0x03, 0x02, 0x00, 0x00 }));

        var certReq = new CertificateRequest(new X500DistinguishedName("CN=TpmAikUnsupported"), dummyPubKey, HashAlgorithmName.SHA256);
        certReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true)); // CA = FALSE
        var generator = X509SignatureGenerator.CreateForRSA(issuerRsa, RSASignaturePadding.Pkcs1);
        using var cert = certReq.Create(issuerCert.SubjectName, generator, DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddYears(1), new byte[] { 1, 2, 3 });

        var authDataBytes = new byte[37];
        var clientDataHash = new byte[32];
        var authDataHash = SHA256.HashData(authDataBytes);
        var attToBeSigned = new byte[authDataHash.Length + clientDataHash.Length];
        Buffer.BlockCopy(authDataHash, 0, attToBeSigned, 0, authDataHash.Length);
        Buffer.BlockCopy(clientDataHash, 0, attToBeSigned, authDataHash.Length, clientDataHash.Length);
        var extraData = SHA256.HashData(attToBeSigned);

        var certInfo = new byte[10 + extraData.Length];
        BinaryPrimitives.WriteUInt32BigEndian(certInfo.AsSpan(0, 4), 0xFF544347);
        BinaryPrimitives.WriteUInt16BigEndian(certInfo.AsSpan(4, 2), 0x8017);
        BinaryPrimitives.WriteUInt16BigEndian(certInfo.AsSpan(6, 2), 0);
        BinaryPrimitives.WriteUInt16BigEndian(certInfo.AsSpan(8, 2), (ushort)extraData.Length);
        Buffer.BlockCopy(extraData, 0, certInfo, 10, extraData.Length);

        var statement = new AttestationStatement("tpm", certInfo, signature: new byte[32], algorithm: -257, x5c: new List<byte[]> { cert.RawData });
        var authData = new AuthenticatorData(new byte[32], AuthenticatorDataFlags.UserPresent, 0, authDataBytes);

        var result = verifier.Verify(statement, authData, clientDataHash);
        result.IsFailure.Should().BeTrue();
        result.Error.Code.Should().Be("Security.PolicyViolation");
    }

    // ── Additional Packed Edge Cases ──────────────────────────────────────────

    [Fact]
    public void PackedVerifier_X509_DerSignatureFallback_ReturnsSuccess()
    {
        var verifier = new PackedAttestationVerifier();
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var certReq = new CertificateRequest("CN=PackedDerAtt", ecdsa, HashAlgorithmName.SHA256);
        using var cert = certReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddYears(1));

        var authDataBytes = new byte[37];
        var clientDataHash = new byte[32];
        var signedData = new byte[authDataBytes.Length + clientDataHash.Length];
        Buffer.BlockCopy(authDataBytes, 0, signedData, 0, authDataBytes.Length);
        Buffer.BlockCopy(clientDataHash, 0, signedData, authDataBytes.Length, clientDataHash.Length);

        var derSig = ecdsa.SignData(signedData, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);

        var statement = new AttestationStatement("packed", Array.Empty<byte>(), signature: derSig, algorithm: (long)CoseAlgorithmIdentifier.ES256, x5c: new List<byte[]> { cert.RawData });
        var authData = new AuthenticatorData(new byte[32], AuthenticatorDataFlags.UserPresent, 0, authDataBytes);

        var result = verifier.Verify(statement, authData, clientDataHash);
        result.IsSuccess.Should().BeTrue();
    }

    [Fact]
    public void PackedVerifier_SelfAttestation_UnsupportedKeyType_ReturnsFailure()
    {
        var verifier = new PackedAttestationVerifier();
        var coseKey = new CosePublicKey(CoseKeyType.Okp, CoseAlgorithmIdentifier.EdDSA, Array.Empty<byte>());
        var credData = new AttestedCredentialData(Guid.NewGuid(), new byte[] { 1 }, coseKey, Array.Empty<byte>());
        var authData = new AuthenticatorData(new byte[32], AuthenticatorDataFlags.UserPresent, 0, new byte[37], credData);

        var statement = new AttestationStatement("packed", Array.Empty<byte>(), signature: new byte[] { 1, 2, 3 }, algorithm: -8);
        var result = verifier.Verify(statement, authData, new byte[32]);

        result.IsFailure.Should().BeTrue();
        result.Error.Description.Should().Contain("Unsupported key type");
    }

    [Fact]
    public void PackedVerifier_X509_InvalidCertBytes_ReturnsFailure()
    {
        var verifier = new PackedAttestationVerifier();
        var statement = new AttestationStatement("packed", Array.Empty<byte>(), signature: new byte[] { 1 }, algorithm: -7, x5c: new List<byte[]> { new byte[] { 0xFF, 0x00 } });
        var authData = new AuthenticatorData(new byte[32], AuthenticatorDataFlags.UserPresent, 0, new byte[37]);

        var result = verifier.Verify(statement, authData, new byte[32]);
        result.IsFailure.Should().BeTrue();
        result.Error.Description.Should().Contain("Failed to verify packed X.509 attestation");
    }

    [Fact]
    public void PackedVerifier_X509_UnsupportedCertAlgorithm_ReturnsFailure()
    {
        var verifier = new PackedAttestationVerifier();
        using var issuerRsa = RSA.Create(2048);
        var issuerReq = new CertificateRequest("CN=Issuer", issuerRsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var issuerCert = issuerReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddYears(1));

        var dummyPubKey = new PublicKey(
            new Oid("1.2.840.10040.4.1"),
            new AsnEncodedData(new byte[] { 0x05, 0x00 }),
            new AsnEncodedData(new byte[] { 0x03, 0x02, 0x00, 0x00 }));

        var certReq = new CertificateRequest(new X500DistinguishedName("CN=UnsupportedKey"), dummyPubKey, HashAlgorithmName.SHA256);
        var generator = X509SignatureGenerator.CreateForRSA(issuerRsa, RSASignaturePadding.Pkcs1);
        using var cert = certReq.Create(issuerCert.SubjectName, generator, DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddYears(1), new byte[] { 1, 2, 3 });

        var statement = new AttestationStatement("packed", Array.Empty<byte>(), signature: new byte[] { 1 }, algorithm: -7, x5c: new List<byte[]> { cert.RawData });
        var authData = new AuthenticatorData(new byte[32], AuthenticatorDataFlags.UserPresent, 0, new byte[37]);

        var result = verifier.Verify(statement, authData, new byte[32]);
        result.IsFailure.Should().BeTrue();
        result.Error.Description.Should().Contain("Unsupported public key algorithm");
    }

    [Fact]
    public void PackedVerifier_SelfAttestation_CorruptedCoordinates_ReturnsFailure()
    {
        var verifier = new PackedAttestationVerifier();
        var coseKey = new CosePublicKey(CoseKeyType.Ec2, CoseAlgorithmIdentifier.ES256, Array.Empty<byte>(), curve: CoseEllipticCurve.P256, x: new byte[] { 1, 2 }, y: new byte[] { 3, 4 });
        var credData = new AttestedCredentialData(Guid.NewGuid(), new byte[] { 1 }, coseKey, Array.Empty<byte>());
        var authData = new AuthenticatorData(new byte[32], AuthenticatorDataFlags.UserPresent, 0, new byte[37], credData);

        var statement = new AttestationStatement("packed", Array.Empty<byte>(), signature: new byte[] { 1, 2, 3 }, algorithm: -7);
        var result = verifier.Verify(statement, authData, new byte[32]);

        result.IsFailure.Should().BeTrue();
        result.Error.Description.Should().Contain("Self-attestation verification error");
    }

    // ── FIDO-U2F Tests ────────────────────────────────────────────────────────

    [Fact]
    public void FidoU2FVerifier_NullOrEmptySignatureOrX5cOrCredData_ReturnsFailure()
    {
        var verifier = new FidoU2FAttestationVerifier();
        verifier.Format.Should().Be("fido-u2f");
        var authDataWithCred = new AuthenticatorData(new byte[32], AuthenticatorDataFlags.UserPresent, 0, new byte[37],
            new AttestedCredentialData(Guid.Empty, new byte[16], new CosePublicKey(CoseKeyType.Ec2, CoseAlgorithmIdentifier.ES256, Array.Empty<byte>()), Array.Empty<byte>()));
        var authDataNoCred = new AuthenticatorData(new byte[32], AuthenticatorDataFlags.UserPresent, 0, new byte[37]);

        var stmtNoSig = new AttestationStatement("fido-u2f", Array.Empty<byte>(), signature: null, x5c: new List<byte[]> { new byte[] { 1 } });
        var noSigRes = verifier.Verify(stmtNoSig, authDataWithCred, new byte[32]);
        noSigRes.IsFailure.Should().BeTrue();
        noSigRes.Error.Code.Should().Be("Security.InvalidToken");
        noSigRes.Error.Description.Should().Contain("missing signature");

        var stmtEmptySig = new AttestationStatement("fido-u2f", Array.Empty<byte>(), signature: Array.Empty<byte>(), x5c: new List<byte[]> { new byte[] { 1 } });
        var emptySigRes = verifier.Verify(stmtEmptySig, authDataWithCred, new byte[32]);
        emptySigRes.IsFailure.Should().BeTrue();
        emptySigRes.Error.Code.Should().Be("Security.InvalidToken");
        emptySigRes.Error.Description.Should().Contain("missing signature");

        var stmtNoX5c = new AttestationStatement("fido-u2f", Array.Empty<byte>(), signature: new byte[] { 1 }, x5c: null);
        var noX5cRes = verifier.Verify(stmtNoX5c, authDataWithCred, new byte[32]);
        noX5cRes.IsFailure.Should().BeTrue();
        noX5cRes.Error.Code.Should().Be("Security.InvalidToken");
        noX5cRes.Error.Description.Should().Contain("missing certificate chain");

        var stmtEmptyX5c = new AttestationStatement("fido-u2f", Array.Empty<byte>(), signature: new byte[] { 1 }, x5c: new List<byte[]>());
        var emptyX5cRes = verifier.Verify(stmtEmptyX5c, authDataWithCred, new byte[32]);
        emptyX5cRes.IsFailure.Should().BeTrue();
        emptyX5cRes.Error.Code.Should().Be("Security.InvalidToken");
        emptyX5cRes.Error.Description.Should().Contain("missing certificate chain");

        var stmtValidShape = new AttestationStatement("fido-u2f", Array.Empty<byte>(), signature: new byte[] { 1 }, x5c: new List<byte[]> { new byte[] { 1 } });
        verifier.Verify(stmtValidShape, authDataNoCred, new byte[32]).IsFailure.Should().BeTrue();
    }

    [Fact]
    public void FidoU2FVerifier_InvalidCoseKeyParameters_ReturnsFailure()
    {
        var verifier = new FidoU2FAttestationVerifier();
        var stmt = new AttestationStatement("fido-u2f", Array.Empty<byte>(), signature: new byte[] { 1 }, x5c: new List<byte[]> { new byte[] { 1 } });

        var rsaKey = new CosePublicKey(CoseKeyType.Rsa, CoseAlgorithmIdentifier.RS256, Array.Empty<byte>());
        var adRsa = new AuthenticatorData(new byte[32], AuthenticatorDataFlags.UserPresent, 0, new byte[37],
            new AttestedCredentialData(Guid.Empty, new byte[16], rsaKey, Array.Empty<byte>()));
        verifier.Verify(stmt, adRsa, new byte[32]).IsFailure.Should().BeTrue();

        var p384Key = new CosePublicKey(CoseKeyType.Ec2, CoseAlgorithmIdentifier.ES384, Array.Empty<byte>(), curve: CoseEllipticCurve.P384, x: new byte[32], y: new byte[32]);
        var adP384 = new AuthenticatorData(new byte[32], AuthenticatorDataFlags.UserPresent, 0, new byte[37],
            new AttestedCredentialData(Guid.Empty, new byte[16], p384Key, Array.Empty<byte>()));
        verifier.Verify(stmt, adP384, new byte[32]).IsFailure.Should().BeTrue();

        var invalidCoordsKey = new CosePublicKey(CoseKeyType.Ec2, CoseAlgorithmIdentifier.ES256, Array.Empty<byte>(), curve: CoseEllipticCurve.P256, x: new byte[16], y: new byte[32]);
        var adInvalidCoords = new AuthenticatorData(new byte[32], AuthenticatorDataFlags.UserPresent, 0, new byte[37],
            new AttestedCredentialData(Guid.Empty, new byte[16], invalidCoordsKey, Array.Empty<byte>()));
        verifier.Verify(stmt, adInvalidCoords, new byte[32]).IsFailure.Should().BeTrue();

        var nullCurveKey = new CosePublicKey(CoseKeyType.Ec2, CoseAlgorithmIdentifier.ES256, Array.Empty<byte>(), curve: null, x: new byte[32], y: new byte[32]);
        var adNullCurve = new AuthenticatorData(new byte[32], AuthenticatorDataFlags.UserPresent, 0, new byte[37],
            new AttestedCredentialData(Guid.Empty, new byte[16], nullCurveKey, Array.Empty<byte>()));
        verifier.Verify(stmt, adNullCurve, new byte[32]).IsFailure.Should().BeTrue();

        var nullXKey = new CosePublicKey(CoseKeyType.Ec2, CoseAlgorithmIdentifier.ES256, Array.Empty<byte>(), curve: CoseEllipticCurve.P256, x: null, y: new byte[32]);
        var adNullX = new AuthenticatorData(new byte[32], AuthenticatorDataFlags.UserPresent, 0, new byte[37],
            new AttestedCredentialData(Guid.Empty, new byte[16], nullXKey, Array.Empty<byte>()));
        verifier.Verify(stmt, adNullX, new byte[32]).IsFailure.Should().BeTrue();

        var nullYKey = new CosePublicKey(CoseKeyType.Ec2, CoseAlgorithmIdentifier.ES256, Array.Empty<byte>(), curve: CoseEllipticCurve.P256, x: new byte[32], y: null);
        var adNullY = new AuthenticatorData(new byte[32], AuthenticatorDataFlags.UserPresent, 0, new byte[37],
            new AttestedCredentialData(Guid.Empty, new byte[16], nullYKey, Array.Empty<byte>()));
        verifier.Verify(stmt, adNullY, new byte[32]).IsFailure.Should().BeTrue();

        var invalidYKey = new CosePublicKey(CoseKeyType.Ec2, CoseAlgorithmIdentifier.ES256, Array.Empty<byte>(), curve: CoseEllipticCurve.P256, x: new byte[32], y: new byte[16]);
        var adInvalidY = new AuthenticatorData(new byte[32], AuthenticatorDataFlags.UserPresent, 0, new byte[37],
            new AttestedCredentialData(Guid.Empty, new byte[16], invalidYKey, Array.Empty<byte>()));
        verifier.Verify(stmt, adInvalidY, new byte[32]).IsFailure.Should().BeTrue();
    }

    [Fact]
    public void FidoU2FVerifier_InvalidCertificateOrKey_ReturnsFailure()
    {
        var verifier = new FidoU2FAttestationVerifier();
        var key = new CosePublicKey(CoseKeyType.Ec2, CoseAlgorithmIdentifier.ES256, Array.Empty<byte>(), curve: CoseEllipticCurve.P256, x: new byte[32], y: new byte[32]);
        var authData = new AuthenticatorData(new byte[32], AuthenticatorDataFlags.UserPresent, 0, new byte[37],
            new AttestedCredentialData(Guid.Empty, new byte[16], key, Array.Empty<byte>()));

        var stmtBadCert = new AttestationStatement("fido-u2f", Array.Empty<byte>(), signature: new byte[] { 1 }, x5c: new List<byte[]> { new byte[] { 0xFF, 0x00 } });
        verifier.Verify(stmtBadCert, authData, new byte[32]).IsFailure.Should().BeTrue();

        using var rsa = RSA.Create(2048);
        var rsaReq = new CertificateRequest("CN=U2FRsa", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var rsaCert = rsaReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddYears(1));
        var stmtRsaCert = new AttestationStatement("fido-u2f", Array.Empty<byte>(), signature: new byte[] { 1 }, x5c: new List<byte[]> { rsaCert.RawData });
        var rsaResult = verifier.Verify(stmtRsaCert, authData, new byte[32]);
        rsaResult.IsFailure.Should().BeTrue();
        rsaResult.Error.Description.Should().Contain("does not contain an EC public key");

        using var ec384 = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        var ec384Req = new CertificateRequest("CN=U2FEc384", ec384, HashAlgorithmName.SHA384);
        using var ec384Cert = ec384Req.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddYears(1));
        var stmt384Cert = new AttestationStatement("fido-u2f", Array.Empty<byte>(), signature: new byte[] { 1 }, x5c: new List<byte[]> { ec384Cert.RawData });
        var res384 = verifier.Verify(stmt384Cert, authData, new byte[32]);
        res384.IsFailure.Should().BeTrue();
        res384.Error.Description.Should().Contain("must use curve P-256");
    }

    [Fact]
    public void FidoU2FVerifier_ValidSignature_ReturnsSuccess()
    {
        var verifier = new FidoU2FAttestationVerifier();
        using var attEcdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var certReq = new CertificateRequest("CN=U2FAttCert", attEcdsa, HashAlgorithmName.SHA256);
        using var attCert = certReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddYears(1));

        using var credEcdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var credParams = credEcdsa.ExportParameters(false);

        var coseKey = new CosePublicKey(
            CoseKeyType.Ec2,
            CoseAlgorithmIdentifier.ES256,
            Array.Empty<byte>(),
            curve: CoseEllipticCurve.P256,
            x: credParams.Q.X,
            y: credParams.Q.Y);

        byte[] credentialId = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        var credData = new AttestedCredentialData(Guid.Empty, credentialId, coseKey, Array.Empty<byte>());
        var rpIdHash = new byte[32];
        RandomNumberGenerator.Fill(rpIdHash);
        var authData = new AuthenticatorData(rpIdHash, AuthenticatorDataFlags.UserPresent, 0, new byte[37], credData);
        var clientDataHash = new byte[32];
        RandomNumberGenerator.Fill(clientDataHash);

        var u2fPublicKey = new byte[65];
        u2fPublicKey[0] = 0x04;
        credParams.Q.X!.CopyTo(u2fPublicKey, 1);
        credParams.Q.Y!.CopyTo(u2fPublicKey, 33);

        var verificationData = new byte[1 + 32 + clientDataHash.Length + credentialId.Length + 65];
        int offset = 0;
        verificationData[offset++] = 0x00;
        rpIdHash.CopyTo(verificationData, offset); offset += 32;
        clientDataHash.CopyTo(verificationData, offset); offset += clientDataHash.Length;
        credentialId.CopyTo(verificationData, offset); offset += credentialId.Length;
        u2fPublicKey.CopyTo(verificationData, offset);

        var validSig = attEcdsa.SignData(verificationData, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);

        var stmt = new AttestationStatement("fido-u2f", Array.Empty<byte>(), signature: validSig, x5c: new List<byte[]> { attCert.RawData });
        var result = verifier.Verify(stmt, authData, clientDataHash);
        result.IsSuccess.Should().BeTrue();

        var invalidSig = new byte[validSig.Length];
        Array.Copy(validSig, invalidSig, validSig.Length);
        invalidSig[^1] ^= 0xFF;
        var stmtBadSig = new AttestationStatement("fido-u2f", Array.Empty<byte>(), signature: invalidSig, x5c: new List<byte[]> { attCert.RawData });
        var badSigRes = verifier.Verify(stmtBadSig, authData, clientDataHash);
        badSigRes.IsFailure.Should().BeTrue();
        badSigRes.Error.Description.Should().Contain("signature verification failed");
    }

    // ── Android SafetyNet Tests ───────────────────────────────────────────────

    [Fact]
    public void Verify_SafetyNetValidationFailures_ReturnsDescriptivePolicyViolations()
    {
        var verifier = new AndroidSafetyNetAttestationVerifier();
        verifier.Format.Should().Be("android-safetynet");
        var authData = new AuthenticatorData(new byte[32], AuthenticatorDataFlags.UserPresent, 0, new byte[37]);
        var clientDataHash = new byte[32];

        Assert.Throws<ArgumentNullException>(() => new AttestationStatement("android-safetynet", null!));
        verifier.Verify(new AttestationStatement("android-safetynet", Array.Empty<byte>()), authData, clientDataHash).IsFailure.Should().BeTrue();

        // Invalid UTF-8 in rawBytes
        verifier.Verify(new AttestationStatement("android-safetynet", new byte[] { 0xFF, 0xFE, 0xFD }), authData, clientDataHash).IsFailure.Should().BeTrue();

        var utf8Dots = new byte[] { 0xFF, (byte)'.', 0xFE, (byte)'.', 0xFD };
        var utf8Result = verifier.Verify(new AttestationStatement("android-safetynet", utf8Dots), authData, clientDataHash);
        utf8Result.IsFailure.Should().BeTrue();
        utf8Result.Error.Description.Should().Contain("failed to decode JWS response bytes");

        // Invalid base64 in signature with valid header and payload
        var b64GoodHeader = Convert.ToBase64String(Encoding.UTF8.GetBytes("{\"alg\":\"RS256\",\"x5c\":[\"AQID\"]}"));
        var b64GoodPayload = Convert.ToBase64String(Encoding.UTF8.GetBytes("{\"nonce\":\"AQID\"}"));
        verifier.Verify(new AttestationStatement("android-safetynet", Encoding.UTF8.GetBytes($"{b64GoodHeader}.{b64GoodPayload}.!@#$%")), authData, clientDataHash).IsFailure.Should().BeTrue();

        verifier.Verify(new AttestationStatement("android-safetynet", Encoding.UTF8.GetBytes("header.payload")), authData, clientDataHash).IsFailure.Should().BeTrue();

        verifier.Verify(new AttestationStatement("android-safetynet", Encoding.UTF8.GetBytes("header.!!!invalid!!!.sig")), authData, clientDataHash).IsFailure.Should().BeTrue();

        var b64BadJson = Convert.ToBase64String(Encoding.UTF8.GetBytes("{not json"));
        verifier.Verify(new AttestationStatement("android-safetynet", Encoding.UTF8.GetBytes($"header.{b64BadJson}.sig")), authData, clientDataHash).IsFailure.Should().BeTrue();

        var b64NoNonce = Convert.ToBase64String(Encoding.UTF8.GetBytes("{}"));
        verifier.Verify(new AttestationStatement("android-safetynet", Encoding.UTF8.GetBytes($"header.{b64NoNonce}.sig")), authData, clientDataHash).IsFailure.Should().BeTrue();

        var b64NullNonce = Convert.ToBase64String(Encoding.UTF8.GetBytes("{\"nonce\":null}"));
        var nullNonceRes = verifier.Verify(new AttestationStatement("android-safetynet", Encoding.UTF8.GetBytes($"header.{b64NullNonce}.sig")), authData, clientDataHash);
        nullNonceRes.IsFailure.Should().BeTrue();
        nullNonceRes.Error.Description.Should().Contain("WebAuthn.SafetyNet.Nonce");

        var b64BadNonce = Convert.ToBase64String(Encoding.UTF8.GetBytes("{\"nonce\":\"!!!\"}"));
        verifier.Verify(new AttestationStatement("android-safetynet", Encoding.UTF8.GetBytes($"header.{b64BadNonce}.sig")), authData, clientDataHash).IsFailure.Should().BeTrue();

        var b64MismatchNonce = Convert.ToBase64String(Encoding.UTF8.GetBytes("{\"nonce\":\"AQID\"}"));
        var resMismatch = verifier.Verify(new AttestationStatement("android-safetynet", Encoding.UTF8.GetBytes($"header.{b64MismatchNonce}.sig")), authData, clientDataHash);
        resMismatch.IsFailure.Should().BeTrue();
        resMismatch.Error.Description.Should().Contain("WebAuthn.SafetyNet.Nonce");
        resMismatch.Error.Description.Should().Contain("AndroidSafetyNet attestation nonce does not match");

        var nonceData = new byte[authData.RawBytes.Length + clientDataHash.Length];
        Buffer.BlockCopy(authData.RawBytes, 0, nonceData, 0, authData.RawBytes.Length);
        Buffer.BlockCopy(clientDataHash, 0, nonceData, authData.RawBytes.Length, clientDataHash.Length);
        var expectedNonceB64 = Convert.ToBase64String(SHA256.HashData(nonceData));

        var b64BadCts = Convert.ToBase64String(Encoding.UTF8.GetBytes($"{{\"nonce\":\"{expectedNonceB64}\",\"ctsProfileMatch\":false}}"));
        var resBadCts = verifier.Verify(new AttestationStatement("android-safetynet", Encoding.UTF8.GetBytes($"header.{b64BadCts}.sig")), authData, clientDataHash);
        resBadCts.IsFailure.Should().BeTrue();
        resBadCts.Error.Description.Should().Contain("WebAuthn.SafetyNet.CtsProfileMatch");
        resBadCts.Error.Description.Should().Contain("ctsProfileMatch is false");

        var b64BadIntegrity = Convert.ToBase64String(Encoding.UTF8.GetBytes($"{{\"nonce\":\"{expectedNonceB64}\",\"basicIntegrity\":false}}"));
        var resBadIntegrity = verifier.Verify(new AttestationStatement("android-safetynet", Encoding.UTF8.GetBytes($"header.{b64BadIntegrity}.sig")), authData, clientDataHash);
        resBadIntegrity.IsFailure.Should().BeTrue();
        resBadIntegrity.Error.Description.Should().Contain("WebAuthn.SafetyNet.BasicIntegrity");
        resBadIntegrity.Error.Description.Should().Contain("basicIntegrity is false");

        var b64HeaderNoX5c = Convert.ToBase64String(Encoding.UTF8.GetBytes("{}"));
        var b64PayloadNoIntegrity = Convert.ToBase64String(Encoding.UTF8.GetBytes($"{{\"nonce\":\"{expectedNonceB64}\",\"ctsProfileMatch\":true}}"));
        verifier.Verify(new AttestationStatement("android-safetynet", Encoding.UTF8.GetBytes($"{b64HeaderNoX5c}.{b64PayloadNoIntegrity}.sig")), authData, clientDataHash).IsFailure.Should().BeTrue();

        var b64ValidPayload = Convert.ToBase64String(Encoding.UTF8.GetBytes($"{{\"nonce\":\"{expectedNonceB64}\",\"ctsProfileMatch\":true,\"basicIntegrity\":true}}"));
        verifier.Verify(new AttestationStatement("android-safetynet", Encoding.UTF8.GetBytes($"!!!badheader!!!.{b64ValidPayload}.sig")), authData, clientDataHash).IsFailure.Should().BeTrue();

        verifier.Verify(new AttestationStatement("android-safetynet", Encoding.UTF8.GetBytes($"{b64HeaderNoX5c}.{b64ValidPayload}.sig")), authData, clientDataHash).IsFailure.Should().BeTrue();

        var b64HeaderBadCert = Convert.ToBase64String(Encoding.UTF8.GetBytes("{\"x5c\":[\"bad\"]}"));
        verifier.Verify(new AttestationStatement("android-safetynet", Encoding.UTF8.GetBytes($"{b64HeaderBadCert}.{b64ValidPayload}.sig")), authData, clientDataHash).IsFailure.Should().BeTrue();

        var b64HeaderEmptyX5c = Convert.ToBase64String(Encoding.UTF8.GetBytes("{\"x5c\":[]}"));
        verifier.Verify(new AttestationStatement("android-safetynet", Encoding.UTF8.GetBytes($"{b64HeaderEmptyX5c}.{b64ValidPayload}.sig")), authData, clientDataHash).IsFailure.Should().BeTrue();
    }

    [Fact]
    public void Verify_SafetyNetValidRsaAndEcdsaJws_ReturnsSuccess()
    {
        var verifier = new AndroidSafetyNetAttestationVerifier();
        var rawAuth = new byte[37];
        Array.Fill(rawAuth, (byte)0x33);
        var authData = new AuthenticatorData(new byte[32], AuthenticatorDataFlags.UserPresent, 0, rawAuth);
        var clientDataHash = new byte[32];
        Array.Fill(clientDataHash, (byte)0x44);

        var nonceData = new byte[authData.RawBytes.Length + clientDataHash.Length];
        Buffer.BlockCopy(authData.RawBytes, 0, nonceData, 0, authData.RawBytes.Length);
        Buffer.BlockCopy(clientDataHash, 0, nonceData, authData.RawBytes.Length, clientDataHash.Length);
        var expectedNonceB64 = Convert.ToBase64String(SHA256.HashData(nonceData));

        var payloadJson = $"{{\"nonce\":\"{expectedNonceB64}\",\"ctsProfileMatch\":true,\"basicIntegrity\":true}}";
        var payloadB64Url = Convert.ToBase64String(Encoding.UTF8.GetBytes(payloadJson)).TrimEnd('=').Replace('+', '-').Replace('/', '_');

        using var rsa = RSA.Create(2048);
        using var caRsa = RSA.Create(2048);
        var caReq = new CertificateRequest("CN=Google Test CA", caRsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var caCert = caReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddYears(1));

        var rsaReq = new CertificateRequest("CN=attest.android.com", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var sanBuilder = new SubjectAlternativeNameBuilder();
        sanBuilder.AddDnsName("attest.android.com");
        rsaReq.CertificateExtensions.Add(sanBuilder.Build());
        using var rsaCert = rsaReq.Create(caCert.SubjectName, X509SignatureGenerator.CreateForRSA(caRsa, RSASignaturePadding.Pkcs1), DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddYears(1), new byte[] { 1, 2, 3 });

        var headerJson = $"{{\"alg\":\"RS256\",\"x5c\":[\"{Convert.ToBase64String(rsaCert.RawData)}\"]}}";
        var headerB64Url = Convert.ToBase64String(Encoding.UTF8.GetBytes(headerJson)).TrimEnd('=').Replace('+', '-').Replace('/', '_');

        var signingInput = Encoding.UTF8.GetBytes(headerB64Url + "." + payloadB64Url);
        var rsaSig = rsa.SignData(signingInput, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var rsaSigB64Url = Convert.ToBase64String(rsaSig).TrimEnd('=').Replace('+', '-').Replace('/', '_');

        var jws = $"{headerB64Url}.{payloadB64Url}.{rsaSigB64Url}";
        var result = verifier.Verify(new AttestationStatement("android-safetynet", Encoding.UTF8.GetBytes(jws)), authData, clientDataHash);
        result.IsSuccess.Should().BeTrue();

        // 1. x5c with empty string element before valid certificate (tests string.IsNullOrEmpty continue)
        var headerWithEmptyStr = $"{{\"alg\":\"RS256\",\"x5c\":[\"\", \"{Convert.ToBase64String(rsaCert.RawData)}\"]}}";
        var headerEmptyB64Url = Convert.ToBase64String(Encoding.UTF8.GetBytes(headerWithEmptyStr)).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var inputEmpty = Encoding.UTF8.GetBytes(headerEmptyB64Url + "." + payloadB64Url);
        var sigEmpty = rsa.SignData(inputEmpty, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var sigEmptyB64Url = Convert.ToBase64String(sigEmpty).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var resEmptyStr = verifier.Verify(new AttestationStatement("android-safetynet", Encoding.UTF8.GetBytes($"{headerEmptyB64Url}.{payloadB64Url}.{sigEmptyB64Url}")), authData, clientDataHash);
        resEmptyStr.IsSuccess.Should().BeTrue();

        // 2. x5c with 2 certificates (tests break after first cert)
        var headerWith2Certs = $"{{\"alg\":\"RS256\",\"x5c\":[\"{Convert.ToBase64String(rsaCert.RawData)}\", \"{Convert.ToBase64String(caCert.RawData)}\"]}}";
        var header2B64Url = Convert.ToBase64String(Encoding.UTF8.GetBytes(headerWith2Certs)).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var input2 = Encoding.UTF8.GetBytes(header2B64Url + "." + payloadB64Url);
        var sig2 = rsa.SignData(input2, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var sig2B64Url = Convert.ToBase64String(sig2).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var res2Certs = verifier.Verify(new AttestationStatement("android-safetynet", Encoding.UTF8.GetBytes($"{header2B64Url}.{payloadB64Url}.{sig2B64Url}")), authData, clientDataHash);
        res2Certs.IsSuccess.Should().BeTrue();

        // 3. Unsupported key cert with subject attest.android.com (tests signatureIsValid = false)
        var dummyPubKey = new PublicKey(
            new Oid("1.2.840.10040.4.1"),
            new AsnEncodedData(new byte[] { 0x05, 0x00 }),
            new AsnEncodedData(new byte[] { 0x03, 0x02, 0x00, 0x00 }));
        var dsaReq = new CertificateRequest(new X500DistinguishedName("CN=attest.android.com"), dummyPubKey, HashAlgorithmName.SHA256);
        var dsaSan = new SubjectAlternativeNameBuilder();
        dsaSan.AddDnsName("attest.android.com");
        dsaReq.CertificateExtensions.Add(dsaSan.Build());
        using var dsaCert = dsaReq.Create(caCert.SubjectName, X509SignatureGenerator.CreateForRSA(caRsa, RSASignaturePadding.Pkcs1), DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddYears(1), new byte[] { 7 });
        var headerDsa = $"{{\"alg\":\"RS256\",\"x5c\":[\"{Convert.ToBase64String(dsaCert.RawData)}\"]}}";
        var headerDsaB64Url = Convert.ToBase64String(Encoding.UTF8.GetBytes(headerDsa)).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var jwsDsa = $"{headerDsaB64Url}.{payloadB64Url}.{rsaSigB64Url}";
        var resDsa = verifier.Verify(new AttestationStatement("android-safetynet", Encoding.UTF8.GetBytes(jwsDsa)), authData, clientDataHash);
        resDsa.IsFailure.Should().BeTrue();
        resDsa.Error.Description.Should().Contain("signature verification failed");

        var badSigB64Url = Convert.ToBase64String(new byte[256]).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var badJws = $"{headerB64Url}.{payloadB64Url}.{badSigB64Url}";
        var badSigResult = verifier.Verify(new AttestationStatement("android-safetynet", Encoding.UTF8.GetBytes(badJws)), authData, clientDataHash);
        badSigResult.IsFailure.Should().BeTrue();
        badSigResult.Error.Description.Should().Contain("WebAuthn.SafetyNet.Signature");
        badSigResult.Error.Description.Should().Contain("JWS signature verification failed");

        var wrongReq = new CertificateRequest("CN=wrong.example.com", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var wrongSan = new SubjectAlternativeNameBuilder();
        wrongSan.AddDnsName("wrong.example.com");
        wrongReq.CertificateExtensions.Add(wrongSan.Build());
        using var wrongCert = wrongReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddYears(1));

        var wrongHeaderJson = $"{{\"alg\":\"RS256\",\"x5c\":[\"{Convert.ToBase64String(wrongCert.RawData)}\"]}}";
        var wrongHeaderB64Url = Convert.ToBase64String(Encoding.UTF8.GetBytes(wrongHeaderJson)).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var wrongInput = Encoding.UTF8.GetBytes(wrongHeaderB64Url + "." + payloadB64Url);
        var wrongSig = rsa.SignData(wrongInput, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var wrongSigB64Url = Convert.ToBase64String(wrongSig).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var wrongJws = $"{wrongHeaderB64Url}.{payloadB64Url}.{wrongSigB64Url}";

        var wrongHostResult = verifier.Verify(new AttestationStatement("android-safetynet", Encoding.UTF8.GetBytes(wrongJws)), authData, clientDataHash);
        wrongHostResult.IsFailure.Should().BeTrue();
        wrongHostResult.Error.Description.Should().Contain("WebAuthn.SafetyNet.CertificateSubject");
        wrongHostResult.Error.Description.Should().Contain("does not match 'attest.android.com'");

        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var ecReq = new CertificateRequest("CN=attest.android.com", ecdsa, HashAlgorithmName.SHA256);
        var ecSan = new SubjectAlternativeNameBuilder();
        ecSan.AddDnsName("attest.android.com");
        ecReq.CertificateExtensions.Add(ecSan.Build());
        using var ecCert = ecReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddYears(1));

        var ecHeaderJson = $"{{\"alg\":\"ES256\",\"x5c\":[\"{Convert.ToBase64String(ecCert.RawData)}\"]}}";
        var ecHeaderB64Url = Convert.ToBase64String(Encoding.UTF8.GetBytes(ecHeaderJson)).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var ecInput = Encoding.UTF8.GetBytes(ecHeaderB64Url + "." + payloadB64Url);
        var ecSig = ecdsa.SignData(ecInput, HashAlgorithmName.SHA256);
        var ecSigB64Url = Convert.ToBase64String(ecSig).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var ecJws = $"{ecHeaderB64Url}.{payloadB64Url}.{ecSigB64Url}";

        var ecResult = verifier.Verify(new AttestationStatement("android-safetynet", Encoding.UTF8.GetBytes(ecJws)), authData, clientDataHash);
        ecResult.IsSuccess.Should().BeTrue();

        var badSigB64Jws = $"{ecHeaderB64Url}.{payloadB64Url}.!@#$%^";
        var badSigB64Result = verifier.Verify(new AttestationStatement("android-safetynet", Encoding.UTF8.GetBytes(badSigB64Jws)), authData, clientDataHash);
        badSigB64Result.IsFailure.Should().BeTrue();
        badSigB64Result.Error.Description.Should().Contain("failed to decode JWS signature");
    }

    // ── TPM Attestation Tests ─────────────────────────────────────────────────

    [Fact]
    public void Verify_TpmValidationFailures_ReturnsDescriptivePolicyViolations()
    {
        var verifier = new TpmAttestationVerifier();
        var authData = new AuthenticatorData(new byte[32], AuthenticatorDataFlags.UserPresent, 0, new byte[37]);
        var clientDataHash = new byte[32];

        verifier.Verify(new AttestationStatement("tpm", new byte[10], signature: null, algorithm: -257, x5c: new List<byte[]> { new byte[] { 1 } }), authData, clientDataHash).IsFailure.Should().BeTrue();
        verifier.Verify(new AttestationStatement("tpm", new byte[10], signature: Array.Empty<byte>(), algorithm: -257, x5c: new List<byte[]> { new byte[] { 1 } }), authData, clientDataHash).IsFailure.Should().BeTrue();

        verifier.Verify(new AttestationStatement("tpm", new byte[10], signature: new byte[] { 1 }, algorithm: null, x5c: new List<byte[]> { new byte[] { 1 } }), authData, clientDataHash).IsFailure.Should().BeTrue();

        verifier.Verify(new AttestationStatement("tpm", new byte[10], signature: new byte[] { 1 }, algorithm: -257, x5c: null), authData, clientDataHash).IsFailure.Should().BeTrue();
        verifier.Verify(new AttestationStatement("tpm", new byte[10], signature: new byte[] { 1 }, algorithm: -257, x5c: new List<byte[]>()), authData, clientDataHash).IsFailure.Should().BeTrue();

        Assert.Throws<ArgumentNullException>(() => new AttestationStatement("tpm", null!, signature: new byte[] { 1 }, algorithm: -257, x5c: new List<byte[]> { new byte[] { 1 } }));
        verifier.Verify(new AttestationStatement("tpm", new byte[5], signature: new byte[] { 1 }, algorithm: -257, x5c: new List<byte[]> { new byte[] { 1 } }), authData, clientDataHash).IsFailure.Should().BeTrue();

        // Length exactly 6 -> missing qualifiedSigner size (reaches line 102)
        var exact6 = new byte[6];
        BinaryPrimitives.WriteUInt32BigEndian(exact6.AsSpan(0, 4), 0xFF544347);
        BinaryPrimitives.WriteUInt16BigEndian(exact6.AsSpan(4, 2), 0x8017);
        var res6 = verifier.Verify(new AttestationStatement("tpm", exact6, signature: new byte[] { 1 }, algorithm: -257, x5c: new List<byte[]> { new byte[] { 1 } }), authData, clientDataHash);
        res6.IsFailure.Should().BeTrue();
        res6.Error.Description.Should().Contain("missing qualifiedSigner size");

        // Length exactly 8 with qualifiedSignerSize = 0 -> missing extraData size (reaches line 110)
        var exact8 = new byte[8];
        BinaryPrimitives.WriteUInt32BigEndian(exact8.AsSpan(0, 4), 0xFF544347);
        BinaryPrimitives.WriteUInt16BigEndian(exact8.AsSpan(4, 2), 0x8017);
        BinaryPrimitives.WriteUInt16BigEndian(exact8.AsSpan(6, 2), 0);
        var res8 = verifier.Verify(new AttestationStatement("tpm", exact8, signature: new byte[] { 1 }, algorithm: -257, x5c: new List<byte[]> { new byte[] { 1 } }), authData, clientDataHash);
        res8.IsFailure.Should().BeTrue();
        res8.Error.Description.Should().Contain("missing extraData size");

        // Length exactly 10 with qualifiedSignerSize = 0, extraDataSize = 1 -> extraData truncated (reaches line 117)
        var exact10 = new byte[10];
        BinaryPrimitives.WriteUInt32BigEndian(exact10.AsSpan(0, 4), 0xFF544347);
        BinaryPrimitives.WriteUInt16BigEndian(exact10.AsSpan(4, 2), 0x8017);
        BinaryPrimitives.WriteUInt16BigEndian(exact10.AsSpan(6, 2), 0);
        BinaryPrimitives.WriteUInt16BigEndian(exact10.AsSpan(8, 2), 1);
        var res10 = verifier.Verify(new AttestationStatement("tpm", exact10, signature: new byte[] { 1 }, algorithm: -257, x5c: new List<byte[]> { new byte[] { 1 } }), authData, clientDataHash);
        res10.IsFailure.Should().BeTrue();
        res10.Error.Description.Should().Contain("extraData truncated");

        // Length 7 -> missing qualifiedSigner size (reaches line 102)
        var shortQsInfo = new byte[7];
        BinaryPrimitives.WriteUInt32BigEndian(shortQsInfo.AsSpan(0, 4), 0xFF544347);
        BinaryPrimitives.WriteUInt16BigEndian(shortQsInfo.AsSpan(4, 2), 0x8017);
        var resQs = verifier.Verify(new AttestationStatement("tpm", shortQsInfo, signature: new byte[] { 1 }, algorithm: -257, x5c: new List<byte[]> { new byte[] { 1 } }), authData, clientDataHash);
        resQs.IsFailure.Should().BeTrue();
        resQs.Error.Description.Should().Contain("missing qualifiedSigner size");

        // Length 10 with qualifiedSignerSize = 10 -> missing extraData size (reaches line 110)
        var shortExtraInfo = new byte[10];
        BinaryPrimitives.WriteUInt32BigEndian(shortExtraInfo.AsSpan(0, 4), 0xFF544347);
        BinaryPrimitives.WriteUInt16BigEndian(shortExtraInfo.AsSpan(4, 2), 0x8017);
        BinaryPrimitives.WriteUInt16BigEndian(shortExtraInfo.AsSpan(6, 2), 10);
        var resExtra = verifier.Verify(new AttestationStatement("tpm", shortExtraInfo, signature: new byte[] { 1 }, algorithm: -257, x5c: new List<byte[]> { new byte[] { 1 } }), authData, clientDataHash);
        resExtra.IsFailure.Should().BeTrue();
        resExtra.Error.Description.Should().Contain("missing extraData size");

        var badMagic = new byte[10];
        BinaryPrimitives.WriteUInt32BigEndian(badMagic.AsSpan(0, 4), 0x12345678);
        verifier.Verify(new AttestationStatement("tpm", badMagic, signature: new byte[] { 1 }, algorithm: -257, x5c: new List<byte[]> { new byte[] { 1 } }), authData, clientDataHash).IsFailure.Should().BeTrue();

        var badType = new byte[10];
        BinaryPrimitives.WriteUInt32BigEndian(badType.AsSpan(0, 4), 0xFF544347);
        BinaryPrimitives.WriteUInt16BigEndian(badType.AsSpan(4, 2), 0x9999);
        verifier.Verify(new AttestationStatement("tpm", badType, signature: new byte[] { 1 }, algorithm: -257, x5c: new List<byte[]> { new byte[] { 1 } }), authData, clientDataHash).IsFailure.Should().BeTrue();

        var shortQs = new byte[7];
        BinaryPrimitives.WriteUInt32BigEndian(shortQs.AsSpan(0, 4), 0xFF544347);
        BinaryPrimitives.WriteUInt16BigEndian(shortQs.AsSpan(4, 2), 0x8017);
        verifier.Verify(new AttestationStatement("tpm", shortQs, signature: new byte[] { 1 }, algorithm: -257, x5c: new List<byte[]> { new byte[] { 1 } }), authData, clientDataHash).IsFailure.Should().BeTrue();

        var shortExtra = new byte[9];
        BinaryPrimitives.WriteUInt32BigEndian(shortExtra.AsSpan(0, 4), 0xFF544347);
        BinaryPrimitives.WriteUInt16BigEndian(shortExtra.AsSpan(4, 2), 0x8017);
        BinaryPrimitives.WriteUInt16BigEndian(shortExtra.AsSpan(6, 2), 0);
        verifier.Verify(new AttestationStatement("tpm", shortExtra, signature: new byte[] { 1 }, algorithm: -257, x5c: new List<byte[]> { new byte[] { 1 } }), authData, clientDataHash).IsFailure.Should().BeTrue();

        var shortExtraPayload = new byte[11];
        BinaryPrimitives.WriteUInt32BigEndian(shortExtraPayload.AsSpan(0, 4), 0xFF544347);
        BinaryPrimitives.WriteUInt16BigEndian(shortExtraPayload.AsSpan(4, 2), 0x8017);
        BinaryPrimitives.WriteUInt16BigEndian(shortExtraPayload.AsSpan(6, 2), 0);
        BinaryPrimitives.WriteUInt16BigEndian(shortExtraPayload.AsSpan(8, 2), 10);
        verifier.Verify(new AttestationStatement("tpm", shortExtraPayload, signature: new byte[] { 1 }, algorithm: -257, x5c: new List<byte[]> { new byte[] { 1 } }), authData, clientDataHash).IsFailure.Should().BeTrue();

        var mismatchExtra = new byte[12];
        BinaryPrimitives.WriteUInt32BigEndian(mismatchExtra.AsSpan(0, 4), 0xFF544347);
        BinaryPrimitives.WriteUInt16BigEndian(mismatchExtra.AsSpan(4, 2), 0x8017);
        BinaryPrimitives.WriteUInt16BigEndian(mismatchExtra.AsSpan(6, 2), 0);
        BinaryPrimitives.WriteUInt16BigEndian(mismatchExtra.AsSpan(8, 2), 2);
        var resMismatchExtra = verifier.Verify(new AttestationStatement("tpm", mismatchExtra, signature: new byte[] { 1 }, algorithm: -257, x5c: new List<byte[]> { new byte[] { 1 } }), authData, clientDataHash);
        resMismatchExtra.IsFailure.Should().BeTrue();
        resMismatchExtra.Error.Description.Should().Contain("WebAuthn.TPM.ExtraData");
        resMismatchExtra.Error.Description.Should().Contain("TPM certInfo extraData does not match");

        var authDataHash = SHA256.HashData(authData.RawBytes);
        var attToBeSigned = new byte[authDataHash.Length + clientDataHash.Length];
        Buffer.BlockCopy(authDataHash, 0, attToBeSigned, 0, authDataHash.Length);
        Buffer.BlockCopy(clientDataHash, 0, attToBeSigned, authDataHash.Length, clientDataHash.Length);
        var extraData = SHA256.HashData(attToBeSigned);

        var validCertInfo = new byte[10 + extraData.Length];
        BinaryPrimitives.WriteUInt32BigEndian(validCertInfo.AsSpan(0, 4), 0xFF544347);
        BinaryPrimitives.WriteUInt16BigEndian(validCertInfo.AsSpan(4, 2), 0x8017);
        BinaryPrimitives.WriteUInt16BigEndian(validCertInfo.AsSpan(6, 2), 0);
        BinaryPrimitives.WriteUInt16BigEndian(validCertInfo.AsSpan(8, 2), (ushort)extraData.Length);
        Buffer.BlockCopy(extraData, 0, validCertInfo, 10, extraData.Length);

        verifier.Verify(new AttestationStatement("tpm", validCertInfo, signature: new byte[] { 1 }, algorithm: -257, x5c: new List<byte[]> { new byte[] { 0xFF, 0x00 } }), authData, clientDataHash).IsFailure.Should().BeTrue();
    }

    [Theory]
    [InlineData(-7)]
    [InlineData(-35)]
    [InlineData(-36)]
    [InlineData(-257)]
    [InlineData(-258)]
    [InlineData(-259)]
    [InlineData(-65535)]
    [InlineData(999)]
    public void Verify_TpmVariousCoseAlgorithms_ProcessesSupportedAlgorithms(long alg)
    {
        var verifier = new TpmAttestationVerifier();
        using var rsa = RSA.Create(2048);
        var certReq = new CertificateRequest("CN=TpmAlgTest", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = certReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddYears(1));

        var authDataBytes = new byte[37];
        Array.Fill(authDataBytes, (byte)0x42);
        var clientDataHash = new byte[32];
        Array.Fill(clientDataHash, (byte)0x99);
        var authDataHash = SHA256.HashData(authDataBytes);
        var attToBeSigned = new byte[authDataHash.Length + clientDataHash.Length];
        Buffer.BlockCopy(authDataHash, 0, attToBeSigned, 0, authDataHash.Length);
        Buffer.BlockCopy(clientDataHash, 0, attToBeSigned, authDataHash.Length, clientDataHash.Length);
        var extraData = SHA256.HashData(attToBeSigned);

        var certInfo = new byte[10 + extraData.Length];
        BinaryPrimitives.WriteUInt32BigEndian(certInfo.AsSpan(0, 4), 0xFF544347);
        BinaryPrimitives.WriteUInt16BigEndian(certInfo.AsSpan(4, 2), 0x8017);
        BinaryPrimitives.WriteUInt16BigEndian(certInfo.AsSpan(6, 2), 0);
        BinaryPrimitives.WriteUInt16BigEndian(certInfo.AsSpan(8, 2), (ushort)extraData.Length);
        Buffer.BlockCopy(extraData, 0, certInfo, 10, extraData.Length);

        var stmt = new AttestationStatement("tpm", certInfo, signature: new byte[256], algorithm: alg, x5c: new List<byte[]> { cert.RawData });
        var authData = new AuthenticatorData(new byte[32], AuthenticatorDataFlags.UserPresent, 0, authDataBytes);

        var result = verifier.Verify(stmt, authData, clientDataHash);
        result.IsFailure.Should().BeTrue();
        result.Error.Description.Should().Contain("WebAuthn.TPM.Signature");
        result.Error.Description.Should().Contain("signature verification failed");

        var hashAlg = alg switch
        {
            -7 => HashAlgorithmName.SHA256,
            -35 => HashAlgorithmName.SHA384,
            -36 => HashAlgorithmName.SHA512,
            -257 => HashAlgorithmName.SHA256,
            -258 => HashAlgorithmName.SHA384,
            -259 => HashAlgorithmName.SHA512,
            -65535 => HashAlgorithmName.SHA1,
            _ => HashAlgorithmName.SHA256
        };

        var validSig = rsa.SignData(certInfo, hashAlg, RSASignaturePadding.Pkcs1);
        var validStmt = new AttestationStatement("tpm", certInfo, signature: validSig, algorithm: alg, x5c: new List<byte[]> { cert.RawData });
        var validResult = verifier.Verify(validStmt, authData, clientDataHash);
        validResult.IsSuccess.Should().BeTrue();
    }

    [Fact]
    public void TpmVerifier_AikCertificateIsCa_ReturnsSecurityPolicyViolation()
    {
        var verifier = new TpmAttestationVerifier();
        using var rsa = RSA.Create(2048);
        var certReq = new CertificateRequest("CN=TpmCaTest", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        certReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(certificateAuthority: true, hasPathLengthConstraint: false, pathLengthConstraint: 0, critical: true));
        using var cert = certReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddYears(1));

        var authDataBytes = new byte[37];
        var clientDataHash = new byte[32];
        var authDataHash = SHA256.HashData(authDataBytes);
        var attToBeSigned = new byte[authDataHash.Length + clientDataHash.Length];
        Buffer.BlockCopy(authDataHash, 0, attToBeSigned, 0, authDataHash.Length);
        Buffer.BlockCopy(clientDataHash, 0, attToBeSigned, authDataHash.Length, clientDataHash.Length);
        var extraData = SHA256.HashData(attToBeSigned);

        var certInfo = new byte[10 + extraData.Length];
        BinaryPrimitives.WriteUInt32BigEndian(certInfo.AsSpan(0, 4), 0xFF544347);
        BinaryPrimitives.WriteUInt16BigEndian(certInfo.AsSpan(4, 2), 0x8017);
        BinaryPrimitives.WriteUInt16BigEndian(certInfo.AsSpan(6, 2), 0);
        BinaryPrimitives.WriteUInt16BigEndian(certInfo.AsSpan(8, 2), (ushort)extraData.Length);
        Buffer.BlockCopy(extraData, 0, certInfo, 10, extraData.Length);

        var sig = rsa.SignData(certInfo, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var stmt = new AttestationStatement("tpm", certInfo, signature: sig, algorithm: -257, x5c: new List<byte[]> { cert.RawData });
        var authData = new AuthenticatorData(new byte[32], AuthenticatorDataFlags.UserPresent, 0, authDataBytes);

        var result = verifier.Verify(stmt, authData, clientDataHash);
        result.IsFailure.Should().BeTrue();
        result.Error.Description.Should().Contain("WebAuthn.TPM.AikCertificate");
        result.Error.Description.Should().Contain("TPM AIK certificate must not be a CA certificate");
    }
}
