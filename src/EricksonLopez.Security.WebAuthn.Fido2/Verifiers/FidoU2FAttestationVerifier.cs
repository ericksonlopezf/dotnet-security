// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.WebAuthn.Fido2.Verifiers;

using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using EricksonLopez.Result;
using EricksonLopez.Security.Abstractions.Errors;
using EricksonLopez.Security.WebAuthn.Fido2.Abstractions;
using EricksonLopez.Security.WebAuthn.Fido2.Enums;
using EricksonLopez.Security.WebAuthn.Fido2.Models;

/// <summary>
/// Verifies the "fido-u2f" WebAuthn attestation statement format per
/// §8.6 of the W3C WebAuthn Level 2 specification and the FIDO U2F Message Formats specification.
/// </summary>
/// <remarks>
/// FIDO U2F (CTAP1) attestation uses ECDSA over P-256 with the verificationData
/// constructed as: 0x00 || rpIdHash (32) || clientDataHash (32) || credentialId || publicKeyU2F (65 bytes uncompressed).
/// The attestation certificate public key must be an EC P-256 key.
/// </remarks>
public sealed class FidoU2FAttestationVerifier : IAttestationVerifier
{
    /// <summary>
    /// Gets the attestation statement format identifier ("fido-u2f").
    /// </summary>
    public string Format => "fido-u2f";

    /// <inheritdoc />
    public Result Verify(AttestationStatement statement, AuthenticatorData authData, byte[] clientDataHash)
    {
        // 1. Verify sig and x5c are present (FIDO-U2F does not define self-attestation)
        if (statement.Signature is null || statement.Signature.Length == 0)
        {
            return Result.Failure(SecurityError.InvalidToken(
                "FIDO-U2F attestation statement missing signature ('sig')."));
        }

        if (statement.X5c is null || statement.X5c.Count == 0)
        {
            return Result.Failure(SecurityError.InvalidToken(
                "FIDO-U2F attestation statement missing certificate chain ('x5c'). " +
                "Self-attestation is not defined in the FIDO-U2F format."));
        }

        // 2. Verify attested credential data is present
        if (authData.AttestedCredentialData is null)
        {
            return Result.Failure(SecurityError.InvalidToken(
                "FIDO-U2F verification requires attested credential data (AT flag must be set)."));
        }

        var credData = authData.AttestedCredentialData;
        var coseKey = credData.PublicKey;

        // 3. Verify the public key is EC P-256 (COSE kty=2, crv=1, alg=-7)
        if (coseKey.KeyType != CoseKeyType.Ec2)
        {
            return Result.Failure(SecurityError.InvalidToken(
                $"FIDO-U2F attestation requires EC2 public key (kty=2). Got kty={(int)coseKey.KeyType}."));
        }

        if (coseKey.Curve != CoseEllipticCurve.P256)
        {
            return Result.Failure(SecurityError.InvalidToken(
                $"FIDO-U2F attestation requires P-256 curve (crv=1). Got crv={(int?)coseKey.Curve}."));
        }

        if (coseKey.X is null || coseKey.X.Length != 32 || coseKey.Y is null || coseKey.Y.Length != 32)
        {
            return Result.Failure(SecurityError.InvalidToken(
                "FIDO-U2F: COSE EC2 key missing valid 32-byte x and y coordinates."));
        }

        // 4. Construct uncompressed public key point: 0x04 || x (32) || y (32) = 65 bytes
        var u2fPublicKey = new byte[65];
        u2fPublicKey[0] = 0x04;
        coseKey.X.CopyTo(u2fPublicKey, 1);
        coseKey.Y.CopyTo(u2fPublicKey, 33);

        // 5. Load attestation certificate and verify it uses EC P-256
        X509Certificate2 attCert;
        try
        {
#if NET9_0_OR_GREATER
            attCert = X509CertificateLoader.LoadCertificate(statement.X5c[0]);
#else
            attCert = new X509Certificate2(statement.X5c[0]);
#endif
        }
        catch (CryptographicException ex)
        {
            return Result.Failure(SecurityError.InvalidToken(
                $"FIDO-U2F attestation certificate could not be parsed: {ex.Message}"));
        }

        using (attCert)
        {
            using var ecKey = attCert.GetECDsaPublicKey();
            if (ecKey is null)
            {
                return Result.Failure(SecurityError.InvalidToken(
                    "FIDO-U2F attestation certificate does not contain an EC public key."));
            }

            var ecParams = ecKey.ExportParameters(false);
            // NIST P-256 OID: 1.2.840.10045.3.1.7
            if (!IsNistP256Curve(ecParams.Curve))
            {
                return Result.Failure(SecurityError.InvalidToken(
                    "FIDO-U2F attestation certificate public key must use curve P-256 (OID 1.2.840.10045.3.1.7)."));
            }

            // 6. Construct verificationData per W3C §8.6 step 4:
            //    0x00 || rpIdHash (32) || clientDataHash (32) || credentialId (variable) || publicKeyU2F (65)
            byte[] credentialId = credData.CredentialId;
            var verificationData = new byte[1 + 32 + clientDataHash.Length + credentialId.Length + 65];
            int offset = 0;
            verificationData[offset++] = 0x00;                                // reserved byte
            authData.RpIdHash.CopyTo(verificationData, offset); offset += 32;
            clientDataHash.CopyTo(verificationData, offset); offset += clientDataHash.Length;
            credentialId.CopyTo(verificationData, offset); offset += credentialId.Length;
            u2fPublicKey.CopyTo(verificationData, offset);

            // 7. Verify the ECDSA-P256-SHA256 signature over verificationData
            bool signatureValid = ecKey.VerifyData(
                verificationData,
                statement.Signature,
                HashAlgorithmName.SHA256,
                DSASignatureFormat.Rfc3279DerSequence);

            if (!signatureValid)
            {
                return Result.Failure(SecurityError.InvalidToken(
                    "FIDO-U2F attestation signature verification failed."));
            }

            return Result.Success();
        }
    }

    private static bool IsNistP256Curve(ECCurve curve) =>
        string.Equals(curve.Oid?.Value, "1.2.840.10045.3.1.7", StringComparison.Ordinal);
}
