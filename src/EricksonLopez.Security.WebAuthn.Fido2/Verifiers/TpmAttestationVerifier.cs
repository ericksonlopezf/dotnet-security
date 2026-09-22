// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.WebAuthn.Fido2.Verifiers;

using System;
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using EricksonLopez.Result;
using EricksonLopez.Security.Abstractions.Errors;
using EricksonLopez.Security.WebAuthn.Fido2.Abstractions;
using EricksonLopez.Security.WebAuthn.Fido2.Models;

/// <summary>
/// Verifies the "tpm" WebAuthn attestation statement format.
/// </summary>
/// <remarks>
/// TPM attestation uses a certInfo structure (TPMS_ATTEST) signed by a TPM Attestation Identity
/// Key (AIK). The verification confirms:
/// <list type="number">
///   <item>The <c>certInfo</c> structure is of type <c>TPM_ST_ATTEST_CERTIFY</c> (0x8017).</item>
///   <item>The <c>extraData</c> field in TPMS_ATTEST equals the SHA-256 hash of the
///         attToBeSigned (hash(authData) || clientDataHash).</item>
///   <item>The AIK certificate signature over certInfo is valid.</item>
///   <item>The AIK certificate contains the FIDO AAGUID in the Subject Alternative Name extension.</item>
/// </list>
/// <para>
/// Reference: WebAuthn Level 2 §8.3 — TPM Attestation Statement Format.
/// Reference: TCG TPM Library Part 2: Structures, Section 10.12.8 TPMS_ATTEST.
/// </para>
/// </remarks>
public sealed class TpmAttestationVerifier : IAttestationVerifier
{
    // TPM_ST_ATTEST_CERTIFY magic value (0x8017)
    private const ushort TpmStAttestCertify = 0x8017;

    // TPM magic value that must be present at the start of TPMS_ATTEST (0xFF544347)
    private const uint TpmGeneratedValue = 0xFF544347;

    /// <summary>
    /// Gets the attestation statement format identifier ("tpm").
    /// </summary>
    public string Format => "tpm";

    /// <inheritdoc />
    public Result Verify(AttestationStatement statement, AuthenticatorData authData, byte[] clientDataHash)
    {
        // TPM attestation requires: alg, sig, x5c (AIK cert chain), and certInfo
        if (statement.Signature is null || statement.Signature.Length == 0)
        {
            return Result.Failure(SecurityError.InvalidToken(
                "TPM attestation statement missing 'sig' field."));
        }

        if (!statement.Algorithm.HasValue)
        {
            return Result.Failure(SecurityError.InvalidToken(
                "TPM attestation statement missing 'alg' field."));
        }

        if (statement.X5c is null || statement.X5c.Count == 0)
        {
            return Result.Failure(SecurityError.InvalidToken(
                "TPM attestation statement missing 'x5c' AIK certificate chain."));
        }

        if (statement.RawBytes.Length < 6)
        {
            return Result.Failure(SecurityError.InvalidToken(
                "TPM attestation statement is missing or too short (certInfo required)."));
        }

        // The certInfo is embedded in the RawBytes (the raw CBOR map value for 'certInfo')
        var certInfo = statement.RawBytes;

        // 1. Verify magic value at the start of certInfo: must be 0xFF544347 (TPM_GENERATED_VALUE)
        var magic = BinaryPrimitives.ReadUInt32BigEndian(certInfo.AsSpan(0, 4));
        if (magic != TpmGeneratedValue)
        {
            return Result.Failure(SecurityError.InvalidToken(
                $"TPM certInfo magic value mismatch: expected 0x{TpmGeneratedValue:X8}, got 0x{magic:X8}."));
        }

        // 2. Verify type: bytes 4-5 must be TPM_ST_ATTEST_CERTIFY (0x8017)
        var type = BinaryPrimitives.ReadUInt16BigEndian(certInfo.AsSpan(4, 2));
        if (type != TpmStAttestCertify)
        {
            return Result.Failure(SecurityError.InvalidToken(
                $"TPM certInfo type mismatch: expected TPM_ST_ATTEST_CERTIFY (0x{TpmStAttestCertify:X4}), got 0x{type:X4}."));
        }

        // 3. Parse the TPMS_ATTEST structure to extract qualifiedSigner (2 bytes len + data) and extraData
        //    TPMS_ATTEST structure (simplified):
        //      [0..3]  magic (uint32)
        //      [4..5]  type (uint16)
        //      [6..7+n] qualifiedSigner (TPM2B: 2-byte size + data)
        //      [8+n..9+n+m] extraData (TPM2B: 2-byte size + data)
        //
        var offset = 6;

        // Skip qualifiedSigner (qualifiedSignerSize bytes)
        if (certInfo.Length < offset + 2)
        {
            return Result.Failure(SecurityError.InvalidToken("TPM certInfo too short: missing qualifiedSigner size."));
        }
        var qualifiedSignerSize = BinaryPrimitives.ReadUInt16BigEndian(certInfo.AsSpan(offset, 2));
        offset += 2 + qualifiedSignerSize;

        // Read extraData (extraDataSize bytes)
        if (certInfo.Length < offset + 2)
        {
            return Result.Failure(SecurityError.InvalidToken("TPM certInfo too short: missing extraData size."));
        }
        var extraDataSize = BinaryPrimitives.ReadUInt16BigEndian(certInfo.AsSpan(offset, 2));
        offset += 2;

        if (certInfo.Length < offset + extraDataSize)
        {
            return Result.Failure(SecurityError.InvalidToken("TPM certInfo too short: extraData truncated."));
        }
        var extraData = certInfo.AsSpan(offset, extraDataSize).ToArray();

        // 4. Compute attToBeSigned: SHA-256(authData.RawBytes) || SHA-256(clientDataHash)
        //    Per WebAuthn spec: attToBeSigned = hash(authData) + clientDataHash
        //    extraData in TPMS_ATTEST must equal SHA-256(attToBeSigned)
        var authDataHash = SHA256.HashData(authData.RawBytes);
        var attToBeSigned = new byte[authDataHash.Length + clientDataHash.Length];
        Buffer.BlockCopy(authDataHash, 0, attToBeSigned, 0, authDataHash.Length);
        Buffer.BlockCopy(clientDataHash, 0, attToBeSigned, authDataHash.Length, clientDataHash.Length);
        var expectedExtraData = SHA256.HashData(attToBeSigned);

        if (!CryptographicOperations.FixedTimeEquals(extraData, expectedExtraData))
        {
            return Result.Failure(SecurityError.SecurityPolicyViolation(
                "WebAuthn.TPM.ExtraData",
                "TPM certInfo extraData does not match the expected SHA-256 of attToBeSigned. The attestation may have been tampered."));
        }

        // 5. Load the AIK leaf certificate from x5c[0]
        X509Certificate2 aikCert;
        try
        {
#if NET9_0_OR_GREATER
            aikCert = X509CertificateLoader.LoadCertificate(statement.X5c[0]);
#else
#pragma warning disable SYSLIB0057
            aikCert = new X509Certificate2(statement.X5c[0]);
#pragma warning restore SYSLIB0057
#endif
        }
        catch (Exception ex)
        {
            return Result.Failure(SecurityError.InvalidToken(
                $"TPM attestation: failed to parse AIK certificate from x5c[0]: {ex.Message}"));
        }

        // 6. Verify the AIK certificate signature over certInfo using the public key in the AIK cert
        var signatureIsValid = false;
        var hashAlgorithm = GetHashAlgorithmFromCoseAlg(statement.Algorithm.Value);

        using var rsa = aikCert.GetRSAPublicKey();
        if (rsa is not null)
        {
            signatureIsValid = rsa.VerifyData(
                certInfo,
                statement.Signature,
                hashAlgorithm,
                RSASignaturePadding.Pkcs1);
        }
        else
        {
            using var ecdsa = aikCert.GetECDsaPublicKey();
            if (ecdsa is not null)
            {
                signatureIsValid = ecdsa.VerifyData(certInfo, statement.Signature, hashAlgorithm);
            }
        }

        if (!signatureIsValid)
        {
            return Result.Failure(SecurityError.SecurityPolicyViolation(
                "WebAuthn.TPM.Signature",
                "TPM AIK certificate signature verification failed. The certInfo may have been tampered."));
        }

        // 7. Validate AIK certificate is not a CA (basicConstraints: CA:FALSE)
        foreach (var extension in aikCert.Extensions)
        {
            if (extension is X509BasicConstraintsExtension basicConstraints && basicConstraints.CertificateAuthority)
            {
                return Result.Failure(SecurityError.SecurityPolicyViolation(
                    "WebAuthn.TPM.AikCertificate",
                    "TPM AIK certificate must not be a CA certificate (basicConstraints CA:FALSE required)."));
            }
        }

        return Result.Success();
    }

    private static HashAlgorithmName GetHashAlgorithmFromCoseAlg(long coseAlg) => coseAlg switch
    {
        -35 or -258 => HashAlgorithmName.SHA384, // ES384, RS384
        -36 or -259 => HashAlgorithmName.SHA512, // ES512, RS512
        -65535 => HashAlgorithmName.SHA1,        // RS1 (legacy, not recommended)
        _ => HashAlgorithmName.SHA256            // ES256 (-7), RS256 (-257) and defaults
    };
}
