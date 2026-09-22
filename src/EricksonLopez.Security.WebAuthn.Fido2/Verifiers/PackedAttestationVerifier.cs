// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.WebAuthn.Fido2.Verifiers;

using System;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using EricksonLopez.Result;
using EricksonLopez.Security.Abstractions.Errors;
using EricksonLopez.Security.WebAuthn.Fido2.Abstractions;
using EricksonLopez.Security.WebAuthn.Fido2.Enums;
using EricksonLopez.Security.WebAuthn.Fido2.Models;

/// <summary>
/// Verifies the "packed" WebAuthn attestation statement format (supporting both self-attestation and X.509 attestation chains).
/// </summary>
public sealed class PackedAttestationVerifier : IAttestationVerifier
{
    /// <summary>
    /// Gets the attestation statement format identifier ("packed").
    /// </summary>
    public string Format => "packed";

    /// <inheritdoc />
    public Result Verify(AttestationStatement statement, AuthenticatorData authData, byte[] clientDataHash)
    {
        if (statement.Signature is null || statement.Signature.Length == 0)
        {
            return Result.Failure(SecurityError.InvalidToken("Packed attestation statement missing signature ('sig')."));
        }

        if (!statement.Algorithm.HasValue)
        {
            return Result.Failure(SecurityError.InvalidToken("Packed attestation statement missing algorithm identifier ('alg')."));
        }

        // Verification data: authData.RawBytes || clientDataHash
        var signedData = new byte[authData.RawBytes.Length + clientDataHash.Length];
        Buffer.BlockCopy(authData.RawBytes, 0, signedData, 0, authData.RawBytes.Length);
        Buffer.BlockCopy(clientDataHash, 0, signedData, authData.RawBytes.Length, clientDataHash.Length);

        // Case 1: X.509 Certificate Chain Attestation (x5c present)
        if (statement.X5c is { Count: > 0 })
        {
            try
            {
#if NET9_0_OR_GREATER
                using var cert = X509CertificateLoader.LoadCertificate(statement.X5c[0]);
#else
                using var cert = new X509Certificate2(statement.X5c[0]);
#endif
                var alg = (CoseAlgorithmIdentifier)statement.Algorithm.Value;

                if (cert.GetECDsaPublicKey() is { } ecdsa)
                {
                    using (ecdsa)
                    {
                        var hashAlg = GetHashAlgorithmName(alg);
                        var valid = ecdsa.VerifyData(signedData, statement.Signature, hashAlg);
                        if (!valid)
                        {
                            // Try DER format if raw IEEE format failed (some authenticators emit DER ASN.1 signatures)
                            valid = ecdsa.VerifyData(signedData, statement.Signature, hashAlg, DSASignatureFormat.Rfc3279DerSequence);
                        }

                        return valid
                            ? Result.Success()
                            : Result.Failure(SecurityError.DecryptionFailed("Packed X.509 ECDSA attestation signature verification failed."));
                    }
                }

                if (cert.GetRSAPublicKey() is { } rsa)
                {
                    using (rsa)
                    {
                        var hashAlg = GetHashAlgorithmName(alg);
                        var padding = alg == CoseAlgorithmIdentifier.PS256 ? RSASignaturePadding.Pss : RSASignaturePadding.Pkcs1;
                        var valid = rsa.VerifyData(signedData, statement.Signature, hashAlg, padding);

                        return valid
                            ? Result.Success()
                            : Result.Failure(SecurityError.DecryptionFailed("Packed X.509 RSA attestation signature verification failed."));
                    }
                }

                return Result.Failure(SecurityError.InvalidKey("Unsupported public key algorithm in attestation certificate."));
            }
            catch (Exception ex)
            {
                return Result.Failure(SecurityError.DecryptionFailed($"Failed to verify packed X.509 attestation: {ex.Message}"));
            }
        }

        // Case 2: Self-Attestation (Surrogate Attestation)
        if (authData.AttestedCredentialData is null)
        {
            return Result.Failure(SecurityError.InvalidToken("Packed self-attestation requires attestedCredentialData in authData."));
        }

        var pubKey = authData.AttestedCredentialData.PublicKey;
        return VerifySignatureWithCoseKey(pubKey, signedData, statement.Signature, (CoseAlgorithmIdentifier)statement.Algorithm.Value);
    }

    private static Result VerifySignatureWithCoseKey(
        CosePublicKey pubKey,
        byte[] signedData,
        byte[] signature,
        CoseAlgorithmIdentifier algorithm)
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
                var hashAlg = GetHashAlgorithmName(algorithm);
                var valid = ecdsa.VerifyData(signedData, signature, hashAlg);
                if (!valid)
                {
                    valid = ecdsa.VerifyData(signedData, signature, hashAlg, DSASignatureFormat.Rfc3279DerSequence);
                }

                return valid
                    ? Result.Success()
                    : Result.Failure(SecurityError.DecryptionFailed("Self-attestation ECDSA signature verification failed."));
            }

            if (pubKey.KeyType == CoseKeyType.Rsa && pubKey.Modulus is not null && pubKey.Exponent is not null)
            {
                var rsaParams = new RSAParameters
                {
                    Modulus = pubKey.Modulus,
                    Exponent = pubKey.Exponent
                };

                using var rsa = RSA.Create(rsaParams);
                var hashAlg = GetHashAlgorithmName(algorithm);
                var padding = algorithm == CoseAlgorithmIdentifier.PS256 ? RSASignaturePadding.Pss : RSASignaturePadding.Pkcs1;
                var valid = rsa.VerifyData(signedData, signature, hashAlg, padding);

                return valid
                    ? Result.Success()
                    : Result.Failure(SecurityError.DecryptionFailed("Self-attestation RSA signature verification failed."));
            }

            return Result.Failure(SecurityError.InvalidKey($"Unsupported key type for self-attestation: {pubKey.KeyType}."));
        }
        catch (Exception ex)
        {
            return Result.Failure(SecurityError.DecryptionFailed($"Self-attestation verification error: {ex.Message}"));
        }
    }

    private static HashAlgorithmName GetHashAlgorithmName(CoseAlgorithmIdentifier alg) => alg switch
    {
        CoseAlgorithmIdentifier.ES384 => HashAlgorithmName.SHA384,
        CoseAlgorithmIdentifier.ES512 => HashAlgorithmName.SHA512,
        _ => HashAlgorithmName.SHA256
    };
}
