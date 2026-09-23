// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.WebAuthn.Fido2.Verifiers;

using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using EricksonLopez.Result;
using EricksonLopez.Security.Abstractions.Errors;
using EricksonLopez.Security.WebAuthn.Fido2.Abstractions;
using EricksonLopez.Security.WebAuthn.Fido2.Models;

/// <summary>
/// Verifies the "android-safetynet" WebAuthn attestation statement format.
/// </summary>
/// <remarks>
/// Android SafetyNet attestation uses a signed JWT (JSON Web Token) issued by Google's
/// SafetyNet API. The JWT contains a <c>nonce</c> binding the attestation to the
/// authenticator data, and <c>ctsProfileMatch</c> / <c>basicIntegrity</c> claims
/// indicating the integrity state of the Android device.
/// <para>
/// Reference: WebAuthn Level 2 §8.5 — Android SafetyNet Attestation Statement Format.
/// </para>
/// </remarks>
public sealed class AndroidSafetyNetAttestationVerifier : IAttestationVerifier
{
    /// <summary>
    /// Gets the attestation statement format identifier ("android-safetynet").
    /// </summary>
    public string Format => "android-safetynet";

    /// <inheritdoc />
    public Result Verify(AttestationStatement statement, AuthenticatorData authData, byte[] clientDataHash)
    {
        // 1. The SafetyNet attestation statement contains a 'response' field: a compact JWT string.
        //    Parse the JWT components: header.payload.signature (base64url encoded).
        if (statement.RawBytes.Length == 0)
        {
            return Result.Failure(SecurityError.InvalidToken(
                "AndroidSafetyNet attestation statement is empty."));
        }

        // The 'response' field in the CBOR map is the SafetyNet JWS as a UTF-8 string.
        string jwtString;
        try
        {
            jwtString = DecodeJwsUtf8(statement.RawBytes);
        }
        catch (Exception ex)
        {
            return Result.Failure(SecurityError.InvalidToken(
                $"AndroidSafetyNet: failed to decode JWS response bytes: {ex.Message}"));
        }

        // 2. Split JWT into header.payload.signature
        var parts = jwtString.Split('.');
        if (parts.Length != 3)
        {
            return Result.Failure(SecurityError.InvalidToken(
                "AndroidSafetyNet JWS does not have the expected 3-part structure (header.payload.signature)."));
        }

        var headerBase64 = parts[0];
        var payloadBase64 = parts[1];
        var signatureBase64 = parts[2];

        // 3. Decode and parse payload
        byte[] payloadBytes;
        try
        {
            payloadBytes = DecodeBase64Url(payloadBase64);
        }
        catch (Exception ex)
        {
            return Result.Failure(SecurityError.InvalidToken(
                $"AndroidSafetyNet: failed to decode JWS payload: {ex.Message}"));
        }

        JsonDocument payloadDoc;
        try
        {
            payloadDoc = JsonDocument.Parse(payloadBytes);
        }
        catch (JsonException ex)
        {
            return Result.Failure(SecurityError.InvalidToken(
                $"AndroidSafetyNet: JWS payload is not valid JSON: {ex.Message}"));
        }

        using (payloadDoc)
        {
            var root = payloadDoc.RootElement;

            // 4. Verify nonce binding: SHA-256(authData || clientDataHash) must match payload.nonce
            var nonceData = new byte[authData.RawBytes.Length + clientDataHash.Length];
            Buffer.BlockCopy(authData.RawBytes, 0, nonceData, 0, authData.RawBytes.Length);
            Buffer.BlockCopy(clientDataHash, 0, nonceData, authData.RawBytes.Length, clientDataHash.Length);

            var expectedNonceHash = SHA256.HashData(nonceData);
            var expectedNonceHex = Convert.ToHexString(expectedNonceHash).ToLowerInvariant();

            if (!root.TryGetProperty("nonce", out var nonceElement))
            {
                return Result.Failure(SecurityError.InvalidToken(
                    "AndroidSafetyNet: JWS payload is missing the 'nonce' field."));
            }

            var actualNonce = nonceElement.GetString() ?? string.Empty;
            // SafetyNet nonce is the Base64-encoded SHA-256 hash
            byte[] nonceDecoded;
            try
            {
                nonceDecoded = Convert.FromBase64String(actualNonce);
            }
            catch
            {
                return Result.Failure(SecurityError.InvalidToken(
                    "AndroidSafetyNet: 'nonce' field in JWS payload is not valid Base64."));
            }

            var actualNonceHex = Convert.ToHexString(nonceDecoded).ToLowerInvariant();
            if (!CryptographicOperations.FixedTimeEquals(
                Encoding.UTF8.GetBytes(expectedNonceHex),
                Encoding.UTF8.GetBytes(actualNonceHex)))
            {
                return Result.Failure(SecurityError.SecurityPolicyViolation(
                    "WebAuthn.SafetyNet.Nonce",
                    "AndroidSafetyNet attestation nonce does not match the expected authenticator data hash. Possible tampering."));
            }

            // 5. Verify device integrity claims
            if (root.TryGetProperty("ctsProfileMatch", out var ctsElement) && !ctsElement.GetBoolean())
            {
                return Result.Failure(SecurityError.SecurityPolicyViolation(
                    "WebAuthn.SafetyNet.CtsProfileMatch",
                    "AndroidSafetyNet: ctsProfileMatch is false. The device does not pass the Android compatibility test suite."));
            }

            if (root.TryGetProperty("basicIntegrity", out var integrityElement) && !integrityElement.GetBoolean())
            {
                return Result.Failure(SecurityError.SecurityPolicyViolation(
                    "WebAuthn.SafetyNet.BasicIntegrity",
                    "AndroidSafetyNet: basicIntegrity is false. The device has been rooted, unlocked, or tampered."));
            }

            // 6. Verify JWS signature using the leaf certificate from the x5c chain in the JWS header
            byte[] headerBytes;
            try
            {
                headerBytes = DecodeBase64Url(headerBase64);
            }
            catch (Exception ex)
            {
                return Result.Failure(SecurityError.InvalidToken(
                    $"AndroidSafetyNet: failed to decode JWS header: {ex.Message}"));
            }

            using var headerDoc = JsonDocument.Parse(headerBytes);
            var headerRoot = headerDoc.RootElement;

            if (!headerRoot.TryGetProperty("x5c", out var x5cElement) || x5cElement.ValueKind != JsonValueKind.Array)
            {
                return Result.Failure(SecurityError.InvalidToken(
                    "AndroidSafetyNet: JWS header is missing the 'x5c' certificate chain."));
            }

            X509Certificate2? leafCert = null;
            try
            {
                foreach (var certElement in x5cElement.EnumerateArray())
                {
                    var certBase64 = certElement.GetString();
                    if (string.IsNullOrEmpty(certBase64)) continue;
                    var certDer = Convert.FromBase64String(certBase64);
#if NET9_0_OR_GREATER
                    leafCert = X509CertificateLoader.LoadCertificate(certDer);
#else
#pragma warning disable SYSLIB0057
                    leafCert = new X509Certificate2(certDer);
#pragma warning restore SYSLIB0057
#endif
                    break; // We only need the leaf certificate for signature verification
                }
            }
            catch (Exception ex)
            {
                return Result.Failure(SecurityError.InvalidToken(
                    $"AndroidSafetyNet: failed to parse leaf certificate from x5c: {ex.Message}"));
            }

            if (leafCert is null)
            {
                return Result.Failure(SecurityError.InvalidToken(
                    "AndroidSafetyNet: x5c array is empty or contains no valid certificate."));
            }

            // Verify the JWS signature: sign(headerBase64 + "." + payloadBase64) using the leaf cert's public key
            byte[] signatureBytes;
            try
            {
                signatureBytes = DecodeBase64Url(signatureBase64);
            }
            catch (Exception ex)
            {
                return Result.Failure(SecurityError.InvalidToken(
                    $"AndroidSafetyNet: failed to decode JWS signature: {ex.Message}"));
            }

            var signingInput = Encoding.UTF8.GetBytes(headerBase64 + "." + payloadBase64);
            var isSignatureValid = false;

            using var rsa = leafCert.GetRSAPublicKey();
            if (rsa is not null)
            {
                isSignatureValid = rsa.VerifyData(
                    signingInput,
                    signatureBytes,
                    HashAlgorithmName.SHA256,
                    RSASignaturePadding.Pkcs1);
            }
            else
            {
                using var ecdsa = leafCert.GetECDsaPublicKey();
                if (ecdsa is not null)
                {
                    isSignatureValid = ecdsa.VerifyData(
                        signingInput,
                        signatureBytes,
                        HashAlgorithmName.SHA256);
                }
            }

            if (!isSignatureValid)
            {
                return Result.Failure(SecurityError.SecurityPolicyViolation(
                    "WebAuthn.SafetyNet.Signature",
                    "AndroidSafetyNet: JWS signature verification failed. The attestation may have been tampered."));
            }

            // 7. Validate that the leaf certificate was issued by Google's SafetyNet CA
            //    (hostname check: attest.android.com)
            var subjectCn = leafCert.GetNameInfo(X509NameType.DnsName, forIssuer: false);
            if (!string.Equals(subjectCn, "attest.android.com", StringComparison.OrdinalIgnoreCase))
            {
                return Result.Failure(SecurityError.SecurityPolicyViolation(
                    "WebAuthn.SafetyNet.CertificateSubject",
                    $"AndroidSafetyNet: leaf certificate subject does not match 'attest.android.com'. Got: '{subjectCn}'."));
            }

            return Result.Success();
        }
    }

    private static byte[] DecodeBase64Url(string base64Url)
    {
        // Convert base64url to standard base64
        var standardBase64 = base64Url
            .Replace('-', '+')
            .Replace('_', '/');

        // Pad to multiple of 4
        switch (standardBase64.Length % 4)
        {
            case 2: standardBase64 += "=="; break;
            case 3: standardBase64 += "="; break;
        }

        return Convert.FromBase64String(standardBase64);
    }

    internal static readonly UTF8Encoding StrictUtf8 = new(false, throwOnInvalidBytes: true);

    private static string DecodeJwsUtf8(byte[] rawBytes) =>
        StrictUtf8.GetString(rawBytes).Trim();
}
