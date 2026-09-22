// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.WebAuthn.Fido2.Parsers;

using System;
using System.Formats.Cbor;
using EricksonLopez.Result;
using EricksonLopez.Security.Abstractions.Errors;
using EricksonLopez.Security.WebAuthn.Fido2.Abstractions;
using EricksonLopez.Security.WebAuthn.Fido2.Enums;
using EricksonLopez.Security.WebAuthn.Fido2.Models;

/// <summary>
/// Decodes CBOR-encoded COSE Key structures into <see cref="CosePublicKey"/> models.
/// </summary>
public sealed class CoseKeyParser : ICoseKeyParser
{
    /// <inheritdoc />
    public Result<CosePublicKey> Parse(ReadOnlySpan<byte> cborBytes)
    {
        if (cborBytes.IsEmpty)
        {
            return Result<CosePublicKey>.Failure(SecurityError.InvalidKey("COSE key CBOR payload is empty."));
        }

        try
        {
            var reader = new CborReader(cborBytes.ToArray(), CborConformanceMode.Strict);
            var mapLength = reader.ReadStartMap();

            CoseKeyType? keyType = null;
            CoseAlgorithmIdentifier? algorithm = null;
            CoseEllipticCurve? curve = null;
            byte[]? x = null;
            byte[]? y = null;
            byte[]? modulus = null;
            byte[]? exponent = null;

            while (reader.PeekState() != CborReaderState.EndMap)
            {
                var label = reader.ReadInt64();

                switch (label)
                {
                    case 1: // kty (Key Type)
                        keyType = (CoseKeyType)reader.ReadInt32();
                        break;

                    case 3: // alg (Algorithm)
                        algorithm = (CoseAlgorithmIdentifier)reader.ReadInt32();
                        break;

                    case -1: // crv (Curve) for EC2/OKP, or n (Modulus) for RSA
                        if (reader.PeekState() == CborReaderState.ByteString)
                        {
                            modulus = reader.ReadByteString();
                        }
                        else
                        {
                            curve = (CoseEllipticCurve)reader.ReadInt32();
                        }
                        break;

                    case -2: // x coordinate for EC2/OKP, or e (Exponent) for RSA
                        if (keyType == CoseKeyType.Rsa)
                        {
                            exponent = reader.ReadByteString();
                        }
                        else
                        {
                            x = reader.ReadByteString();
                        }
                        break;

                    case -3: // y coordinate for EC2
                        y = reader.ReadByteString();
                        break;

                    default:
                        reader.SkipValue();
                        break;
                }
            }

            reader.ReadEndMap();

            if (!keyType.HasValue)
            {
                return Result<CosePublicKey>.Failure(SecurityError.InvalidKey("COSE key is missing required 'kty' parameter."));
            }

            if (!algorithm.HasValue)
            {
                return Result<CosePublicKey>.Failure(SecurityError.InvalidKey("COSE key is missing required 'alg' parameter."));
            }

            var bytesConsumed = cborBytes.Length - reader.BytesRemaining;
            var result = new CosePublicKey(
                keyType.Value,
                algorithm.Value,
                cborBytes.Slice(0, bytesConsumed).ToArray(),
                curve,
                x,
                y,
                modulus,
                exponent);

            return Result<CosePublicKey>.Success(result);
        }
        catch (CborContentException ex)
        {
            return Result<CosePublicKey>.Failure(SecurityError.InvalidKey($"Invalid CBOR encoding in COSE key: {ex.Message}"));
        }
        catch (Exception ex)
        {
            return Result<CosePublicKey>.Failure(SecurityError.InvalidKey($"Failed to parse COSE key: {ex.Message}"));
        }
    }
}
