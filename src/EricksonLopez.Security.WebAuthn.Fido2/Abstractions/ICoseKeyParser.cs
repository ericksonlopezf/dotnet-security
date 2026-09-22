// Copyright © Erickson Lopez. MIT License.

using System;
using EricksonLopez.Result;
using EricksonLopez.Security.WebAuthn.Fido2.Models;

namespace EricksonLopez.Security.WebAuthn.Fido2.Abstractions;

/// <summary>
/// Defines the contract for parsing binary CBOR-encoded COSE keys into <see cref="CosePublicKey"/> models.
/// </summary>
public interface ICoseKeyParser
{
    /// <summary>
    /// Parses a CBOR-encoded COSE Key map from a byte span.
    /// </summary>
    /// <param name="cborBytes">The raw CBOR byte span.</param>
    /// <returns>A result containing the parsed <see cref="CosePublicKey"/> or an error.</returns>
    Result<CosePublicKey> Parse(ReadOnlySpan<byte> cborBytes);
}
