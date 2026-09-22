// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Abstractions.Cryptography;

using System;
using EricksonLopez.Result;
using EricksonLopez.Security.Abstractions.Primitives;

/// <summary>
/// Defines the contract for high-performance digital signature generation and verification.
/// </summary>
public interface IDigitalSignatureEngine
{
    /// <summary>
    /// Signs the provided payload using the specified key.
    /// </summary>
    /// <param name="payload">The data to sign.</param>
    /// <param name="keyId">The identifier of the private key to use for signing.</param>
    /// <param name="signatureDestination">The destination span for the generated signature.</param>
    /// <param name="bytesWritten">The number of bytes written to the signature destination.</param>
    /// <returns>A <see cref="Result"/> indicating success or a cryptographic failure error.</returns>
    Result Sign(ReadOnlySpan<byte> payload, KeyIdentifier keyId, Span<byte> signatureDestination, out int bytesWritten);

    /// <summary>
    /// Verifies the digital signature of the provided payload using the specified key.
    /// </summary>
    /// <param name="payload">The data that was signed.</param>
    /// <param name="signature">The signature to verify.</param>
    /// <param name="keyId">The identifier of the public key to use for verification.</param>
    /// <returns>A <see cref="Result"/> indicating whether the signature is valid.</returns>
    Result Verify(ReadOnlySpan<byte> payload, ReadOnlySpan<byte> signature, KeyIdentifier keyId);
}
