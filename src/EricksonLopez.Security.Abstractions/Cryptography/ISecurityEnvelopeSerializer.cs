// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Abstractions.Cryptography;

using System;
using EricksonLopez.Result;

/// <summary>
/// Defines contracts for serializing and deserializing tamper-resistant binary <see cref="SecurityEnvelope"/> instances.
/// </summary>
public interface ISecurityEnvelopeSerializer
{
    /// <summary>
    /// Serializes a <see cref="SecurityEnvelope"/> into a newly allocated binary byte array.
    /// </summary>
    /// <param name="envelope">The envelope to serialize.</param>
    /// <returns>A byte array containing the serialized envelope.</returns>
    byte[] Serialize(SecurityEnvelope envelope);

    /// <summary>
    /// Serializes a <see cref="SecurityEnvelope"/> into a caller-supplied destination span for zero allocations.
    /// </summary>
    /// <param name="envelope">The envelope to serialize.</param>
    /// <param name="destination">The destination byte span.</param>
    /// <param name="bytesWritten">The total number of bytes written to the destination.</param>
    /// <returns><see langword="true"/> if the destination buffer was large enough; otherwise, <see langword="false"/>.</returns>
    bool TrySerialize(SecurityEnvelope envelope, Span<byte> destination, out int bytesWritten);

    /// <summary>
    /// Deserializes a binary payload into a validated <see cref="SecurityEnvelope"/>.
    /// </summary>
    /// <param name="payload">The binary serialized payload span.</param>
    /// <returns>A <see cref="Result{T}"/> containing the reconstructed <see cref="SecurityEnvelope"/> or an error.</returns>
    Result<SecurityEnvelope> Deserialize(ReadOnlySpan<byte> payload);
}
