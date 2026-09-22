// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Abstractions.Primitives;

using System;

/// <summary>
/// Defines a contract for a byte-oriented secret buffer whose underlying memory is scrubbed
/// with <c>CryptographicOperations.ZeroMemory</c> upon disposal.
/// </summary>
public interface ISecretBuffer : ISecret
{
    /// <summary>
    /// Gets a read-only span over the secret buffer for zero-allocation access.
    /// Access should be bounded by a <see langword="scoped"/> or <see langword="using"/> block.
    /// </summary>
    /// <exception cref="ObjectDisposedException">The buffer has been disposed</exception>
    ReadOnlySpan<byte> Span { get; }
}
