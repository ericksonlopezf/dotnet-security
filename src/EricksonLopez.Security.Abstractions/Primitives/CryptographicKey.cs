// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Abstractions.Primitives;

using System;
using System.Diagnostics;

/// <summary>
/// Encapsulates a cryptographic key consisting of strong metadata and protected in-memory key material.
/// Implements <see cref="IDisposable"/> to wipe key bytes from memory when released.
/// </summary>
[DebuggerDisplay("{Metadata.KeyId}:{Metadata.Version} ({Metadata.Purpose}, {Metadata.Status})")]
public sealed class CryptographicKey : IDisposable
{
    private readonly ISecretBuffer _keyMaterial;
    private bool _disposed;

    /// <summary>
    /// Gets the immutable metadata associated with this cryptographic key.
    /// </summary>
    public KeyMetadata Metadata { get; }

    /// <summary>
    /// Gets the length of the key material in bytes.
    /// </summary>
    public int KeyLengthInBytes => _keyMaterial.Length;

    /// <summary>
    /// Gets a value indicating whether this key has been disposed.
    /// </summary>
    public bool IsDisposed => _disposed;

    /// <summary>
    /// Initializes a new instance of the <see cref="CryptographicKey"/> class.
    /// </summary>
    /// <param name="metadata">The key metadata.</param>
    /// <param name="keyMaterial">The memory-managed secret buffer containing the key bytes.</param>
    /// <exception cref="ArgumentNullException"><paramref name="metadata"/> or <paramref name="keyMaterial"/> is <see langword="null"/></exception>
    public CryptographicKey(KeyMetadata metadata, ISecretBuffer keyMaterial)
    {
        Metadata = metadata ?? throw new ArgumentNullException(nameof(metadata));
        _keyMaterial = keyMaterial ?? throw new ArgumentNullException(nameof(keyMaterial));
    }

    /// <summary>
    /// Returns a readonly span over the raw key bytes for immediate cryptographic execution.
    /// </summary>
    /// <returns>A readonly span containing the raw key material.</returns>
    /// <exception cref="ObjectDisposedException">The key has been disposed</exception>
    public ReadOnlySpan<byte> GetKeyBytes()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return _keyMaterial.Span;
    }

    /// <summary>
    /// Safely copies the key material to the provided destination span.
    /// </summary>
    /// <param name="destination">The destination buffer.</param>
    /// <returns><see langword="true"/> if successfully copied; otherwise, <see langword="false"/>.</returns>
    /// <exception cref="ObjectDisposedException">The key has been disposed</exception>
    public bool TryCopyKeyBytes(Span<byte> destination)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (destination.Length < _keyMaterial.Length)
        {
            return false;
        }

        _keyMaterial.Span.CopyTo(destination);
        return true;
    }

    /// <summary>
    /// Releases the resources used by this instance.
    /// </summary>
    /// <remarks>
    /// Scrubs the underlying key material from memory upon disposal.
    /// </remarks>
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _keyMaterial.Dispose();
        _disposed = true;
    }

    /// <inheritdoc />
    public override string ToString() => $"[CryptographicKey: {Metadata.KeyId}:{Metadata.Version}, Purpose={Metadata.Purpose}]";
}
