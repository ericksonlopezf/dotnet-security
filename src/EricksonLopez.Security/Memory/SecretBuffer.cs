// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Memory;

using System;
using System.Buffers;
using System.Security.Cryptography;
using System.Threading;
using EricksonLopez.Security.Abstractions.Primitives;

/// <summary>
/// Provides a high-performance, memory-scrubbing byte buffer that wipes its memory with
/// <see cref="CryptographicOperations.ZeroMemory(Span{byte})"/> when disposed.
/// Allocates from <see cref="ArrayPool{T}.Shared"/> for efficiency and low GC pressure.
/// </summary>
public sealed class SecretBuffer : ISecretBuffer
{
    private byte[]? _rentedBuffer;
    private readonly int _length;
    // FINDING-CRIT-02 (resolved): volatile guarantees memory visibility on ARM64 and weak-memory
    // architectures so that a Dispose() on Thread A is immediately visible to Thread B reading
    // _disposed in Span / GetWritableSpan.
    private volatile bool _disposed;

    /// <inheritdoc />
    public int Length
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _length;
        }
    }

    /// <inheritdoc />
    public bool IsDisposed => _disposed;

    // Gets the underlying rented buffer for zero-memory wiping assertions.
    // Internal diagnostic hook to avoid brittle reflection in unit tests.
    internal byte[]? DangerousRentedBufferForTesting => _rentedBuffer;

    /// <inheritdoc />
    public ReadOnlySpan<byte> Span
    {
        get
        {
            var buffer = _rentedBuffer;
            ObjectDisposedException.ThrowIf(_disposed || buffer is null, this);
            return buffer.AsSpan(0, _length);
        }
    }



    /// <summary>
    /// Initializes a new instance of the <see cref="SecretBuffer"/> class by renting a buffer from the array pool.
    /// </summary>
    /// <param name="length">The required length in bytes.</param>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="length"/> is less than or equal to zero</exception>
    public SecretBuffer(int length)
    {
        if (length <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(length), length, "Secret buffer length must be greater than zero.");
        }

        _length = length;
        _rentedBuffer = ArrayPool<byte>.Shared.Rent(length);
        // Ensure the entire rented buffer capacity is clean before use, eliminating slack space leakage (VULN-006)
        CryptographicOperations.ZeroMemory(_rentedBuffer);
    }

    /// <summary>
    /// Creates a new <see cref="SecretBuffer"/> by copying bytes from a source span.
    /// </summary>
    /// <param name="source">The source byte span.</param>
    /// <returns>A new <see cref="SecretBuffer"/> containing a copy of the source bytes.</returns>
    /// <exception cref="ArgumentException"><paramref name="source"/> is empty</exception>
    public static SecretBuffer FromSpan(ReadOnlySpan<byte> source)
    {
        if (source.IsEmpty)
        {
            throw new ArgumentException("Source span cannot be empty.", nameof(source));
        }

        var buffer = new SecretBuffer(source.Length);
        source.CopyTo(buffer.GetWritableSpan());
        return buffer;
    }

    /// <summary>
    /// Creates a new <see cref="SecretBuffer"/> populated with cryptographically strong random bytes.
    /// </summary>
    /// <param name="length">The number of random bytes.</param>
    /// <returns>A new <see cref="SecretBuffer"/>.</returns>
    public static SecretBuffer CreateRandom(int length)
    {
        var buffer = new SecretBuffer(length);
        RandomNumberGenerator.Fill(buffer.GetWritableSpan());
        return buffer;
    }

    /// <summary>
    /// Creates a new <see cref="SecretBuffer"/> by encoding the provided character span into UTF-8.
    /// </summary>
    /// <param name="chars">The character span containing sensitive text.</param>
    /// <returns>A new <see cref="SecretBuffer"/> containing the UTF-8 bytes.</returns>
    /// <exception cref="ArgumentException"><paramref name="chars"/> is empty</exception>
    public static SecretBuffer FromUtf8(ReadOnlySpan<char> chars)
    {
        if (chars.IsEmpty)
        {
            throw new ArgumentException("Source characters cannot be empty.", nameof(chars));
        }

        int byteCount = System.Text.Encoding.UTF8.GetByteCount(chars);
        var buffer = new SecretBuffer(byteCount);
        System.Text.Encoding.UTF8.GetBytes(chars, buffer.GetWritableSpan());
        return buffer;
    }

    /// <summary>
    /// Returns a writable span over the secret buffer for initial population.
    /// Access should be limited strictly to construction/initialization.
    /// </summary>
    /// <returns>A writable span.</returns>
    /// <exception cref="ObjectDisposedException">The buffer has been disposed</exception>
    public Span<byte> GetWritableSpan()
    {
        var buffer = _rentedBuffer;
        ObjectDisposedException.ThrowIf(_disposed || buffer is null, this);
        return buffer.AsSpan(0, _length);
    }

    /// <summary>
    /// Performs constant-time comparison of this secret buffer against another byte span.
    /// </summary>
    /// <param name="other">The other byte span.</param>
    /// <returns><see langword="true"/> if equal in constant time; otherwise, <see langword="false"/>.</returns>
    public bool FixedTimeEquals(ReadOnlySpan<byte> other)
    {
        var buffer = _rentedBuffer;
        ObjectDisposedException.ThrowIf(_disposed || buffer is null, this);
        return CryptographicOperations.FixedTimeEquals(buffer.AsSpan(0, _length), other);
    }

    /// <summary>
    /// Finalizes an instance of the <see cref="SecretBuffer"/> class.
    /// Ensures the rented buffer is zeroed out and returned to the pool if Dispose was omitted.
    /// </summary>
    ~SecretBuffer()
    {
        DisposeCore(fromFinalizer: true);
    }

    /// <summary>
    /// Releases the resources used by this instance.
    /// </summary>
    /// <remarks>
    /// Zeroes out the underlying rented memory buffer upon disposal and returns it to the pool.
    /// </remarks>
    public void Dispose()
    {
        DisposeCore(fromFinalizer: false);
        GC.SuppressFinalize(this);
    }

    private void DisposeCore(bool fromFinalizer)
    {
        _disposed = true;
        var buffer = Interlocked.Exchange(ref _rentedBuffer, null);
        if (buffer is null)
        {
            return;
        }

        CryptographicOperations.ZeroMemory(buffer);
        if (!fromFinalizer)
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    /// <inheritdoc />
    public override string ToString() => "[REDACTED SECRET BUFFER]";
}
