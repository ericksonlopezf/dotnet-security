// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Tokens;

using System;
using System.Buffers;
using System.Security.Cryptography;
using System.Text;
using EricksonLopez.Security.Abstractions.Tokens;
using EricksonLopez.Security.Randomness;

/// <summary>
/// Provides a token hasher implementation using HMAC-SHA256 (or keyed SHA-256) to produce secure,
/// deterministic hash digests for database token lookup without storing reversible token plaintext.
/// </summary>
public sealed class HmacSha256TokenHasher : ITokenHasher, IDisposable
{
    private readonly byte[]? _pepperKey;
    // AUDIT-FIX-02: volatile ensures dispose flag visibility on ARM64 and other weak-memory
    // architectures. Without volatile, Thread B calling TryHashToken/HashToken/VerifyToken
    // concurrently with Thread A calling Dispose() could read a stale false value of _disposed,
    // bypassing the ObjectDisposedException guard and accessing a zeroed _pepperKey.
    private volatile bool _disposed;


    /// <summary>
    /// Gets a value indicating whether this instance has been disposed.
    /// </summary>
    public bool IsDisposed => _disposed;

    /// <summary>
    /// Initializes a new instance of the <see cref="HmacSha256TokenHasher"/> class without a pepper key (standard SHA-256).
    /// </summary>
    /// <remarks>
    /// Without a pepper key, <see cref="HashToken"/> uses unkeyed <c>SHA-256</c> (not HMAC). This is
    /// deterministic and suitable for low-entropy token spaces, but provides no secret-keyed protection
    /// against precomputed lookup or rainbow table attacks. For production environments, prefer the
    /// <see cref="HmacSha256TokenHasher(ReadOnlySpan{byte})"/> overload and supply a 32-byte application-level
    /// pepper key stored separately from the token database.
    /// </remarks>
    public HmacSha256TokenHasher()
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="HmacSha256TokenHasher"/> class with an HMAC pepper key.
    /// </summary>
    /// <param name="pepperKey">The secret pepper key bytes.</param>
    /// <exception cref="ArgumentException"><paramref name="pepperKey"/> is empty</exception>
    public HmacSha256TokenHasher(ReadOnlySpan<byte> pepperKey)
    {
        if (pepperKey.IsEmpty)
        {
            throw new ArgumentException("Pepper key cannot be empty.", nameof(pepperKey));
        }

        _pepperKey = pepperKey.ToArray();
    }

    internal byte[]? PepperKey => _pepperKey;

    /// <summary>
    /// Releases the resources used by this instance and actively zeroes the pepper key bytes from memory.
    /// </summary>
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        if (_pepperKey is not null)
        {
            CryptographicOperations.ZeroMemory(_pepperKey);
        }
    }

    /// <summary>
    /// Computes the cryptographic hash of a token into a destination character span without heap allocations.
    /// </summary>
    /// <param name="token">The token character span to hash.</param>
    /// <param name="destination">The destination buffer which must be at least 64 characters in length.</param>
    /// <param name="charsWritten">When this method returns, the number of characters written to <paramref name="destination"/>.</param>
    /// <returns><see langword="true"/> if the hash was successfully written; otherwise, <see langword="false"/>.</returns>
    public bool TryHashToken(ReadOnlySpan<char> token, Span<char> destination, out int charsWritten)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        charsWritten = 0;
        if (token.IsEmpty || destination.Length < 64)
        {
            return false;
        }

        int maxByteCount = Encoding.UTF8.GetMaxByteCount(token.Length);
        byte[]? rented = null;
        // Stryker disable once Conditional,Equality : Stack allocation threshold vs heap allocation for large buffers
        Span<byte> tokenBytes = maxByteCount <= 256
            ? stackalloc byte[maxByteCount]
            : (rented = ArrayPool<byte>.Shared.Rent(maxByteCount));

        Span<byte> hash = stackalloc byte[32];
        try
        {
            int actualBytes = Encoding.UTF8.GetBytes(token, tokenBytes);
            var tokenSlice = tokenBytes[..actualBytes];

            if (_pepperKey is not null)
            {
                HMACSHA256.HashData(_pepperKey, tokenSlice, hash);
            }
            else
            {
                SHA256.HashData(tokenSlice, hash);
            }

            FormatHexLower(hash, destination[..64]);
            charsWritten = 64;
            return true;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(hash);
            CryptographicOperations.ZeroMemory(tokenBytes);
            if (rented is not null)
            {
                ArrayPool<byte>.Shared.Return(rented);
            }
        }
    }

    /// <inheritdoc />
    /// <remarks>
    /// <strong>Memory Note (HMAC-06):</strong> The returned <see langword="string"/> is a managed heap
    /// allocation containing the hex-encoded HMAC-SHA256 hash. .NET strings are immutable and cannot
    /// be explicitly zeroed — the hash value will remain in memory until the next garbage collection cycle.
    /// For callers operating in a hot path or that need to minimize the window during which the hash is
    /// accessible in memory, prefer <see cref="TryHashToken(ReadOnlySpan{char}, Span{char}, out int)"/>,
    /// which writes directly into a caller-provided <see cref="Span{T}"/> that can be zeroed after use.
    /// </remarks>
    public string HashToken(ReadOnlySpan<char> token)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (token.IsEmpty)
        {
            throw new ArgumentException("Token cannot be empty.", nameof(token));
        }

        Span<char> hexChars = stackalloc char[64];
        TryHashToken(token, hexChars, out _);
        return new string(hexChars);
    }

    /// <inheritdoc />
    public bool VerifyToken(ReadOnlySpan<char> token, string expectedHash)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (token.IsEmpty || string.IsNullOrWhiteSpace(expectedHash) || expectedHash.Length != 64)
        {
            return false;
        }

        Span<char> actualHash = stackalloc char[64];
        TryHashToken(token, actualHash, out _);
        return ConstantTimeComparer.Shared.FixedTimeEquals(actualHash, expectedHash.AsSpan());
    }

    private static void FormatHexLower(ReadOnlySpan<byte> bytes, Span<char> destination)
    {
        const string hexAlphabet = "0123456789abcdef";
        for (int i = 0; i < bytes.Length; i++)
        {
            byte b = bytes[i];
            // Stryker disable once Bitwise : byte is unsigned so >> 4 and >>> 4 are mathematically identical
            destination[i * 2] = hexAlphabet[b >> 4];
            destination[i * 2 + 1] = hexAlphabet[b & 0xF];
        }
    }
}
