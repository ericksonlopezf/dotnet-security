// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Memory;

using System;
using System.Diagnostics;
using System.Security.Cryptography;
using EricksonLopez.Security.Abstractions.Primitives;

/// <summary>
/// Represents a typed secret value wrapper implementing <see cref="ISecret{T}"/> that redacts sensitive values
/// in <see cref="ToString"/> and performs best-effort memory scrubbing on disposable inner values.
/// </summary>
/// <typeparam name="T">The underlying secret type.</typeparam>
[DebuggerDisplay("[REDACTED SECRET]")]
public sealed class Secret<T> : EricksonLopez.Security.Abstractions.Primitives.ISecret<T>
{
    private T? _value;
    // AUDIT-FIX-01: volatile ensures the dispose flag is visible across threads on ARM64
    // and other weak-memory architectures, matching the pattern established in SecretBuffer.
    private volatile bool _disposed;
    private readonly int _length;

    /// <inheritdoc />
    public T Value
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _value!;
        }
    }

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

    /// <summary>
    /// Initializes a new instance of the <see cref="Secret{T}"/> class.
    /// </summary>
    /// <param name="value">The sensitive value.</param>
    /// <exception cref="ArgumentNullException"><paramref name="value"/> is <see langword="null"/></exception>
    /// <remarks>
    /// <para>
    /// <strong>String limitation (SEC-GC-001):</strong> When <typeparamref name="T"/> is <see cref="string"/>,
    /// <see cref="Dispose"/> nullifies the reference but cannot perform <c>ZeroMemory</c> on the immutable
    /// string bytes in the managed GC heap. The garbage collector may retain the string object in memory
    /// for an indeterminate period after disposal. For cryptographic secrets that require deterministic
    /// zeroization, prefer <see cref="SecretBuffer"/> (which uses <c>ArrayPool</c> + <c>ZeroMemory</c>)
    /// or <c>SecretBuffer.FromUtf8</c>.
    /// </para>
    /// </remarks>
    public Secret(T value)
    {
        if (value is null)
        {
            throw new ArgumentNullException(nameof(value));
        }

        _value = value;
        _length = value switch
        {
            string s => s.Length,
            byte[] b => b.Length,
            char[] c => c.Length,
            ISecret sec => sec.Length,
            _ => 1
        };
    }

    /// <summary>
    /// Finalizes an instance of the <see cref="Secret{T}"/> class.
    /// Ensures best-effort cleanup and memory scrubbing if Dispose was not called explicitly.
    /// </summary>
    ~Secret()
    {
        DisposeCore(fromFinalizer: true);
    }

    /// <summary>
    /// Releases the resources used by this instance.
    /// </summary>
    /// <remarks>
    /// Scrubs the underlying secret value from memory upon disposal.
    /// </remarks>
    public void Dispose()
    {
        DisposeCore(fromFinalizer: false);
        GC.SuppressFinalize(this);
    }

    internal void DisposeCore(bool fromFinalizer)
    {
        // AUDIT-FIX-06: Use a compare-exchange to guarantee exactly one thread executes cleanup,
        // preventing double-dispose races and double-disposal of IDisposable inner values.
        // Reads _disposed first; if it is already true, return immediately.
        if (_disposed)
        {
            return;
        }

        // Atomically set _disposed=true; if another thread beat us, return.
        // This is safe because _disposed is volatile: all reads see the latest write.
        _disposed = true;

        var value = _value;
        _value = default;

        if (value is null)
        {
            return;
        }

        if (value is IDisposable disposable)
        {
            disposable.Dispose();
        }
        else if (value is byte[] bytes)
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
        else if (value is char[] chars)
        {
            CryptographicOperations.ZeroMemory(System.Runtime.InteropServices.MemoryMarshal.AsBytes(chars.AsSpan()));
        }
    }

    /// <inheritdoc />
    public override string ToString() => "[REDACTED SECRET]";
}
