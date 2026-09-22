// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Mfa;

using System;
using System.Threading;
using System.Threading.Tasks;

/// <summary>
/// Provides a delegate-driven implementation of <see cref="ITotpReplayStore"/> to easily integrate
/// distributed stores (such as Redis, distributed caches, or shared databases) without requiring a full subclass.
/// </summary>
public sealed class DelegateTotpReplayStore : ITotpReplayStore
{
    private readonly Func<string, DateTimeOffset, CancellationToken, ValueTask<bool>> _asyncHandler;
    private readonly Func<string, DateTimeOffset, bool>? _syncHandler;

    /// <summary>
    /// Initializes a new instance of the <see cref="DelegateTotpReplayStore"/> class with an asynchronous delegate handler.
    /// </summary>
    /// <param name="asyncHandler">The asynchronous delegate invoked to record replay keys.</param>
    /// <exception cref="ArgumentNullException"><paramref name="asyncHandler"/> is <see langword="null"/></exception>
    public DelegateTotpReplayStore(Func<string, DateTimeOffset, CancellationToken, ValueTask<bool>> asyncHandler)
        : this(asyncHandler, null)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="DelegateTotpReplayStore"/> class with both asynchronous and synchronous handlers.
    /// </summary>
    /// <param name="asyncHandler">The asynchronous delegate invoked to record replay keys.</param>
    /// <param name="syncHandler">Optional synchronous delegate invoked during synchronous verification.</param>
    /// <exception cref="ArgumentNullException"><paramref name="asyncHandler"/> is <see langword="null"/></exception>
    public DelegateTotpReplayStore(
        Func<string, DateTimeOffset, CancellationToken, ValueTask<bool>> asyncHandler,
        Func<string, DateTimeOffset, bool>? syncHandler)
    {
        _asyncHandler = asyncHandler ?? throw new ArgumentNullException(nameof(asyncHandler));
        _syncHandler = syncHandler;
    }

    /// <inheritdoc />
    public bool TryAdd(string key, DateTimeOffset expiresAt)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(key);

        if (_syncHandler != null)
        {
            return _syncHandler(key, expiresAt);
        }

        return _asyncHandler(key, expiresAt, CancellationToken.None).AsTask().GetAwaiter().GetResult();
    }

    /// <inheritdoc />
    public ValueTask<bool> TryAddAsync(string key, DateTimeOffset expiresAt, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(key);

        if (cancellationToken.IsCancellationRequested)
        {
            return ValueTask.FromCanceled<bool>(cancellationToken);
        }

        return _asyncHandler(key, expiresAt, cancellationToken);
    }
}
