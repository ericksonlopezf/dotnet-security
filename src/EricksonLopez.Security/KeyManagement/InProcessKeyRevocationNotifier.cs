// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.KeyManagement;

using System;
using System.Collections.Concurrent;
using System.Threading;
using System.Threading.Tasks;
using EricksonLopez.Security.Abstractions.KeyManagement;
using EricksonLopez.Security.Abstractions.Primitives;

/// <summary>
/// Provides a high-performance, in-process, thread-safe implementation of <see cref="IKeyRevocationNotifier"/>.
/// Dispatches revocation events synchronously or asynchronously to registered in-process key rings.
/// </summary>
public sealed class InProcessKeyRevocationNotifier : IKeyRevocationNotifier
{
    private readonly ConcurrentDictionary<Guid, Action<KeyIdentifier, KeyVersion, KeyPurpose>> _subscribers = new();

    /// <summary>
    /// Initializes a new instance of the <see cref="InProcessKeyRevocationNotifier"/> class.
    /// </summary>
    public InProcessKeyRevocationNotifier()
    {
    }

    /// <inheritdoc />
    public ValueTask NotifyRevokedAsync(
        KeyIdentifier keyId,
        KeyVersion version,
        KeyPurpose purpose,
        CancellationToken cancellationToken = default)
    {
        if (cancellationToken.IsCancellationRequested)
        {
            return ValueTask.FromCanceled(cancellationToken);
        }

        foreach (var subscriber in _subscribers.Values)
        {
            try
            {
                subscriber(keyId, version, purpose);
            }
            catch
            {
                // Defensive isolation: prevent a failing subscriber from interrupting other listeners.
            }
        }

        return ValueTask.CompletedTask;
    }

    /// <inheritdoc />
    public IDisposable Subscribe(Action<KeyIdentifier, KeyVersion, KeyPurpose> handler)
    {
        ArgumentNullException.ThrowIfNull(handler);
        var subscriptionId = Guid.NewGuid();
        _subscribers.TryAdd(subscriptionId, handler);

        return new SubscriptionToken(() => _subscribers.TryRemove(subscriptionId, out _));
    }

    private sealed class SubscriptionToken : IDisposable
    {
        private Action? _unsubscribe;

        public SubscriptionToken(Action unsubscribe)
        {
            _unsubscribe = unsubscribe;
        }

        public void Dispose()
        {
            Interlocked.Exchange(ref _unsubscribe, null)?.Invoke();
        }
    }
}
