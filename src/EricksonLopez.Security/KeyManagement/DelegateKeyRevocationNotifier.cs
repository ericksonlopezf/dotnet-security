// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.KeyManagement;

using System;
using System.Threading;
using System.Threading.Tasks;
using EricksonLopez.Security.Abstractions.KeyManagement;
using EricksonLopez.Security.Abstractions.Primitives;

/// <summary>
/// Provides a distributed-ready adapter for <see cref="IKeyRevocationNotifier"/> that forwards key revocation broadcasts
/// to an external message broker or distributed cache (such as Redis Pub/Sub, RabbitMQ, Kafka, or Azure Service Bus)
/// while coordinating local in-process notification across active <see cref="IKeyRing"/> instances.
/// </summary>
public sealed class DelegateKeyRevocationNotifier : IKeyRevocationNotifier
{
    private readonly Func<KeyIdentifier, KeyVersion, KeyPurpose, CancellationToken, ValueTask> _publishHandler;
    private readonly InProcessKeyRevocationNotifier _localNotifier = new();

    /// <summary>
    /// Initializes a new instance of the <see cref="DelegateKeyRevocationNotifier"/> class.
    /// </summary>
    /// <param name="publishHandler">The asynchronous delegate invoked to broadcast key revocation events to an external message broker.</param>
    /// <exception cref="ArgumentNullException"><paramref name="publishHandler"/> is <see langword="null"/></exception>
    public DelegateKeyRevocationNotifier(
        Func<KeyIdentifier, KeyVersion, KeyPurpose, CancellationToken, ValueTask> publishHandler)
    {
        _publishHandler = publishHandler ?? throw new ArgumentNullException(nameof(publishHandler));
    }

    /// <inheritdoc />
    public async ValueTask NotifyRevokedAsync(
        KeyIdentifier keyId,
        KeyVersion version,
        KeyPurpose purpose,
        CancellationToken cancellationToken = default)
    {
        // 1. Invalidate local in-process key rings immediately.
        await _localNotifier.NotifyRevokedAsync(keyId, version, purpose, cancellationToken).ConfigureAwait(false);

        // 2. Broadcast revocation notice to external distributed broker.
        await _publishHandler(keyId, version, purpose, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Ingests a remote key revocation event received from an external message bus or cluster subscriber.
    /// Evicts the specified key from local in-process key rings without republishing to the distributed bus.
    /// </summary>
    /// <param name="keyId">The identifier of the revoked key.</param>
    /// <param name="version">The version of the revoked key.</param>
    /// <param name="purpose">The cryptographic purpose of the revoked key.</param>
    /// <param name="cancellationToken">A token to monitor for cancellation requests.</param>
    /// <returns>A <see cref="ValueTask"/> representing the asynchronous operation.</returns>
    public ValueTask ReceiveRemoteRevocationAsync(
        KeyIdentifier keyId,
        KeyVersion version,
        KeyPurpose purpose,
        CancellationToken cancellationToken = default)
    {
        return _localNotifier.NotifyRevokedAsync(keyId, version, purpose, cancellationToken);
    }

    /// <inheritdoc />
    public IDisposable Subscribe(Action<KeyIdentifier, KeyVersion, KeyPurpose> handler)
    {
        return _localNotifier.Subscribe(handler);
    }
}
