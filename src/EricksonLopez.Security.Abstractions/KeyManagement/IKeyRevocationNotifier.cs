// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Abstractions.KeyManagement;

using System;
using System.Threading;
using System.Threading.Tasks;
using EricksonLopez.Security.Abstractions.Primitives;

/// <summary>
/// Defines a contract for dispatching and receiving real-time key revocation signals
/// across in-process key rings and distributed cluster nodes.
/// </summary>
public interface IKeyRevocationNotifier
{
    /// <summary>
    /// Broadcasts a key revocation notification to all registered listeners.
    /// </summary>
    /// <param name="keyId">The identifier of the revoked key.</param>
    /// <param name="version">The version of the revoked key.</param>
    /// <param name="purpose">The purpose of the revoked key.</param>
    /// <param name="cancellationToken">A token to observe while waiting for the task to complete.</param>
    /// <returns>A <see cref="ValueTask"/> representing the asynchronous broadcast operation.</returns>
    ValueTask NotifyRevokedAsync(KeyIdentifier keyId, KeyVersion version, KeyPurpose purpose, CancellationToken cancellationToken = default);

    /// <summary>
    /// Registers a revocation listener callback invoked when a key revocation signal is received.
    /// </summary>
    /// <param name="handler">The delegate invoked upon key revocation.</param>
    /// <returns>An <see cref="IDisposable"/> token that unregisters the callback upon disposal.</returns>
    IDisposable Subscribe(Action<KeyIdentifier, KeyVersion, KeyPurpose> handler);
}
