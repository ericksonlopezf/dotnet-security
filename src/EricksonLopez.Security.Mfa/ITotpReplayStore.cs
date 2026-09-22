// Copyright © Erickson Lopez. MIT License.
using System;
using System.Threading;
using System.Threading.Tasks;

namespace EricksonLopez.Security.Mfa;

/// <summary>
/// Defines the contract for recording and verifying consumed TOTP tokens to prevent replay attacks across single-node or distributed environments.
/// </summary>
public interface ITotpReplayStore
{
    /// <summary>
    /// Attempts to record a consumed TOTP token replay key with an expiration timestamp.
    /// </summary>
    /// <param name="key">The unique replay key (e.g. hash of secret and time-step index).</param>
    /// <param name="expiresAt">The timestamp at which this replay record expires.</param>
    /// <returns><see langword="true"/> if the key was successfully added (not previously consumed); <see langword="false"/> if already consumed.</returns>
    bool TryAdd(string key, DateTimeOffset expiresAt);

    /// <summary>
    /// Asynchronously attempts to record a consumed TOTP token replay key with an expiration timestamp.
    /// </summary>
    /// <param name="key">The unique replay key (e.g. hash of secret and time-step index).</param>
    /// <param name="expiresAt">The timestamp at which this replay record expires.</param>
    /// <param name="cancellationToken">A token to monitor for cancellation requests.</param>
    /// <returns><see langword="true"/> if the key was successfully added (not previously consumed); <see langword="false"/> if already consumed.</returns>
    ValueTask<bool> TryAddAsync(string key, DateTimeOffset expiresAt, CancellationToken cancellationToken = default);
}
