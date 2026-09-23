// Copyright © Erickson Lopez. MIT License.
using System;
using System.Collections.Concurrent;
using System.Threading;
using System.Threading.Tasks;

namespace EricksonLopez.Security.Mfa;

/// <summary>
/// Provides a default in-memory, thread-safe implementation of <see cref="ITotpReplayStore"/> with capacity limits and rate-limited expiration pruning.
/// </summary>
public sealed class InMemoryTotpReplayStore : ITotpReplayStore
{
    private readonly ConcurrentDictionary<string, DateTimeOffset> _consumedCodes = new(StringComparer.Ordinal);
    private long _lastPruneTicks;

    /// <summary>
    /// Defines the default maximum capacity of consumed codes retained in memory.
    /// </summary>
    public const int MaxCapacity = 50_000;

    private readonly int _maxCapacity;
    private readonly int _pruneThreshold;

    internal ConcurrentDictionary<string, DateTimeOffset> ConsumedCodes => _consumedCodes;
    internal int ConsumedCodesCount => _consumedCodes.Count;

    /// <summary>
    /// Initializes a new instance of the <see cref="InMemoryTotpReplayStore"/> class.
    /// </summary>
    /// <param name="maxCapacity">Maximum capacity of consumed codes retained in memory.</param>
    /// <param name="pruneThreshold">Threshold count beyond which routine expiration pruning runs.</param>
    public InMemoryTotpReplayStore(int maxCapacity = MaxCapacity, int pruneThreshold = 1000)
    {
        if (maxCapacity <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(maxCapacity), "Maximum capacity must be greater than zero.");
        }

        if (pruneThreshold <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(pruneThreshold), "Prune threshold must be greater than zero.");
        }

        _maxCapacity = maxCapacity;
        _pruneThreshold = pruneThreshold;
    }

    /// <inheritdoc />
    public bool TryAdd(string key, DateTimeOffset expiresAt)
    {
        var now = DateTimeOffset.UtcNow;
        if (_consumedCodes.Count >= _maxCapacity)
        {
            PruneExpiredCodes(now);
            if (_consumedCodes.Count >= _maxCapacity)
            {
                // Saturated cache cannot safely track replay without evicting active tokens.
                // Fail-closed to prevent replay attacks during DoS/memory flooding.
                return false;
            }
        }

        if (!_consumedCodes.TryAdd(key, expiresAt))
        {
            return false;
        }

        if (_consumedCodes.Count > _pruneThreshold)
        {
            PruneExpiredCodes(now);
        }

        return true;
    }

    /// <inheritdoc />
    public ValueTask<bool> TryAddAsync(string key, DateTimeOffset expiresAt, CancellationToken cancellationToken = default)
    {
        if (cancellationToken.IsCancellationRequested)
        {
            return ValueTask.FromCanceled<bool>(cancellationToken);
        }

        return ValueTask.FromResult(TryAdd(key, expiresAt));
    }

    internal void PruneExpiredCodes(DateTimeOffset now)
    {
        long nowTicks = now.UtcTicks;
        long lastTicks = Volatile.Read(ref _lastPruneTicks);

        if (nowTicks - lastTicks < TimeSpan.FromSeconds(1).Ticks && _consumedCodes.Count < _maxCapacity)
        {
            return;
        }

        // Stryker disable once Block,Statement : Concurrency race optimization where losing thread exits early
        if (Interlocked.CompareExchange(ref _lastPruneTicks, nowTicks, lastTicks) != lastTicks)
        {
            return;
        }

        foreach (var kvp in _consumedCodes)
        {
            if (kvp.Value < now)
            {
                _consumedCodes.TryRemove(kvp.Key, out _);
            }
        }
    }
}
