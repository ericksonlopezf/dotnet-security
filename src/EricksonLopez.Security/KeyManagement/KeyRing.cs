// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.KeyManagement;

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using EricksonLopez.Security.Memory;
using System.Threading;
using System.Threading.Tasks;
using EricksonLopez.Result;
using EricksonLopez.Security.Abstractions.Cryptography;
using EricksonLopez.Security.Abstractions.Errors;
using EricksonLopez.Security.Abstractions.KeyManagement;
using EricksonLopez.Security.Abstractions.Primitives;

/// <summary>
/// Provides a thread-safe implementation of <see cref="IKeyRing"/> and <see cref="IEncryptionKeyProvider"/>.
/// Resolves active and historical cryptographic keys from an underlying <see cref="IKeyStore"/>.
/// </summary>
public sealed class KeyRing : IKeyRing, IEncryptionKeyProvider, IDisposable
{
    private readonly IKeyStore _keyStore;
    private readonly TimeSpan? _instanceCacheTtl;
    private readonly IDisposable? _revocationSubscription;

    /// <summary>
    /// Initializes a new instance of the <see cref="KeyRing"/> class.
    /// </summary>
    /// <param name="keyStore">The underlying persistent or in-memory key store.</param>
    /// <exception cref="ArgumentNullException"><paramref name="keyStore"/> is <see langword="null"/></exception>
    public KeyRing(IKeyStore keyStore) : this(keyStore, null, null)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="KeyRing"/> class with configuration options.
    /// </summary>
    /// <param name="keyStore">The underlying persistent or in-memory key store.</param>
    /// <param name="options">Optional configuration options specifying caching behaviors.</param>
    /// <exception cref="ArgumentNullException"><paramref name="keyStore"/> is <see langword="null"/></exception>
    public KeyRing(IKeyStore keyStore, KeyRingOptions? options) : this(keyStore, options, null)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="KeyRing"/> class with configuration options and revocation notifier.
    /// </summary>
    /// <param name="keyStore">The underlying persistent or in-memory key store.</param>
    /// <param name="options">Optional configuration options specifying caching behaviors.</param>
    /// <param name="revocationNotifier">Optional key revocation notifier for real-time cache invalidation.</param>
    /// <exception cref="ArgumentNullException"><paramref name="keyStore"/> is <see langword="null"/></exception>
    public KeyRing(IKeyStore keyStore, KeyRingOptions? options, IKeyRevocationNotifier? revocationNotifier)
    {
        _keyStore = keyStore ?? throw new ArgumentNullException(nameof(keyStore));
        if (options != null)
        {
            _instanceCacheTtl = options.CacheTtl;
        }

        if (revocationNotifier != null)
        {
            _revocationSubscription = revocationNotifier.Subscribe((keyId, version, purpose) =>
            {
                InvalidateKey(keyId, version);
                InvalidateActiveKey(purpose);
            });
        }
    }

    // Resolves the effective cache TTL, preferring instance-level KeyRingOptions if supplied.
    private TimeSpan EffectiveCacheTtl => _instanceCacheTtl ?? CacheTtl;

    /// <inheritdoc />
    /// <remarks>
    /// <strong>Performance Note (REM-03)</strong>: Resolves active keys from the local in-memory cache
    /// on cache hits with zero async overhead. In asynchronous workflows, always prefer
    /// <see cref="GetActiveKeyAsync(KeyPurpose, CancellationToken)"/> for non-cached resolution.
    /// </remarks>
    public Result<CryptographicKey> GetActiveKey(KeyPurpose purpose)
    {
        if (_activeKeyCache.TryGetValue(purpose, out var cached) && cached.Expires > DateTimeOffset.UtcNow)
        {
            lock (_cacheLock)
            {
                if (cached.Bytes is not null && cached.Expires > DateTimeOffset.UtcNow)
                {
                    return new CryptographicKey(cached.Metadata, SecretBuffer.FromSpan(cached.Bytes));
                }
            }
        }

        return GetActiveKeyAsync(purpose).AsTask().GetAwaiter().GetResult();
    }

    /// <inheritdoc />
    /// <remarks>
    /// <strong>Performance Note (REM-03)</strong>: Resolves versioned keys from the local in-memory cache
    /// on cache hits with zero async overhead. In asynchronous workflows, always prefer
    /// <see cref="GetKeyAsync(KeyIdentifier, KeyVersion, CancellationToken)"/> for non-cached resolution.
    /// </remarks>
    public Result<CryptographicKey> GetKey(KeyIdentifier keyId, KeyVersion version)
    {
        var cacheKey = $"{keyId.Value}:{version.Value}";
        if (_keyCache.TryGetValue(cacheKey, out var cached) && cached.Expires > DateTimeOffset.UtcNow)
        {
            lock (_cacheLock)
            {
                if (cached.Bytes is not null && cached.Expires > DateTimeOffset.UtcNow)
                {
                    return new CryptographicKey(cached.Metadata, SecretBuffer.FromSpan(cached.Bytes));
                }
            }
        }

        return GetKeyAsync(keyId, version).AsTask().GetAwaiter().GetResult();
    }

    private readonly ConcurrentDictionary<KeyPurpose, (KeyMetadata Metadata, byte[] Bytes, DateTimeOffset Expires)> _activeKeyCache = new();
    private readonly ConcurrentDictionary<string, (KeyMetadata Metadata, byte[] Bytes, DateTimeOffset Expires)> _keyCache = new();
    // FINDING-CRIT-03 (resolved): protects the read+copy path from racing with ClearCache ZeroMemory+Clear.
    // Without this lock, Thread A could read cached.Bytes while Thread B zeros those same bytes.
    private readonly object _cacheLock = new();
    // KR-05 (resolved): Per-purpose semaphore prevents thundering herd on concurrent cache misses.
    // Only 1 thread per KeyPurpose fetches from the key store; all others wait and reuse the cached result.
    private readonly ConcurrentDictionary<KeyPurpose, SemaphoreSlim> _purposeSemaphores = new();

    /// <summary>
    /// Gets or sets the global default time-to-live for in-memory cached cryptographic keys.
    /// Defaults to 30 seconds to minimize plaintext exposure in memory dumps.
    /// Set to <see cref="TimeSpan.Zero"/> to disable caching.
    /// Prefer configuring via <see cref="KeyRingOptions"/> in dependency injection containers.
    /// </summary>
    public static TimeSpan CacheTtl { get; set; } = TimeSpan.FromSeconds(30);

    internal void ClearCache()
    {
        lock (_cacheLock)
        {
            foreach (var entry in _activeKeyCache.Values)
            {
                if (entry.Bytes is not null)
                {
                    CryptographicOperations.ZeroMemory(entry.Bytes);
                }
            }
            _activeKeyCache.Clear();

            foreach (var entry in _keyCache.Values)
            {
                if (entry.Bytes is not null)
                {
                    CryptographicOperations.ZeroMemory(entry.Bytes);
                }
            }
            _keyCache.Clear();
        }
    }

    /// <inheritdoc />
    public void InvalidateKey(KeyIdentifier keyId, KeyVersion version)
    {
        var cacheKey = $"{keyId.Value}:{version.Value}";
        lock (_cacheLock)
        {
            if (_keyCache.TryRemove(cacheKey, out var entry) && entry.Bytes is not null)
            {
                CryptographicOperations.ZeroMemory(entry.Bytes);
            }

            foreach (var kvp in _activeKeyCache)
            {
                if (kvp.Value.Metadata.KeyId == keyId && kvp.Value.Metadata.Version == version)
                {
                    if (_activeKeyCache.TryRemove(kvp.Key, out var activeEntry) && activeEntry.Bytes is not null)
                    {
                        CryptographicOperations.ZeroMemory(activeEntry.Bytes);
                    }
                }
            }
        }
    }

    /// <inheritdoc />
    public void InvalidateActiveKey(KeyPurpose purpose)
    {
        lock (_cacheLock)
        {
            if (_activeKeyCache.TryRemove(purpose, out var entry) && entry.Bytes is not null)
            {
                CryptographicOperations.ZeroMemory(entry.Bytes);
            }
        }
    }

    /// <inheritdoc />
    public void InvalidateAll()
    {
        ClearCache();
    }

    /// <inheritdoc />
    public void Dispose()
    {
        _revocationSubscription?.Dispose();
        ClearCache();
        // Dispose all semaphores to release any waiting threads.
        foreach (var semaphore in _purposeSemaphores.Values)
        {
            semaphore.Dispose();
        }
        _purposeSemaphores.Clear();
        GC.SuppressFinalize(this);
    }

    /// <inheritdoc />
    public async ValueTask<Result<CryptographicKey>> GetActiveKeyAsync(KeyPurpose purpose, CancellationToken cancellationToken = default)
    {
        // FINDING-CRIT-03 (resolved): lock protects TryGetValue+SecretBuffer.FromSpan from racing
        // with ClearCache() which zeros the bytes array under the same lock.
        lock (_cacheLock)
        {
            if (_activeKeyCache.TryGetValue(purpose, out var cached) && cached.Expires > DateTimeOffset.UtcNow)
            {
                return new CryptographicKey(cached.Metadata, SecretBuffer.FromSpan(cached.Bytes));
            }
        }

        // KR-05 (resolved): Use a per-purpose SemaphoreSlim to serialize concurrent cache misses.
        // Only 1 thread fetches from the store per purpose; all others wait and find the key in cache.
        var semaphore = _purposeSemaphores.GetOrAdd(purpose, _ => new SemaphoreSlim(1, 1));
        await semaphore.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            // Double-check: another thread may have populated the cache while we were waiting.
            lock (_cacheLock)
            {
                if (_activeKeyCache.TryGetValue(purpose, out var cached) && cached.Expires > DateTimeOffset.UtcNow)
                {
                    return new CryptographicKey(cached.Metadata, SecretBuffer.FromSpan(cached.Bytes));
                }
            }

            return await FetchAndCacheActiveKeyAsync(purpose, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            semaphore.Release();
        }
    }

    private async Task<Result<CryptographicKey>> FetchAndCacheActiveKeyAsync(KeyPurpose purpose, CancellationToken cancellationToken)
    {
        var metadataResult = await _keyStore.ListMetadataAsync(purpose, cancellationToken).ConfigureAwait(false);
        if (metadataResult.IsFailure) return metadataResult.Error;

        KeyMetadata? activeMetadata = null;
        foreach (var m in metadataResult.Value)
        {
            if (m.Purpose == purpose && m.IsUsableForNewOperations())
            {
                if (activeMetadata is null || m.Version.Value > activeMetadata.Version.Value)
                {
                    activeMetadata = m;
                }
            }
        }

        if (activeMetadata is null) return SecurityError.KeyNotFound($"Active key for purpose '{purpose}'");

        var keyResult = await GetKeyAsync(activeMetadata.KeyId, activeMetadata.Version, cancellationToken).ConfigureAwait(false);
        if (keyResult.IsSuccess && EffectiveCacheTtl > TimeSpan.Zero)
        {
            var keyBytes = keyResult.Value.GetKeyBytes().ToArray();
            lock (_cacheLock)
            {
                if (_activeKeyCache.TryGetValue(purpose, out var oldEntry) && oldEntry.Bytes is not null)
                {
                    CryptographicOperations.ZeroMemory(oldEntry.Bytes);
                }
                _activeKeyCache[purpose] = (activeMetadata, keyBytes, DateTimeOffset.UtcNow.Add(EffectiveCacheTtl));
            }
        }
        return keyResult;
    }

    private const int MaxKeyCacheCapacity = 1000;

    private void PruneKeyCache(DateTimeOffset now)
    {
        foreach (var kvp in _keyCache)
        {
            if (kvp.Value.Expires <= now)
            {
                if (_keyCache.TryRemove(kvp.Key, out var removed) && removed.Bytes is not null)
                {
                    CryptographicOperations.ZeroMemory(removed.Bytes);
                }
            }
        }

        if (_keyCache.Count >= MaxKeyCacheCapacity)
        {
            var overflowCount = _keyCache.Count - (int)(MaxKeyCacheCapacity * 0.8);
            if (overflowCount > 0)
            {
                var oldestKeys = _keyCache
                    .OrderBy(x => x.Value.Expires)
                    .Take(overflowCount)
                    .Select(x => x.Key)
                    .ToList();

                foreach (var k in oldestKeys)
                {
                    if (_keyCache.TryRemove(k, out var removed) && removed.Bytes is not null)
                    {
                        CryptographicOperations.ZeroMemory(removed.Bytes);
                    }
                }
            }
        }
    }

    /// <inheritdoc />
    public async ValueTask<Result<CryptographicKey>> GetKeyAsync(KeyIdentifier keyId, KeyVersion version, CancellationToken cancellationToken = default)
    {
        var cacheKey = $"{keyId.Value}:{version.Value}";
        // FINDING-CRIT-03 (resolved): lock protects TryGetValue+SecretBuffer.FromSpan.
        lock (_cacheLock)
        {
            if (_keyCache.TryGetValue(cacheKey, out var cached) && cached.Expires > DateTimeOffset.UtcNow)
            {
                if (cached.Metadata.Status is KeyStatus.Revoked or KeyStatus.Destroyed)
                    return SecurityError.KeyRevoked(keyId.Value, $"The cryptographic key with identifier '{keyId}' is not usable because its status is '{cached.Metadata.Status}'.");
                return new CryptographicKey(cached.Metadata, SecretBuffer.FromSpan(cached.Bytes));
            }
        }

        var storeResult = await _keyStore.GetKeyAsync(keyId, version, cancellationToken).ConfigureAwait(false);
        if (storeResult.IsFailure) return storeResult.Error;

        var key = storeResult.Value;
        if (key.Metadata.Status is KeyStatus.Revoked or KeyStatus.Destroyed)
        {
            key.Dispose();
            return SecurityError.KeyRevoked(keyId.Value, $"The cryptographic key with identifier '{keyId}' is not usable because its status is '{key.Metadata.Status}'.");
        }

        if (_keyCache.Count >= MaxKeyCacheCapacity)
        {
            PruneKeyCache(DateTimeOffset.UtcNow);
        }

        if (EffectiveCacheTtl > TimeSpan.Zero)
        {
            var keyBytes = key.GetKeyBytes().ToArray();
            lock (_cacheLock)
            {
                if (_keyCache.TryGetValue(cacheKey, out var oldEntry) && oldEntry.Bytes is not null)
                {
                    CryptographicOperations.ZeroMemory(oldEntry.Bytes);
                }
                _keyCache[cacheKey] = (key.Metadata, keyBytes, DateTimeOffset.UtcNow.Add(EffectiveCacheTtl));
            }
        }
        return key;
    }

    /// <inheritdoc />
    public ValueTask<Result<IReadOnlyList<KeyMetadata>>> ListMetadataAsync(KeyPurpose? purpose = null, CancellationToken cancellationToken = default) =>
        _keyStore.ListMetadataAsync(purpose, cancellationToken);

    /// <inheritdoc />
    public ValueTask<Result<CryptographicKey>> GetActiveEncryptionKeyAsync(KeyPurpose purpose = KeyPurpose.Encryption, CancellationToken cancellationToken = default) =>
        GetActiveKeyAsync(purpose, cancellationToken);

    /// <inheritdoc />
    public ValueTask<Result<CryptographicKey>> GetDecryptionKeyAsync(KeyIdentifier keyId, KeyVersion version, CancellationToken cancellationToken = default) =>
        GetKeyAsync(keyId, version, cancellationToken);
}
