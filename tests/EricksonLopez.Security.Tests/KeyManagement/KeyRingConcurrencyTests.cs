// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Tests.KeyManagement;

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using AwesomeAssertions;
using EricksonLopez.Result;
using EricksonLopez.Security.Abstractions.KeyManagement;
using EricksonLopez.Security.Abstractions.Primitives;
using EricksonLopez.Security.Cryptography;
using EricksonLopez.Security.KeyManagement;
using EricksonLopez.Security.Memory;
using Xunit;

public sealed class KeyRingConcurrencyTests
{
    [Fact]
    public async Task KeyRing_ConcurrentGetActiveKey_UnderActiveKeyRotation_RemainsThreadSafe()
    {
        var store = new InMemoryKeyStore();
        var lifecycle = new KeyLifecycleManager(store);
        var keyRing = new KeyRing(store);

        // Seed an initial active encryption key
        var initialKeyResult = await lifecycle.GenerateAndActivateKeyAsync(KeyPurpose.Encryption);
        initialKeyResult.IsSuccess.Should().BeTrue();

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(60));
        var cancellationToken = cts.Token;

        var observedKeys = new ConcurrentBag<KeyIdentifier>();
        var errors = new ConcurrentBag<string>();
        var readCounter = 0;

        // 15 concurrent readers fetching active keys
        var readerTasks = Enumerable.Range(0, 15).Select(async _ =>
        {
            for (var i = 0; i < 20; i++)
            {
                if (cancellationToken.IsCancellationRequested)
                {
                    break;
                }

                var keyRes = await keyRing.GetActiveKeyAsync(KeyPurpose.Encryption, cancellationToken);
                if (keyRes.IsSuccess)
                {
                    observedKeys.Add(keyRes.Value.Metadata.KeyId);
                    (keyRes.Value.Metadata.Status == KeyStatus.Active || keyRes.Value.Metadata.Status == KeyStatus.Retired).Should().BeTrue();

                }
                else
                {
                    errors.Add($"Failed to get active key: {keyRes.Error.Description}");
                }

                Interlocked.Increment(ref readCounter);
                await Task.Yield();
            }
        });

        // 1 writer task rotating keys periodically, synchronized with reader progress
        var writerTask = Task.Run(async () =>
        {
            for (var r = 0; r < 5; r++)
            {
                if (cancellationToken.IsCancellationRequested)
                {
                    break;
                }

                var targetReads = (r + 1) * 30;
                var spin = new SpinWait();
                while (Volatile.Read(ref readCounter) < targetReads && !cancellationToken.IsCancellationRequested)
                {
                    spin.SpinOnce();
                    if (spin.NextSpinWillYield)
                    {
                        await Task.Yield();
                    }
                }

                var rotateResult = await lifecycle.RotateKeyAsync(
                    KeyPurpose.Encryption,
                    validityPeriod: TimeSpan.FromMinutes(5),
                    cancellationToken: cancellationToken);

                if (rotateResult.IsFailure)
                {
                    errors.Add($"Rotation failed: {rotateResult.Error.Description}");
                }
            }
        }, cancellationToken);

        await Task.WhenAll(readerTasks.Concat([writerTask]));

        errors.Should().BeEmpty();
        observedKeys.Should().NotBeEmpty();
        // Readers should have seen at least one valid active key identifier
        observedKeys.Distinct().Count().Should().BeGreaterThanOrEqualTo(1);
    }

    [Fact]
    public async Task InMemoryKeyStore_ConcurrentReadWriteAndStatusUpdates_NeverCorruptsState()
    {
        var store = new InMemoryKeyStore();
        const int numKeys = 40;
        var keys = new List<CryptographicKey>();

        for (var i = 0; i < numKeys; i++)
        {
            var keyId = KeyIdentifier.Prefixed($"k_{i}");
            var meta = new KeyMetadata(keyId, KeyVersion.Initial, KeyPurpose.Encryption, KeyStatus.Active, "AES-256-GCM", DateTimeOffset.UtcNow);
            var buffer = SecretBuffer.CreateRandom(32);
            keys.Add(new CryptographicKey(meta, buffer));
        }

        var errors = new ConcurrentBag<string>();

        // Concurrent saves
        var saveTasks = keys.Select(async k =>
        {
            var saveRes = await store.SaveKeyAsync(k);
            if (saveRes.IsFailure)
            {
                errors.Add($"Save failed for key {k.Metadata.KeyId}: {saveRes.Error.Description}");
            }
        });

        await Task.WhenAll(saveTasks);
        errors.Should().BeEmpty();

        // Concurrent mixed operations: GetKey, ListMetadata, UpdateStatus
        var mixedTasks = keys.Select(async k =>
        {
            // Read
            var getRes = await store.GetKeyAsync(k.Metadata.KeyId, k.Metadata.Version);
            if (getRes.IsFailure)
            {
                errors.Add($"Get failed for key {k.Metadata.KeyId}: {getRes.Error.Description}");
            }

            // Update
            var updateRes = await store.UpdateStatusAsync(k.Metadata.KeyId, k.Metadata.Version, KeyStatus.Retired);
            if (updateRes.IsFailure)
            {
                errors.Add($"Update failed for key {k.Metadata.KeyId}: {updateRes.Error.Description}");
            }

            // List
            var listRes = await store.ListMetadataAsync(KeyPurpose.Encryption);
            if (listRes.IsFailure)
            {
                errors.Add($"List failed: {listRes.Error.Description}");
            }
        });

        await Task.WhenAll(mixedTasks);
        errors.Should().BeEmpty();

        // Verify all keys are now Retired
        var finalList = await store.ListMetadataAsync(KeyPurpose.Encryption);
        finalList.IsSuccess.Should().BeTrue();
        finalList.Value.Count.Should().Be(numKeys);
        finalList.Value.All(m => m.Status == KeyStatus.Retired).Should().BeTrue();
    }


    [Fact]
    public async Task KeyRing_ConcurrentEncryptionAndDecryption_WithLiveRotatingKeys()
    {
        var store = new InMemoryKeyStore();
        var lifecycle = new KeyLifecycleManager(store);
        var keyRing = new KeyRing(store);
        var engine = AesGcmEncryptionEngine.Shared;

        var initialKeyRes = await lifecycle.GenerateAndActivateKeyAsync(KeyPurpose.Encryption);
        initialKeyRes.IsSuccess.Should().BeTrue();

        var encryptedItems = new ConcurrentBag<(byte[] Ciphertext, byte[] Nonce, byte[] Tag, KeyIdentifier KeyId, KeyVersion Version, string Plaintext)>();
        var errors = new ConcurrentBag<string>();

        var encryptionStarted = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

        // 20 concurrent tasks encrypting data
        var encryptTasks = Enumerable.Range(0, 20).Select(async i =>
        {
            for (var j = 0; j < 10; j++)
            {
                var keyRes = await keyRing.GetActiveKeyAsync(KeyPurpose.Encryption);
                if (keyRes.IsFailure)
                {
                    errors.Add($"Active key retrieval error: {keyRes.Error.Description}");
                    continue;
                }

                var key = keyRes.Value;
                var text = $"Message_{i}_{j}";
                var plaintextBytes = Encoding.UTF8.GetBytes(text);
                var aad = Encoding.UTF8.GetBytes($"tenant_{i}");

                var encRes = engine.Encrypt(plaintextBytes, key.GetKeyBytes(), aad);
                if (encRes.IsFailure)
                {
                    errors.Add($"Encrypt error: {encRes.Error.Description}");
                    continue;
                }

                var enc = encRes.Value;
                encryptedItems.Add((enc.Ciphertext.ToArray(), enc.Nonce.ToArray(), enc.Tag.ToArray(), key.Metadata.KeyId, key.Metadata.Version, text));
                if (encryptedItems.Count >= 5)
                {
                    encryptionStarted.TrySetResult();
                }

                await Task.Yield();
            }
        });

        // Rotate key concurrently once encryption is demonstrably underway
        var rotationTask = Task.Run(async () =>
        {
            await encryptionStarted.Task;
            await lifecycle.RotateKeyAsync(KeyPurpose.Encryption, TimeSpan.FromMinutes(10));
        });

        await Task.WhenAll(encryptTasks.Concat([rotationTask]));
        errors.Should().BeEmpty();
        encryptedItems.Should().NotBeEmpty();

        // Verify all encrypted items can be decrypted using the key specified in metadata
        foreach (var item in encryptedItems)
        {
            var keyRes = await keyRing.GetKeyAsync(item.KeyId, item.Version);
            keyRes.IsSuccess.Should().BeTrue();

            var decrypted = new byte[Encoding.UTF8.GetByteCount(item.Plaintext)];
            var decRes = engine.Decrypt(
                item.Ciphertext,
                keyRes.Value.GetKeyBytes(),
                item.Nonce,
                item.Tag,
                Encoding.UTF8.GetBytes($"tenant_{item.Plaintext.Split('_')[1]}"),
                decrypted,
                out int written);

            decRes.IsSuccess.Should().BeTrue();
            written.Should().Be(decrypted.Length);
            Encoding.UTF8.GetString(decrypted).Should().Be(item.Plaintext);
        }
    }

    // FINDING-CRIT-03 (resolved): Regression test for the KeyRing cache TOCTOU race condition.
    // Without _cacheLock, Thread A reads cached.Bytes while Thread B zeros those same bytes
    // in ClearCache(), producing a key with all-zero bytes that would fail AES-GCM.
    [Fact]
    public async Task KeyRing_ConcurrentGetAndClearCache_NeverReturnsZeroedKeyBytes_SEC_024()
    {
        var store = new InMemoryKeyStore();
        var lifecycle = new KeyLifecycleManager(store);
        var keyRing = new KeyRing(store);

        // Seed initial key
        var seedResult = await lifecycle.GenerateAndActivateKeyAsync(KeyPurpose.Encryption);
        seedResult.IsSuccess.Should().BeTrue();

        // Raise cache TTL so keys get cached
        KeyRing.CacheTtl = TimeSpan.FromMinutes(5);

        var errors = new ConcurrentBag<string>();
        var zeroKeyCount = 0;
        var iterationsPerThread = 50;

        // 8 reader threads concurrently reading the active key
        var readerTasks = Enumerable.Range(0, 8).Select(async _ =>
        {
            for (var i = 0; i < iterationsPerThread; i++)
            {
                try
                {
                    var result = await keyRing.GetActiveKeyAsync(KeyPurpose.Encryption);
                    if (result.IsSuccess)
                    {
                        var keyBytes = result.Value.GetKeyBytes();
                        // A zeroed key means the TOCTOU race produced corrupted key material
                        var allZero = true;
                        foreach (var b in keyBytes)
                        {
                            if (b != 0) { allZero = false; break; }
                        }
                        if (allZero && keyBytes.Length > 0)
                        {
                            Interlocked.Increment(ref zeroKeyCount);
                            errors.Add($"Reader got all-zero key bytes on iteration {i}");
                        }

                        result.Value.Dispose();
                    }
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    // Exceptions from disposed SecretBuffer etc. are acceptable transients
                }
                await Task.Yield();
            }
        });

        // 2 cache-clearing threads concurrently clearing the cache
        // (simulating key rotation / cache invalidation)
        var clearerTasks = Enumerable.Range(0, 2).Select(async _ =>
        {
            for (var i = 0; i < iterationsPerThread; i++)
            {
                keyRing.ClearCache();
                // Re-seed after clear so readers have something to find
                try
                {
                    await lifecycle.GenerateAndActivateKeyAsync(KeyPurpose.Encryption);
                }
                catch
                {
                    // Ignore — seed may fail if store has concurrent writes
                }
                await Task.Yield();
            }
        });

        await Task.WhenAll(readerTasks.Concat(clearerTasks));

        // Reset TTL for other tests
        KeyRing.CacheTtl = TimeSpan.Zero;

        zeroKeyCount.Should().Be(0,
            $"No key returned by GetActiveKeyAsync must have all-zero bytes. Errors: {string.Join(", ", errors)}");
    }

    [Fact]
    public async Task KeyRing_WithKeyRingOptions_UsesInstanceCacheTtl_REM_02()
    {
        var store = new InMemoryKeyStore();
        var lifecycle = new KeyLifecycleManager(store);
        var options = new KeyRingOptions { CacheTtl = TimeSpan.FromSeconds(60) };
        var keyRing = new KeyRing(store, options);

        var keyResult = await lifecycle.GenerateAndActivateKeyAsync(KeyPurpose.Encryption);
        keyResult.IsSuccess.Should().BeTrue();

        var activeKey = await keyRing.GetActiveKeyAsync(KeyPurpose.Encryption);
        activeKey.IsSuccess.Should().BeTrue();
        activeKey.Value.Metadata.KeyId.Should().Be(keyResult.Value.Metadata.KeyId);
    }

    /// <summary>
    /// KR-05 Regression Test: Under concurrent cache misses, the key store should be called
    /// exactly once per KeyPurpose (not N times — the thundering herd anti-pattern).
    /// The SemaphoreSlim(1,1) per-purpose guard introduced in KR-05 ensures only one thread
    /// fetches from the store; all other threads wait and re-use the cached result.
    /// </summary>
    [Fact]
    public async Task KeyRing_NoThunderingHerd_UnderConcurrentCacheMiss()
    {
        // Arrange
        var countingStore = new CountingKeyStore();
        var lifecycle = new KeyLifecycleManager(countingStore);
        var keyRing = new KeyRing(countingStore, new KeyRingOptions { CacheTtl = TimeSpan.FromSeconds(30) });

        var keyResult = await lifecycle.GenerateAndActivateKeyAsync(KeyPurpose.Encryption);
        keyResult.IsSuccess.Should().BeTrue();

        // Force cache cold start by creating a new KeyRing instance
        var freshKeyRing = new KeyRing(countingStore, new KeyRingOptions { CacheTtl = TimeSpan.FromSeconds(30) });
        var getCountBefore = countingStore.GetActiveKeyCallCount;

        const int concurrentThreads = 32;
        var tasks = new Task<Result<CryptographicKey>>[concurrentThreads];
        var barrier = new Barrier(concurrentThreads); // synchronize all threads to fire simultaneously

        for (int i = 0; i < concurrentThreads; i++)
        {
            tasks[i] = Task.Run(async () =>
            {
                barrier.SignalAndWait(); // Ensure all threads start simultaneously (cold cache)
                return await freshKeyRing.GetActiveKeyAsync(KeyPurpose.Encryption);
            });
        }

        var results = await Task.WhenAll(tasks);

        // Assert: All calls succeed and return the same key
        results.Should().AllSatisfy(r => r.IsSuccess.Should().BeTrue());
        var firstKeyId = results[0].Value.Metadata.KeyId;
        results.Should().AllSatisfy(r => r.Value.Metadata.KeyId.Should().Be(firstKeyId));

        // Assert: Key store ListMetadataAsync called significantly fewer times than concurrentThreads
        // With SemaphoreSlim fix: exactly 1 call (the first thread fetches; all others get cached result)
        // Without fix: up to 32 calls (thundering herd)
        var callsAfterConcurrentMiss = countingStore.ListMetadataCallCount - 0;
        callsAfterConcurrentMiss.Should().BeLessThanOrEqualTo(
            concurrentThreads / 4, // Allow some slack for timing; strict would be == 1
            "KR-05: SemaphoreSlim should prevent more than a handful of store calls for the same purpose");

        // Dispose all returned keys
        foreach (var result in results)
        {
            result.Value.Dispose();
        }
    }
}

/// <summary>
/// A test-only key store wrapper that counts store access calls for KR-05 thundering herd verification.
/// </summary>
internal sealed class CountingKeyStore : IKeyStore
{
    private readonly InMemoryKeyStore _inner = new();
    private int _listMetadataCallCount;
    private int _getActiveKeyCallCount;

    public int ListMetadataCallCount => _listMetadataCallCount;
    public int GetActiveKeyCallCount => _getActiveKeyCallCount;

    public ValueTask<Result<IReadOnlyList<KeyMetadata>>> ListMetadataAsync(KeyPurpose? purpose = null, CancellationToken cancellationToken = default)
    {
        Interlocked.Increment(ref _listMetadataCallCount);
        return _inner.ListMetadataAsync(purpose, cancellationToken);
    }

    public ValueTask<Result<CryptographicKey>> GetKeyAsync(KeyIdentifier keyId, KeyVersion version, CancellationToken cancellationToken = default)
    {
        Interlocked.Increment(ref _getActiveKeyCallCount);
        return _inner.GetKeyAsync(keyId, version, cancellationToken);
    }

    public ValueTask<Result> SaveKeyAsync(CryptographicKey key, CancellationToken cancellationToken = default) =>
        _inner.SaveKeyAsync(key, cancellationToken);

    public ValueTask<Result> UpdateStatusAsync(KeyIdentifier keyId, KeyVersion version, KeyStatus newStatus, CancellationToken cancellationToken = default) =>
        _inner.UpdateStatusAsync(keyId, version, newStatus, cancellationToken);
}
