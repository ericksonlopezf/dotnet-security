// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.KeyManagement;

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using EricksonLopez.Result;
using EricksonLopez.Security.Abstractions.Errors;
using EricksonLopez.Security.Abstractions.KeyManagement;
using EricksonLopez.Security.Abstractions.Primitives;
using EricksonLopez.Security.Memory;

/// <summary>
/// Provides a thread-safe in-memory key store implementation of <see cref="IKeyStore"/> suitable for
/// testing, development, and containerized microservice deployments.
/// </summary>
public sealed class InMemoryKeyStore : IKeyStore
{
    /// <summary>
    /// Maximum number of keys that can be stored in a single <see cref="InMemoryKeyStore"/> instance.
    /// Prevents unbounded memory growth if used as a long-lived store. See DOS-002, CON-003.
    /// </summary>
    public const int MaxKeys = 10_000;

    private readonly ConcurrentDictionary<string, (KeyMetadata Metadata, byte[] KeyBytes)> _storage = new(StringComparer.Ordinal);

    /// <summary>
    /// Initializes a new instance of the <see cref="InMemoryKeyStore"/> class.
    /// Throws if the environment is set to Production to prevent data loss.
    /// </summary>
    /// <exception cref="NotSupportedException">The execution environment is set to Production</exception>
    public InMemoryKeyStore()
    {
        var aspnetEnv = Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT");
        var dotnetEnv = Environment.GetEnvironmentVariable("DOTNET_ENVIRONMENT");
        if (IsProductionEnvironment(aspnetEnv) || IsProductionEnvironment(dotnetEnv))
        {
            throw new NotSupportedException("Cloud KeyStore Integration is pending v2.0. InMemoryKeyStore stub cannot be used in production to avoid data loss.");
        }
    }

    private static bool IsProductionEnvironment(string? env)
    {
        return string.Equals(env, "Production", StringComparison.OrdinalIgnoreCase) ||
               string.Equals(env, "Prod", StringComparison.OrdinalIgnoreCase) ||
               string.Equals(env, "Live", StringComparison.OrdinalIgnoreCase);
    }

    private static string GetKeyIndex(KeyIdentifier keyId, KeyVersion version) => $"{keyId.Value}:{version.Value}";

    /// <inheritdoc />
    public ValueTask<Result> SaveKeyAsync(CryptographicKey key, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(key);

        var index = GetKeyIndex(key.Metadata.KeyId, key.Metadata.Version);

        // DOS-002 / CON-003: Reject if adding a new key would exceed capacity.
        if (!_storage.ContainsKey(index) && _storage.Count >= MaxKeys)
        {
            return ValueTask.FromResult(Result.Failure(SecurityError.StoreCapacityExceeded(
                $"InMemoryKeyStore capacity exceeded ({MaxKeys} keys). " +
                "This store is intended for testing and development only. " +
                "For production use, configure a persistent cloud key store.")));
        }

        var keyBytes = key.GetKeyBytes().ToArray();

        _storage[index] = (key.Metadata, keyBytes);
        return ValueTask.FromResult(Result.Success());
    }

    /// <inheritdoc />
    public ValueTask<Result<CryptographicKey>> GetKeyAsync(KeyIdentifier keyId, KeyVersion version, CancellationToken cancellationToken = default)
    {
        var index = GetKeyIndex(keyId, version);
        if (!_storage.TryGetValue(index, out var entry))
        {
            return ValueTask.FromResult<Result<CryptographicKey>>(SecurityError.KeyNotFound($"{keyId}:{version}"));
        }

        var secretBuffer = SecretBuffer.FromSpan(entry.KeyBytes);
        var cryptographicKey = new CryptographicKey(entry.Metadata, secretBuffer);
        return ValueTask.FromResult<Result<CryptographicKey>>(cryptographicKey);
    }

    /// <inheritdoc />
    public ValueTask<Result<IReadOnlyList<KeyMetadata>>> ListMetadataAsync(KeyPurpose? purpose = null, CancellationToken cancellationToken = default)
    {
        var query = _storage.Values.Select(v => v.Metadata);
        if (purpose.HasValue)
        {
            query = query.Where(m => m.Purpose == purpose.Value);
        }

        IReadOnlyList<KeyMetadata> results = query.OrderByDescending(m => m.Version.Value).ToList();
        return ValueTask.FromResult<Result<IReadOnlyList<KeyMetadata>>>(Result<IReadOnlyList<KeyMetadata>>.Success(results));
    }

    /// <inheritdoc />
    public ValueTask<Result> UpdateStatusAsync(KeyIdentifier keyId, KeyVersion version, KeyStatus newStatus, CancellationToken cancellationToken = default)
    {
        var index = GetKeyIndex(keyId, version);

        // CONC-002/KM-005 fix: use a CAS loop with TryUpdate to prevent lost-update race conditions.
        // Two concurrent callers reading the same entry could overwrite each other's writes.
        // TryUpdate atomically replaces the value only if it still matches the expected current value.
        const int maxRetries = 10;
        for (var attempt = 0; attempt < maxRetries; attempt++)
        {
            if (!_storage.TryGetValue(index, out var current))
            {
                return ValueTask.FromResult<Result>(SecurityError.KeyNotFound($"{keyId}:{version}"));
            }

            var updatedMetadata = current.Metadata with
            {
                Status = newStatus,
                RevokedAtUtc = newStatus == KeyStatus.Revoked ? DateTimeOffset.UtcNow : current.Metadata.RevokedAtUtc
            };

            // KM-003 fix: zero key bytes when transitioning to Revoked or Destroyed.
            // This minimizes the window during which key material resides in memory after a key
            // is no longer authorized for use. The entry is replaced with a zeroed byte array
            // to preserve the store structure while clearing the sensitive material.
            byte[] finalKeyBytes = current.KeyBytes;
            if (newStatus == KeyStatus.Revoked || newStatus == KeyStatus.Destroyed)
            {
                finalKeyBytes = new byte[current.KeyBytes.Length]; // zeroed by runtime
                CryptographicOperations.ZeroMemory(current.KeyBytes); // zero the original
            }

            var newEntry = (updatedMetadata, finalKeyBytes);

            // Atomically replace only if the current value hasn't changed since we read it.
            if (_storage.TryUpdate(index, newEntry, current))
            {
                return ValueTask.FromResult(Result.Success());
            }

            // Another thread updated the same key concurrently. Retry.
        }

        // Extremely unlikely: failed all retries under heavy contention.
        return ValueTask.FromResult<Result>(
            Error.Failure("InMemoryKeyStore.UpdateStatusFailed",
                $"Failed to update status for key '{keyId}:{version}' after {maxRetries} attempts due to concurrent modification."));
    }
}
