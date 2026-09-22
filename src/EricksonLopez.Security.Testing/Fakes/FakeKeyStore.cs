// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Testing.Fakes;

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using EricksonLopez.Result;
using EricksonLopez.Security.Abstractions.Errors;
using EricksonLopez.Security.Abstractions.KeyManagement;
using EricksonLopez.Security.Abstractions.Primitives;
using EricksonLopez.Security.Abstractions.Secrets;
using EricksonLopez.Security.Memory;

/// <summary>
/// Provides an in-memory test double implementation of <see cref="IKeyStore"/> with inspectable state and simulated failure injection.
/// </summary>
public sealed class FakeKeyStore : IKeyStore
{
    private readonly ConcurrentDictionary<string, (KeyMetadata Metadata, byte[] KeyBytes)> _keys = new(StringComparer.Ordinal);

    /// <summary>
    /// Gets or sets an optional simulated error to return on all operations.
    /// </summary>
    public Error? InjectedError { get; set; }

    /// <summary>
    /// Gets the number of keys currently stored.
    /// </summary>
    public int Count => _keys.Count;

    private static string GetIndex(KeyIdentifier keyId, KeyVersion version) => $"{keyId.Value}:{version.Value}";

    /// <inheritdoc />
    public ValueTask<Result> SaveKeyAsync(CryptographicKey key, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(key);

        if (InjectedError is not null)
        {
            return ValueTask.FromResult<Result>(InjectedError);
        }

        var index = GetIndex(key.Metadata.KeyId, key.Metadata.Version);
        _keys[index] = (key.Metadata, key.GetKeyBytes().ToArray());
        return ValueTask.FromResult(Result.Success());
    }

    /// <inheritdoc />
    public ValueTask<Result<CryptographicKey>> GetKeyAsync(KeyIdentifier keyId, KeyVersion version, CancellationToken cancellationToken = default)
    {
        if (InjectedError is not null)
        {
            return ValueTask.FromResult<Result<CryptographicKey>>(InjectedError);
        }

        var index = GetIndex(keyId, version);
        if (!_keys.TryGetValue(index, out var entry))
        {
            return ValueTask.FromResult<Result<CryptographicKey>>(SecurityError.KeyNotFound($"{keyId}:{version}"));
        }

        var buffer = SecretBuffer.FromSpan(entry.KeyBytes);
        return ValueTask.FromResult<Result<CryptographicKey>>(new CryptographicKey(entry.Metadata, buffer));
    }

    /// <inheritdoc />
    public ValueTask<Result<IReadOnlyList<KeyMetadata>>> ListMetadataAsync(KeyPurpose? purpose = null, CancellationToken cancellationToken = default)
    {
        if (InjectedError is not null)
        {
            return ValueTask.FromResult<Result<IReadOnlyList<KeyMetadata>>>(InjectedError);
        }

        var query = _keys.Values.Select(v => v.Metadata);
        if (purpose.HasValue)
        {
            query = query.Where(m => m.Purpose == purpose.Value);
        }

        IReadOnlyList<KeyMetadata> list = query.OrderByDescending(m => m.Version.Value).ToList();
        return ValueTask.FromResult<Result<IReadOnlyList<KeyMetadata>>>(Result<IReadOnlyList<KeyMetadata>>.Success(list));
    }

    /// <inheritdoc />
    public ValueTask<Result> UpdateStatusAsync(KeyIdentifier keyId, KeyVersion version, KeyStatus newStatus, CancellationToken cancellationToken = default)
    {
        if (InjectedError is not null)
        {
            return ValueTask.FromResult<Result>(InjectedError);
        }

        var index = GetIndex(keyId, version);
        if (!_keys.TryGetValue(index, out var entry))
        {
            return ValueTask.FromResult<Result>(SecurityError.KeyNotFound($"{keyId}:{version}"));
        }

        var updated = entry.Metadata with
        {
            Status = newStatus,
            RevokedAtUtc = newStatus == KeyStatus.Revoked ? DateTimeOffset.UtcNow : entry.Metadata.RevokedAtUtc
        };

        _keys[index] = (updated, entry.KeyBytes);
        return ValueTask.FromResult(Result.Success());
    }

    /// <summary>
    /// Resets all stored keys and clears injected errors.
    /// </summary>
    public void Reset()
    {
        _keys.Clear();
        InjectedError = null;
    }
}
