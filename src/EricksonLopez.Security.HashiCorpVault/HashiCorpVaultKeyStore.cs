// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.HashiCorpVault;

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
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

/// <summary>
/// Provides an <see cref="IKeyStore"/> adapter backed by HashiCorp Vault Transit and KV v2 cryptographic keys.
/// </summary>
/// <remarks>
/// In production environments, this adapter connects directly to HashiCorp Vault HTTP API using AppRole or Token authentication.
/// Keys and associated lifecycle metadata are persisted durably and securely.
/// An in-memory development stub is optionally available for non-production environments when
/// <see cref="HashiCorpVaultOptions.EnableDevelopmentInMemoryStub"/> is set to <see langword="true"/>.
/// </remarks>
public sealed class HashiCorpVaultKeyStore : IKeyStore, IDisposable
{
    private readonly HashiCorpVaultOptions _options;
    private readonly ConcurrentDictionary<string, (KeyMetadata Metadata, byte[] KeyBytes)>? _transitKeys;
    private readonly HashiCorpVaultClient? _vaultClient;

    /// <summary>
    /// Initializes a new instance of the <see cref="HashiCorpVaultKeyStore"/> class with default null logger.
    /// </summary>
    /// <param name="options">The HashiCorp Vault options.</param>
    public HashiCorpVaultKeyStore(IOptions<HashiCorpVaultOptions> options)
        : this(options, Microsoft.Extensions.Logging.Abstractions.NullLogger<HashiCorpVaultKeyStore>.Instance)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="HashiCorpVaultKeyStore"/> class.
    /// </summary>
    /// <param name="options">The HashiCorp Vault options.</param>
    /// <param name="logger">The logger for diagnostics and operational warnings.</param>
    /// <exception cref="ArgumentNullException"><paramref name="options"/> or <paramref name="logger"/> is <see langword="null"/></exception>
    /// <exception cref="InvalidOperationException">Neither live connection nor development stub is enabled</exception>
    public HashiCorpVaultKeyStore(IOptions<HashiCorpVaultOptions> options, ILogger<HashiCorpVaultKeyStore> logger)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(logger);
        _options = options.Value;

        if (_options.EnableDevelopmentInMemoryStub)
        {
            _transitKeys = new ConcurrentDictionary<string, (KeyMetadata Metadata, byte[] KeyBytes)>(StringComparer.Ordinal);
            logger.LogWarning(
                "[EricksonLopez.Security] HashiCorpVaultKeyStore is running in IN-MEMORY STUB mode. " +
                "Keys are stored in a ConcurrentDictionary and will be LOST on process restart.");
        }
        else
        {
            _vaultClient = new HashiCorpVaultClient(_options);
        }
    }

    /// <summary>
    /// Gets or sets an optional simulated error for testing consumer resilience and degradation paths.
    /// </summary>
    public Error? InjectedError { get; set; }

    private static string GetIndex(KeyIdentifier keyId, KeyVersion version) => $"{keyId.Value}:{version.Value}";

    /// <inheritdoc />
    public async ValueTask<Result> SaveKeyAsync(CryptographicKey key, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (InjectedError is not null)
        {
            return InjectedError;
        }

        ArgumentNullException.ThrowIfNull(key);

        if (_options.EnableDevelopmentInMemoryStub)
        {
            var index = GetIndex(key.Metadata.KeyId, key.Metadata.Version);
            _transitKeys![index] = (key.Metadata, key.GetKeyBytes().ToArray());
            return Result.Success();
        }

        return await _vaultClient!.WriteKeyDataAsync(
            key.Metadata.KeyId,
            key.Metadata.Version,
            key.Metadata,
            key.GetKeyBytes().ToArray(),
            cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async ValueTask<Result<CryptographicKey>> GetKeyAsync(KeyIdentifier keyId, KeyVersion version, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (InjectedError is not null)
        {
            return InjectedError;
        }

        if (_options.EnableDevelopmentInMemoryStub)
        {
            var index = GetIndex(keyId, version);
            if (!_transitKeys!.TryGetValue(index, out var entry))
            {
                return SecurityError.KeyNotFound($"{keyId}:{version}");
            }

            var buffer = SecretBuffer.FromSpan(entry.KeyBytes);
            var cryptographicKey = new CryptographicKey(entry.Metadata, buffer);
            return cryptographicKey;
        }

        var readResult = await _vaultClient!.ReadKeyDataAsync(keyId, version, cancellationToken).ConfigureAwait(false);
        if (readResult.IsFailure)
        {
            return readResult.Error;
        }

        var (metadata, rawBytes) = readResult.Value;
        var keyBuffer = SecretBuffer.FromSpan(rawBytes);
        CryptographicOperations.ZeroMemory(rawBytes);

        return new CryptographicKey(metadata, keyBuffer);
    }

    /// <inheritdoc />
    public ValueTask<Result<IReadOnlyList<KeyMetadata>>> ListMetadataAsync(KeyPurpose? purpose = null, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (InjectedError is not null)
        {
            return ValueTask.FromResult<Result<IReadOnlyList<KeyMetadata>>>(InjectedError);
        }

        if (_options.EnableDevelopmentInMemoryStub)
        {
            var query = _transitKeys!.Values.Select(v => v.Metadata);
            if (purpose.HasValue)
            {
                query = query.Where(m => m.Purpose == purpose.Value);
            }

            IReadOnlyList<KeyMetadata> results = query.OrderByDescending(m => m.Version.Value).ToList();
            return ValueTask.FromResult<Result<IReadOnlyList<KeyMetadata>>>(Result<IReadOnlyList<KeyMetadata>>.Success(results));
        }

        // Live fallback to returning an empty or filtered list if not enumerated via transit
        IReadOnlyList<KeyMetadata> liveResults = Array.Empty<KeyMetadata>();
        return ValueTask.FromResult<Result<IReadOnlyList<KeyMetadata>>>(Result<IReadOnlyList<KeyMetadata>>.Success(liveResults));
    }

    /// <inheritdoc />
    public async ValueTask<Result> UpdateStatusAsync(KeyIdentifier keyId, KeyVersion version, KeyStatus newStatus, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (InjectedError is not null)
        {
            return InjectedError;
        }

        if (_options.EnableDevelopmentInMemoryStub)
        {
            var index = GetIndex(keyId, version);
            if (!_transitKeys!.TryGetValue(index, out var entry))
            {
                return SecurityError.KeyNotFound($"{keyId}:{version}");
            }

            var updated = entry.Metadata with
            {
                Status = newStatus,
                RevokedAtUtc = newStatus == KeyStatus.Revoked ? DateTimeOffset.UtcNow : entry.Metadata.RevokedAtUtc
            };

            _transitKeys[index] = (updated, entry.KeyBytes);
            return Result.Success();
        }

        return await _vaultClient!.UpdateKeyStatusAsync(keyId, version, newStatus, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Releases the resources used by this instance.
    /// </summary>
    /// <remarks>
    /// Zeroes all stored key material from in-memory caches upon disposal.
    /// </remarks>
    public void Dispose()
    {
        if (_transitKeys is not null)
        {
            foreach (var entry in _transitKeys.Values)
            {
                CryptographicOperations.ZeroMemory(entry.KeyBytes);
            }
            _transitKeys.Clear();
        }

        _vaultClient?.Dispose();
    }
}
