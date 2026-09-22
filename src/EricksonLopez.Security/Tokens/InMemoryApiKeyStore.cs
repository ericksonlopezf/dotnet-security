// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Tokens;

using System;
using System.Collections.Concurrent;
using System.Threading;
using System.Threading.Tasks;
using EricksonLopez.Result;
using EricksonLopez.Security.Abstractions.Errors;
using EricksonLopez.Security.Abstractions.Primitives;
using EricksonLopez.Security.Abstractions.Tokens;

/// <summary>
/// Provides a thread-safe in-memory API key store implementation of <see cref="IApiKeyStore"/> suitable for
/// testing, development, and containerized microservice deployments.
/// </summary>
public sealed class InMemoryApiKeyStore : IApiKeyStore
{
    private readonly ConcurrentDictionary<string, ApiKey> _keys = new(StringComparer.Ordinal);

    /// <summary>
    /// Initializes a new instance of the <see cref="InMemoryApiKeyStore"/> class.
    /// </summary>
    public InMemoryApiKeyStore()
    {
    }

    /// <inheritdoc />
    public ValueTask<Result<ApiKey>> GetByIdAsync(ApiKeyId keyId, CancellationToken cancellationToken = default)
    {
        if (_keys.TryGetValue(keyId.Value, out var key))
        {
            return ValueTask.FromResult<Result<ApiKey>>(key);
        }

        return ValueTask.FromResult<Result<ApiKey>>(SecurityError.KeyNotFound(keyId.Value));
    }

    /// <inheritdoc />
    public ValueTask<Result> SaveAsync(ApiKey apiKey, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(apiKey);

        _keys[apiKey.Id.Value] = apiKey;
        return ValueTask.FromResult(Result.Success());
    }

    /// <inheritdoc />
    public ValueTask<Result> RevokeAsync(ApiKeyId keyId, CancellationToken cancellationToken = default)
    {
        if (_keys.TryGetValue(keyId.Value, out var key))
        {
            _keys[keyId.Value] = key with { RevokedAtUtc = DateTimeOffset.UtcNow };
            return ValueTask.FromResult(Result.Success());
        }

        return ValueTask.FromResult<Result>(SecurityError.KeyNotFound(keyId.Value));
    }
}
