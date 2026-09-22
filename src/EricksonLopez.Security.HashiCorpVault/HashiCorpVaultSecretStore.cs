// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.HashiCorpVault;

using System;
using System.Collections.Concurrent;
using System.Threading;
using System.Threading.Tasks;
using EricksonLopez.Result;
using EricksonLopez.Security.Abstractions.Errors;
using EricksonLopez.Security.Abstractions.Primitives;
using EricksonLopez.Security.Abstractions.Secrets;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

/// <summary>
/// Provides an <see cref="ISecretStore"/> adapter backed by the HashiCorp Vault KV v2 secrets engine.
/// </summary>
/// <remarks>
/// In production environments, this adapter connects directly to HashiCorp Vault HTTP API using AppRole or Token authentication.
/// An in-memory development stub is optionally available for non-production environments when
/// <see cref="HashiCorpVaultOptions.EnableDevelopmentInMemoryStub"/> is set to <see langword="true"/>.
/// </remarks>
public sealed class HashiCorpVaultSecretStore : ISecretStore, IDisposable
{
    private readonly HashiCorpVaultOptions _options;
    private readonly ConcurrentDictionary<string, string>? _kvStorage;
    private readonly HashiCorpVaultClient? _vaultClient;

    /// <summary>
    /// Initializes a new instance of the <see cref="HashiCorpVaultSecretStore"/> class with default null logger.
    /// </summary>
    /// <param name="options">The HashiCorp Vault options.</param>
    public HashiCorpVaultSecretStore(IOptions<HashiCorpVaultOptions> options)
        : this(options, Microsoft.Extensions.Logging.Abstractions.NullLogger<HashiCorpVaultSecretStore>.Instance)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="HashiCorpVaultSecretStore"/> class.
    /// </summary>
    /// <param name="options">The HashiCorp Vault options.</param>
    /// <param name="logger">The logger for diagnostics and operational warnings.</param>
    /// <exception cref="ArgumentNullException"><paramref name="options"/> or <paramref name="logger"/> is <see langword="null"/></exception>
    /// <exception cref="InvalidOperationException">Neither live connection nor development stub is enabled</exception>
    public HashiCorpVaultSecretStore(IOptions<HashiCorpVaultOptions> options, ILogger<HashiCorpVaultSecretStore> logger)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(logger);
        _options = options.Value;

        if (_options.EnableDevelopmentInMemoryStub)
        {
            _kvStorage = new ConcurrentDictionary<string, string>(StringComparer.Ordinal);
            logger.LogWarning(
                "[EricksonLopez.Security] HashiCorpVaultSecretStore is running in IN-MEMORY STUB mode. " +
                "Secrets are stored in a ConcurrentDictionary and will be LOST on process restart.");
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

    private string NormalizeKey(string secretName) => $"{_options.SecretPathPrefix}{secretName.Trim().ToLowerInvariant()}";

    /// <inheritdoc />
    public async ValueTask<Result<Redacted<string>>> GetSecretAsync(string secretName, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (InjectedError is not null)
        {
            return InjectedError;
        }

        if (string.IsNullOrWhiteSpace(secretName))
        {
            return SecurityError.SecretNotFound("Empty secret name.");
        }

        var normalized = NormalizeKey(secretName);

        if (_options.EnableDevelopmentInMemoryStub)
        {
            if (_kvStorage is not null && _kvStorage.TryGetValue(normalized, out var secretValue))
            {
                return new Redacted<string>(secretValue);
            }

            return SecurityError.SecretNotFound(secretName);
        }

        var readResult = await _vaultClient!.ReadKvSecretAsync(normalized, cancellationToken).ConfigureAwait(false);
        if (readResult.IsFailure)
        {
            return readResult.Error;
        }

        return new Redacted<string>(readResult.Value);
    }

    /// <inheritdoc />
    public async ValueTask<Result> SetSecretAsync(string secretName, string secretValue, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (InjectedError is not null)
        {
            return InjectedError;
        }

        if (string.IsNullOrWhiteSpace(secretName))
        {
            return SecurityError.SecretNotFound("Empty secret name.");
        }

        var normalized = NormalizeKey(secretName);

        if (_options.EnableDevelopmentInMemoryStub)
        {
            if (_kvStorage is not null)
            {
                _kvStorage[normalized] = secretValue;
            }
            return Result.Success();
        }

        return await _vaultClient!.WriteKvSecretAsync(normalized, secretValue, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Releases the resources used by this instance.
    /// </summary>
    public void Dispose()
    {
        _vaultClient?.Dispose();
    }
}
