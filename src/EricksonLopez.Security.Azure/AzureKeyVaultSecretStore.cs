// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Azure;

using System;
using System.Collections.Concurrent;
using System.Threading;
using System.Threading.Tasks;
using global::Azure;
using global::Azure.Identity;
using global::Azure.Security.KeyVault.Secrets;
using EricksonLopez.Result;
using EricksonLopez.Security.Abstractions.Errors;
using EricksonLopez.Security.Abstractions.Primitives;
using EricksonLopez.Security.Abstractions.Secrets;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

/// <summary>
/// Provides an <see cref="ISecretStore"/> adapter backed by Azure Key Vault Secrets.
/// </summary>
/// <remarks>
/// In production environments, this adapter connects directly to Azure Key Vault using <see cref="SecretClient"/>
/// and authenticated via <see cref="global::Azure.Core.TokenCredential"/> (defaults to <see cref="global::Azure.Identity.DefaultAzureCredential"/>).
/// An in-memory development stub is optionally available for non-production environments when
/// <see cref="AzureKeyVaultOptions.EnableDevelopmentInMemoryStub"/> is set to <see langword="true"/>.
/// </remarks>
public sealed class AzureKeyVaultSecretStore : ISecretStore
{
    private readonly AzureKeyVaultOptions _options;
    private readonly ConcurrentDictionary<string, string>? _vaultStorage;
    private readonly SecretClient? _secretClient;

    /// <summary>
    /// Initializes a new instance of the <see cref="AzureKeyVaultSecretStore"/> class with default null logger.
    /// </summary>
    /// <param name="options">The Azure Key Vault configuration options.</param>
    public AzureKeyVaultSecretStore(IOptions<AzureKeyVaultOptions> options)
        : this(options, Microsoft.Extensions.Logging.Abstractions.NullLogger<AzureKeyVaultSecretStore>.Instance)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="AzureKeyVaultSecretStore"/> class.
    /// </summary>
    /// <param name="options">The Azure Key Vault configuration options.</param>
    /// <param name="logger">The logger for diagnostics and operational warnings.</param>
    /// <exception cref="ArgumentNullException"><paramref name="options"/> or <paramref name="logger"/> is <see langword="null"/></exception>
    /// <exception cref="InvalidOperationException">Neither live connection nor development stub is enabled</exception>
    public AzureKeyVaultSecretStore(IOptions<AzureKeyVaultOptions> options, ILogger<AzureKeyVaultSecretStore> logger)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(logger);
        _options = options.Value;

        if (_options.EnableDevelopmentInMemoryStub)
        {
            _vaultStorage = new ConcurrentDictionary<string, string>(StringComparer.Ordinal);
            logger.LogWarning(
                "[EricksonLopez.Security] AzureKeyVaultSecretStore is running in IN-MEMORY STUB mode. " +
                "Secrets are stored in a ConcurrentDictionary and will be LOST on process restart.");
        }
        else
        {
            if (_options.SecretClient is not null)
            {
                _secretClient = _options.SecretClient;
            }
            else if (_options.VaultUri is not null)
            {
                var credential = _options.Credential ?? new DefaultAzureCredential();
                _secretClient = new SecretClient(_options.VaultUri, credential);
            }
            else
            {
                throw new InvalidOperationException(
                    "AzureKeyVaultSecretStore requires either a configured VaultUri, a pre-configured SecretClient, " +
                    "or EnableDevelopmentInMemoryStub = true for testing environments.");
            }
        }
    }

    /// <summary>
    /// Gets or sets an optional simulated error for testing consumer resilience and degradation paths.
    /// </summary>
    public Error? InjectedError { get; set; }

    private string NormalizeKey(string secretName) =>
        $"{_options.SecretPrefix}{secretName.Trim().Replace('.', '-').Replace(':', '-').Replace('_', '-').ToLowerInvariant()}";

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
            if (_vaultStorage is not null && _vaultStorage.TryGetValue(normalized, out var secretValue))
            {
                return new Redacted<string>(secretValue);
            }

            return SecurityError.SecretNotFound(secretName);
        }

        try
        {
            KeyVaultSecret secret = await _secretClient!.GetSecretAsync(normalized, cancellationToken: cancellationToken).ConfigureAwait(false);
            return new Redacted<string>(secret.Value);
        }
        catch (RequestFailedException ex) when (ex.Status == 404)
        {
            return SecurityError.SecretNotFound(secretName);
        }
        catch (RequestFailedException ex)
        {
            return SecurityError.InvalidCiphertext($"Azure Key Vault request failed with status {ex.Status}: {ex.Message}");
        }
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
            if (_vaultStorage is not null)
            {
                _vaultStorage[normalized] = secretValue;
            }
            return Result.Success();
        }

        try
        {
            await _secretClient!.SetSecretAsync(normalized, secretValue, cancellationToken).ConfigureAwait(false);
            return Result.Success();
        }
        catch (RequestFailedException ex)
        {
            return SecurityError.InvalidCiphertext($"Azure Key Vault request failed with status {ex.Status}: {ex.Message}");
        }
    }
}
