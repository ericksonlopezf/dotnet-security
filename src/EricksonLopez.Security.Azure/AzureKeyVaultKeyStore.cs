// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Azure;

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using global::Azure;
using global::Azure.Identity;
using global::Azure.Security.KeyVault.Secrets;
using EricksonLopez.Result;
using EricksonLopez.Security.Abstractions.Errors;
using EricksonLopez.Security.Abstractions.KeyManagement;
using EricksonLopez.Security.Abstractions.Primitives;
using EricksonLopez.Security.Memory;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

/// <summary>
/// Provides an <see cref="IKeyStore"/> adapter backed by Azure Key Vault cryptographic keys.
/// </summary>
/// <remarks>
/// In production environments, this adapter connects directly to Azure Key Vault using <see cref="SecretClient"/>
/// to durably persist cryptographic keys and their associated lifecycle metadata via tags.
/// An in-memory development stub is optionally available for non-production environments when
/// <see cref="AzureKeyVaultOptions.EnableDevelopmentInMemoryStub"/> is set to <see langword="true"/>.
/// </remarks>
public sealed class AzureKeyVaultKeyStore : IKeyStore, IDisposable
{
    private readonly AzureKeyVaultOptions _options;
    private readonly ConcurrentDictionary<string, (KeyMetadata Metadata, byte[] KeyBytes)>? _inMemoryKeys;
    private readonly SecretClient? _secretClient;

    /// <summary>
    /// Initializes a new instance of the <see cref="AzureKeyVaultKeyStore"/> class with default null logger.
    /// </summary>
    /// <param name="options">The Azure Key Vault configuration options.</param>
    public AzureKeyVaultKeyStore(IOptions<AzureKeyVaultOptions> options)
        : this(options, Microsoft.Extensions.Logging.Abstractions.NullLogger<AzureKeyVaultKeyStore>.Instance)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="AzureKeyVaultKeyStore"/> class.
    /// </summary>
    /// <param name="options">The Azure Key Vault configuration options.</param>
    /// <param name="logger">The logger for diagnostics and operational warnings.</param>
    /// <exception cref="ArgumentNullException"><paramref name="options"/> or <paramref name="logger"/> is <see langword="null"/></exception>
    /// <exception cref="InvalidOperationException">Neither live connection nor development stub is enabled</exception>
    public AzureKeyVaultKeyStore(IOptions<AzureKeyVaultOptions> options, ILogger<AzureKeyVaultKeyStore> logger)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(logger);
        _options = options.Value;

        if (_options.EnableDevelopmentInMemoryStub)
        {
            _inMemoryKeys = new ConcurrentDictionary<string, (KeyMetadata Metadata, byte[] KeyBytes)>(StringComparer.Ordinal);
            logger.LogWarning(
                "[EricksonLopez.Security] AzureKeyVaultKeyStore is running in IN-MEMORY STUB mode. " +
                "Keys are stored in a ConcurrentDictionary and will be LOST on process restart.");
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
                    "AzureKeyVaultKeyStore requires either a configured VaultUri, a pre-configured SecretClient, " +
                    "or EnableDevelopmentInMemoryStub = true for testing environments.");
            }
        }
    }

    /// <summary>
    /// Gets or sets an optional simulated error for testing consumer resilience and degradation paths.
    /// </summary>
    public Error? InjectedError { get; set; }

    private static string GetIndex(KeyIdentifier keyId, KeyVersion version) => $"{keyId.Value}:{version.Value}";

    private string FormatKeySecretName(KeyIdentifier keyId, KeyVersion version) =>
        $"{_options.SecretPrefix}key-{keyId.Value.Trim().Replace(':', '-').Replace('_', '-').ToLowerInvariant()}-v{version.Value}";

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
            _inMemoryKeys![index] = (key.Metadata, key.GetKeyBytes().ToArray());
            return Result.Success();
        }

        try
        {
            var secretName = FormatKeySecretName(key.Metadata.KeyId, key.Metadata.Version);
            var base64Key = Convert.ToBase64String(key.GetKeyBytes());
            var secret = new KeyVaultSecret(secretName, base64Key);

            secret.Properties.Tags["KeyId"] = key.Metadata.KeyId.Value;
            secret.Properties.Tags["Version"] = key.Metadata.Version.Value.ToString(System.Globalization.CultureInfo.InvariantCulture);
            secret.Properties.Tags["Purpose"] = key.Metadata.Purpose.ToString();
            secret.Properties.Tags["Status"] = key.Metadata.Status.ToString();
            secret.Properties.Tags["AlgorithmId"] = key.Metadata.AlgorithmId;
            secret.Properties.Tags["CreatedAtUtc"] = key.Metadata.CreatedAtUtc.ToString("O", System.Globalization.CultureInfo.InvariantCulture);

            if (key.Metadata.ExpiresAtUtc.HasValue)
            {
                secret.Properties.ExpiresOn = key.Metadata.ExpiresAtUtc.Value;
                secret.Properties.Tags["ExpiresAtUtc"] = key.Metadata.ExpiresAtUtc.Value.ToString("O", System.Globalization.CultureInfo.InvariantCulture);
            }

            if (key.Metadata.RevokedAtUtc.HasValue)
            {
                secret.Properties.Tags["RevokedAtUtc"] = key.Metadata.RevokedAtUtc.Value.ToString("O", System.Globalization.CultureInfo.InvariantCulture);
            }

            secret.Properties.Enabled = key.Metadata.Status == KeyStatus.Active;

            await _secretClient!.SetSecretAsync(secret, cancellationToken).ConfigureAwait(false);
            return Result.Success();
        }
        catch (RequestFailedException ex)
        {
            return SecurityError.InvalidCiphertext($"Azure Key Vault request failed with status {ex.Status}: {ex.Message}");
        }
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
            if (!_inMemoryKeys!.TryGetValue(index, out var entry))
            {
                return SecurityError.KeyNotFound($"{keyId}:{version}");
            }

            var buffer = SecretBuffer.FromSpan(entry.KeyBytes);
            var cryptographicKey = new CryptographicKey(entry.Metadata, buffer);
            return cryptographicKey;
        }

        try
        {
            var secretName = FormatKeySecretName(keyId, version);
            KeyVaultSecret secret = await _secretClient!.GetSecretAsync(secretName, cancellationToken: cancellationToken).ConfigureAwait(false);

            var rawBytes = Convert.FromBase64String(secret.Value);
            var metadata = ParseMetadataFromProperties(secret.Properties, keyId, version);
            var buffer = SecretBuffer.FromSpan(rawBytes);
            CryptographicOperations.ZeroMemory(rawBytes);

            return new CryptographicKey(metadata, buffer);
        }
        catch (RequestFailedException ex) when (ex.Status == 404)
        {
            return SecurityError.KeyNotFound($"{keyId}:{version}");
        }
        catch (RequestFailedException ex)
        {
            return SecurityError.InvalidCiphertext($"Azure Key Vault request failed with status {ex.Status}: {ex.Message}");
        }
    }

    /// <inheritdoc />
    public async ValueTask<Result<IReadOnlyList<KeyMetadata>>> ListMetadataAsync(KeyPurpose? purpose = null, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (InjectedError is not null)
        {
            return InjectedError;
        }

        if (_options.EnableDevelopmentInMemoryStub)
        {
            var query = _inMemoryKeys!.Values.Select(v => v.Metadata);
            if (purpose.HasValue)
            {
                query = query.Where(m => m.Purpose == purpose.Value);
            }

            IReadOnlyList<KeyMetadata> stubResults = query.OrderByDescending(m => m.Version.Value).ToList();
            return Result<IReadOnlyList<KeyMetadata>>.Success(stubResults);
        }

        try
        {
            var results = new List<KeyMetadata>();
            await foreach (SecretProperties properties in _secretClient!.GetPropertiesOfSecretsAsync(cancellationToken).ConfigureAwait(false))
            {
                if (properties.Tags.ContainsKey("KeyId") && properties.Tags.ContainsKey("Version"))
                {
                    var meta = ParseMetadataFromProperties(properties, null, null);
                    if (!purpose.HasValue || meta.Purpose == purpose.Value)
                    {
                        results.Add(meta);
                    }
                }
            }

            IReadOnlyList<KeyMetadata> ordered = results.OrderByDescending(m => m.Version.Value).ToList();
            return Result<IReadOnlyList<KeyMetadata>>.Success(ordered);
        }
        catch (RequestFailedException ex)
        {
            return SecurityError.InvalidCiphertext($"Azure Key Vault request failed with status {ex.Status}: {ex.Message}");
        }
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
            if (!_inMemoryKeys!.TryGetValue(index, out var entry))
            {
                return SecurityError.KeyNotFound($"{keyId}:{version}");
            }

            var updated = entry.Metadata with
            {
                Status = newStatus,
                RevokedAtUtc = newStatus == KeyStatus.Revoked ? DateTimeOffset.UtcNow : entry.Metadata.RevokedAtUtc
            };

            _inMemoryKeys[index] = (updated, entry.KeyBytes);
            return Result.Success();
        }

        try
        {
            var secretName = FormatKeySecretName(keyId, version);
            KeyVaultSecret secret = await _secretClient!.GetSecretAsync(secretName, cancellationToken: cancellationToken).ConfigureAwait(false);

            secret.Properties.Tags["Status"] = newStatus.ToString();
            if (newStatus == KeyStatus.Revoked)
            {
                secret.Properties.Tags["RevokedAtUtc"] = DateTimeOffset.UtcNow.ToString("O", System.Globalization.CultureInfo.InvariantCulture);
            }
            secret.Properties.Enabled = newStatus == KeyStatus.Active;

            await _secretClient.UpdateSecretPropertiesAsync(secret.Properties, cancellationToken).ConfigureAwait(false);
            return Result.Success();
        }
        catch (RequestFailedException ex) when (ex.Status == 404)
        {
            return SecurityError.KeyNotFound($"{keyId}:{version}");
        }
        catch (RequestFailedException ex)
        {
            return SecurityError.InvalidCiphertext($"Azure Key Vault request failed with status {ex.Status}: {ex.Message}");
        }
    }

    private static KeyMetadata ParseMetadataFromProperties(SecretProperties properties, KeyIdentifier? fallbackKeyId, KeyVersion? fallbackVersion)
    {
        properties.Tags.TryGetValue("KeyId", out var keyIdStr);
        properties.Tags.TryGetValue("Version", out var versionStr);
        properties.Tags.TryGetValue("Purpose", out var purposeStr);
        properties.Tags.TryGetValue("Status", out var statusStr);
        properties.Tags.TryGetValue("AlgorithmId", out var algorithmId);
        properties.Tags.TryGetValue("CreatedAtUtc", out var createdStr);
        properties.Tags.TryGetValue("ExpiresAtUtc", out var expiresStr);
        properties.Tags.TryGetValue("RevokedAtUtc", out var revokedStr);

        var keyId = !string.IsNullOrWhiteSpace(keyIdStr)
            ? KeyIdentifier.Prefixed(keyIdStr)
            : fallbackKeyId ?? KeyIdentifier.Prefixed("unknown");

        var version = int.TryParse(versionStr, out var vNum)
            ? new KeyVersion(vNum)
            : fallbackVersion ?? KeyVersion.Initial;

        var purpose = Enum.TryParse<KeyPurpose>(purposeStr, out var p) ? p : KeyPurpose.Encryption;
        var status = Enum.TryParse<KeyStatus>(statusStr, out var s) ? s : (properties.Enabled == true ? KeyStatus.Active : KeyStatus.Retired);
        var algorithm = !string.IsNullOrWhiteSpace(algorithmId) ? algorithmId : "AES-256-GCM";
        var createdAt = DateTimeOffset.TryParse(createdStr, out var cd) ? cd : properties.CreatedOn ?? DateTimeOffset.UtcNow;
        DateTimeOffset? expiresAt = DateTimeOffset.TryParse(expiresStr, out var ed) ? ed : properties.ExpiresOn;
        DateTimeOffset? revokedAt = DateTimeOffset.TryParse(revokedStr, out var rd) ? rd : null;

        return new KeyMetadata(keyId, version, purpose, status, algorithm, createdAt, expiresAt, revokedAt);
    }

    /// <summary>
    /// Releases the resources used by this instance.
    /// </summary>
    /// <remarks>
    /// Zeroes all stored key material from in-memory caches upon disposal.
    /// </remarks>
    public void Dispose()
    {
        if (_inMemoryKeys is not null)
        {
            foreach (var entry in _inMemoryKeys.Values)
            {
                CryptographicOperations.ZeroMemory(entry.KeyBytes);
            }
            _inMemoryKeys.Clear();
        }
    }
}
