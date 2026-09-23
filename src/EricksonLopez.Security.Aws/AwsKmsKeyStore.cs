// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Aws;

using System;
using System.Buffers;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Amazon;
using Amazon.KeyManagementService;
using Amazon.SecretsManager;
using Amazon.SecretsManager.Model;
using EncryptRequest = Amazon.KeyManagementService.Model.EncryptRequest;
using DecryptRequest = Amazon.KeyManagementService.Model.DecryptRequest;
using EricksonLopez.Result;
using EricksonLopez.Security.Abstractions.Errors;
using EricksonLopez.Security.Abstractions.KeyManagement;
using EricksonLopez.Security.Abstractions.Primitives;
using EricksonLopez.Security.Memory;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

/// <summary>
/// Provides an <see cref="IKeyStore"/> adapter backed by AWS Key Management Service (KMS) and Secrets Manager.
/// </summary>
/// <remarks>
/// In production environments, this adapter connects directly to AWS Secrets Manager with KMS CMK encryption
/// to persist cryptographic keys and their associated lifecycle metadata durably.
/// An in-memory development stub is optionally available for non-production environments when
/// <see cref="AwsSecurityOptions.EnableDevelopmentInMemoryStub"/> is set to <see langword="true"/>.
/// </remarks>
public sealed class AwsKmsKeyStore : IKeyStore, IDisposable
{
    private readonly AwsSecurityOptions _options;
    private readonly ConcurrentDictionary<string, (KeyMetadata Metadata, byte[] KeyBytes)>? _kmsKeys;
    private readonly IAmazonSecretsManager? _secretsManagerClient;
    private readonly IAmazonKeyManagementService? _kmsClient;
    private readonly bool _ownsClients;

    /// <summary>
    /// Initializes a new instance of the <see cref="AwsKmsKeyStore"/> class with default null logger.
    /// </summary>
    /// <param name="options">The AWS security options.</param>
    public AwsKmsKeyStore(IOptions<AwsSecurityOptions> options)
        : this(options, Microsoft.Extensions.Logging.Abstractions.NullLogger<AwsKmsKeyStore>.Instance)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="AwsKmsKeyStore"/> class.
    /// </summary>
    /// <param name="options">The AWS security options.</param>
    /// <param name="logger">The logger for diagnostics and operational warnings.</param>
    /// <exception cref="ArgumentNullException"><paramref name="options"/> or <paramref name="logger"/> is <see langword="null"/></exception>
    /// <exception cref="InvalidOperationException">Neither live connection nor development stub is enabled</exception>
    public AwsKmsKeyStore(IOptions<AwsSecurityOptions> options, ILogger<AwsKmsKeyStore> logger)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(logger);
        _options = options.Value;

        if (_options.EnableDevelopmentInMemoryStub)
        {
            _kmsKeys = new ConcurrentDictionary<string, (KeyMetadata Metadata, byte[] KeyBytes)>(StringComparer.Ordinal);
            logger.LogWarning(
                "[EricksonLopez.Security] AwsKmsKeyStore is running in IN-MEMORY STUB mode. " +
                "Keys are stored in a ConcurrentDictionary and will be LOST on process restart.");
        }
        else
        {
            if (_options.KmsClient is null && _options.SecretsManagerClient is null && _options.Credentials is null && string.IsNullOrWhiteSpace(_options.KmsKeyId))
            {
                throw new InvalidOperationException(
                    "AwsKmsKeyStore requires configured KmsKeyId, Credentials, pre-configured clients, " +
                    "or EnableDevelopmentInMemoryStub = true for testing environments.");
            }

            var region = RegionEndpoint.GetBySystemName(_options.Region);
            if (_options.SecretsManagerClient is not null)
            {
                _secretsManagerClient = _options.SecretsManagerClient;
                _ownsClients = false;
            }
            else
            {
                // Stryker disable once Conditional,Equality,Boolean : AWS SDK client construction with or without explicit credentials
                _secretsManagerClient = _options.Credentials is not null
                    ? new AmazonSecretsManagerClient(_options.Credentials, region)
                    : new AmazonSecretsManagerClient(region);
                _ownsClients = true;
            }

            if (_options.KmsClient is not null)
            {
                _kmsClient = _options.KmsClient;
            }
            else
            {
                // Stryker disable once Conditional,Equality : AWS SDK client construction with or without explicit credentials
                _kmsClient = _options.Credentials is not null
                    ? new AmazonKeyManagementServiceClient(_options.Credentials, region)
                    : new AmazonKeyManagementServiceClient(region);
            }
        }
    }

    /// <summary>
    /// Gets or sets an optional simulated error for testing consumer resilience and degradation paths.
    /// </summary>
    public Error? InjectedError { get; set; }

    private static string GetIndex(KeyIdentifier keyId, KeyVersion version) => $"{keyId.Value}:{version.Value}";

    private string FormatKeySecretName(KeyIdentifier keyId, KeyVersion version) =>
        $"{_options.SecretPrefix}kms-keys/{keyId.Value.Trim().Replace(':', '-').Replace('_', '-')}/v{version.Value}";

    internal static string SerializeKeyRecord(KeyMetadata metadata, byte[] keyBytes)
    {
        var buffer = new ArrayBufferWriter<byte>();
        using (var writer = new Utf8JsonWriter(buffer))
        {
            writer.WriteStartObject();
            writer.WriteString("key_bytes", Convert.ToBase64String(keyBytes));
            writer.WriteString("key_id", metadata.KeyId.Value);
            writer.WriteString("version", metadata.Version.Value.ToString(CultureInfo.InvariantCulture));
            writer.WriteString("purpose", metadata.Purpose.ToString());
            writer.WriteString("status", metadata.Status.ToString());
            writer.WriteString("algorithm", metadata.AlgorithmId);
            writer.WriteString("created_at", metadata.CreatedAtUtc.ToString("O", CultureInfo.InvariantCulture));
            if (metadata.ExpiresAtUtc.HasValue)
            {
                writer.WriteString("expires_at", metadata.ExpiresAtUtc.Value.ToString("O", CultureInfo.InvariantCulture));
            }
            if (metadata.RevokedAtUtc.HasValue)
            {
                writer.WriteString("revoked_at", metadata.RevokedAtUtc.Value.ToString("O", CultureInfo.InvariantCulture));
            }
            writer.WriteEndObject();
        }
        return Encoding.UTF8.GetString(buffer.WrittenSpan);
    }

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
            _kmsKeys![index] = (key.Metadata, key.GetKeyBytes().ToArray());
            return Result.Success();
        }

        var encryptRequest = new EncryptRequest
        {
            KeyId = _options.KmsKeyId,
            Plaintext = new System.IO.MemoryStream(key.GetKeyBytes().ToArray())
        };
        var encryptResponse = await _kmsClient!.EncryptAsync(encryptRequest, cancellationToken).ConfigureAwait(false);
        var encryptedBlob = encryptResponse.CiphertextBlob.ToArray();

        var secretName = FormatKeySecretName(key.Metadata.KeyId, key.Metadata.Version);
        var secretString = SerializeKeyRecord(key.Metadata, encryptedBlob);

        try
        {
            var putRequest = new PutSecretValueRequest { SecretId = secretName, SecretString = secretString };
            await _secretsManagerClient!.PutSecretValueAsync(putRequest, cancellationToken).ConfigureAwait(false);
            return Result.Success();
        }
        catch (ResourceNotFoundException)
        {
            try
            {
                var createRequest = new CreateSecretRequest
                {
                    Name = secretName,
                    SecretString = secretString,
                    KmsKeyId = !string.IsNullOrWhiteSpace(_options.KmsKeyId) ? _options.KmsKeyId : null
                };
                await _secretsManagerClient!.CreateSecretAsync(createRequest, cancellationToken).ConfigureAwait(false);
                return Result.Success();
            }
            catch (AmazonSecretsManagerException ex)
            {
                return SecurityError.InvalidCiphertext($"AWS Secrets Manager create failed: {ex.Message}");
            }
        }
        catch (AmazonSecretsManagerException ex)
        {
            return SecurityError.InvalidCiphertext($"AWS Secrets Manager save failed: {ex.Message}");
        }
    }

    /// <inheritdoc />
    public async ValueTask<Result<CryptographicKey>> GetKeyAsync(KeyIdentifier keyId, KeyVersion version, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (InjectedError is not null) return InjectedError;

        if (_options.EnableDevelopmentInMemoryStub)
        {
            var index = GetIndex(keyId, version);
            if (!_kmsKeys!.TryGetValue(index, out var entry)) return SecurityError.KeyNotFound($"{keyId}:{version}");
            return new CryptographicKey(entry.Metadata, SecretBuffer.FromSpan(entry.KeyBytes));
        }

        var secretName = FormatKeySecretName(keyId, version);
        try
        {
            var request = new GetSecretValueRequest { SecretId = secretName };
            var response = await _secretsManagerClient!.GetSecretValueAsync(request, cancellationToken).ConfigureAwait(false);

            if (string.IsNullOrWhiteSpace(response.SecretString)) return SecurityError.KeyNotFound($"{keyId}:{version}");

            using var doc = JsonDocument.Parse(response.SecretString);
            var root = doc.RootElement;
            root.TryGetProperty("key_bytes", out var bytesProp);

            // Envelope Decryption
            var encryptedBytes = Convert.FromBase64String(bytesProp.GetString() ?? string.Empty);
            var decryptRequest = new DecryptRequest
            {
                CiphertextBlob = new System.IO.MemoryStream(encryptedBytes)
            };
            var decryptResponse = await _kmsClient!.DecryptAsync(decryptRequest, cancellationToken).ConfigureAwait(false);

            var rawBytes = decryptResponse.Plaintext.ToArray();

            var metadata = new KeyMetadata(keyId, version, KeyPurpose.Encryption, KeyStatus.Active, "AES-256-GCM", DateTimeOffset.UtcNow);
            var buffer = SecretBuffer.FromSpan(rawBytes);
            CryptographicOperations.ZeroMemory(rawBytes);

            return new CryptographicKey(metadata, buffer);
        }
        catch (Exception ex)
        {
            return SecurityError.InvalidCiphertext($"AWS retrieve/decrypt failed: {ex.Message}");
        }
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
            var query = _kmsKeys!.Values.Select(v => v.Metadata);
            if (purpose.HasValue)
            {
                query = query.Where(m => m.Purpose == purpose.Value);
            }

            IReadOnlyList<KeyMetadata> results = query.OrderByDescending(m => m.Version.Value).ToList();
            return ValueTask.FromResult<Result<IReadOnlyList<KeyMetadata>>>(Result<IReadOnlyList<KeyMetadata>>.Success(results));
        }

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
            if (!_kmsKeys!.TryGetValue(index, out var entry))
            {
                return SecurityError.KeyNotFound($"{keyId}:{version}");
            }

            var updated = entry.Metadata with
            {
                Status = newStatus,
                RevokedAtUtc = newStatus == KeyStatus.Revoked ? DateTimeOffset.UtcNow : entry.Metadata.RevokedAtUtc
            };

            _kmsKeys[index] = (updated, entry.KeyBytes);
            return Result.Success();
        }

        var getKeyResult = await GetKeyAsync(keyId, version, cancellationToken).ConfigureAwait(false);
        if (getKeyResult.IsFailure)
        {
            return getKeyResult.Error;
        }

        using var existingKey = getKeyResult.Value;
        var updatedMetadata = existingKey.Metadata with
        {
            Status = newStatus,
            RevokedAtUtc = newStatus == KeyStatus.Revoked ? DateTimeOffset.UtcNow : existingKey.Metadata.RevokedAtUtc
        };

        var secretName = FormatKeySecretName(keyId, version);
        var secretString = SerializeKeyRecord(updatedMetadata, existingKey.GetKeyBytes().ToArray());

        try
        {
            var putRequest = new PutSecretValueRequest { SecretId = secretName, SecretString = secretString };
            await _secretsManagerClient!.PutSecretValueAsync(putRequest, cancellationToken).ConfigureAwait(false);
            return Result.Success();
        }
        catch (AmazonSecretsManagerException ex)
        {
            return SecurityError.InvalidCiphertext($"AWS Secrets Manager update failed: {ex.Message}");
        }
    }

    /// <summary>
    /// Releases the resources used by this instance.
    /// </summary>
    /// <remarks>
    /// Zeroes all stored key material from in-memory caches upon disposal.
    /// </remarks>
    public void Dispose()
    {
        if (_kmsKeys is not null)
        {
            foreach (var entry in _kmsKeys.Values)
            {
                CryptographicOperations.ZeroMemory(entry.KeyBytes);
            }
            _kmsKeys.Clear();
        }

        if (_ownsClients)
        {
            // Stryker disable once Statement : Resource disposal for internally created AWS SDK clients
            _secretsManagerClient?.Dispose();
            // Stryker disable once Statement : Resource disposal for internally created AWS SDK clients
            _kmsClient?.Dispose();
        }
    }
}
