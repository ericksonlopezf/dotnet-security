// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.GoogleCloud;

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
using EricksonLopez.Result;
using EricksonLopez.Security.Abstractions.Errors;
using EricksonLopez.Security.Abstractions.KeyManagement;
using EricksonLopez.Security.Abstractions.Primitives;
using EricksonLopez.Security.Memory;
using Google.Api.Gax.ResourceNames;
using Google.Cloud.Kms.V1;
using Google.Cloud.SecretManager.V1;
using Google.Protobuf;
using Grpc.Core;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

/// <summary>
/// Provides an <see cref="IKeyStore"/> adapter backed by Google Cloud KMS and Secret Manager.
/// Supports Cloud HSM hardware-protected keys for high-assurance workloads such as e-CF digital invoice signing.
/// </summary>
/// <remarks>
/// In production environments, this adapter connects directly to Google Cloud services using <see cref="KeyManagementServiceClient"/>
/// and <see cref="SecretManagerServiceClient"/>.
/// An in-memory development stub is optionally available for non-production environments when
/// <see cref="GoogleCloudSecurityOptions.EnableDevelopmentInMemoryStub"/> is set to <see langword="true"/>.
/// </remarks>
public sealed class GoogleCloudKmsKeyStore : IKeyStore, IDisposable
{
    private readonly GoogleCloudSecurityOptions _options;
    private readonly ConcurrentDictionary<string, (KeyMetadata Metadata, byte[] KeyBytes)>? _inMemoryKeys;
    private readonly KeyManagementServiceClient? _kmsClient;
    private readonly SecretManagerServiceClient? _secretClient;

    /// <summary>
    /// Initializes a new instance of the <see cref="GoogleCloudKmsKeyStore"/> class with default null logger.
    /// </summary>
    /// <param name="options">The Google Cloud security options.</param>
    public GoogleCloudKmsKeyStore(IOptions<GoogleCloudSecurityOptions> options)
        : this(options, Microsoft.Extensions.Logging.Abstractions.NullLogger<GoogleCloudKmsKeyStore>.Instance)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="GoogleCloudKmsKeyStore"/> class.
    /// </summary>
    /// <param name="options">The Google Cloud security options.</param>
    /// <param name="logger">The logger for diagnostics and operational warnings.</param>
    /// <exception cref="ArgumentNullException"><paramref name="options"/> or <paramref name="logger"/> is <see langword="null"/></exception>
    /// <exception cref="InvalidOperationException">Neither live connection nor development stub is enabled</exception>
    public GoogleCloudKmsKeyStore(IOptions<GoogleCloudSecurityOptions> options, ILogger<GoogleCloudKmsKeyStore> logger)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(logger);
        _options = options.Value;

        if (_options.EnableDevelopmentInMemoryStub)
        {
            _inMemoryKeys = new ConcurrentDictionary<string, (KeyMetadata Metadata, byte[] KeyBytes)>(StringComparer.Ordinal);
            logger.LogWarning(
                "[EricksonLopez.Security] GoogleCloudKmsKeyStore is running in IN-MEMORY STUB mode. " +
                "Keys are stored in a ConcurrentDictionary and will be LOST on process restart.");
        }
        else
        {
            if (_options.KmsClient is not null)
            {
                _kmsClient = _options.KmsClient;
            }
            else if (!string.IsNullOrWhiteSpace(_options.ProjectId))
            {
                _kmsClient = KeyManagementServiceClient.Create();
            }
            else
            {
                throw new InvalidOperationException(
                    "GoogleCloudKmsKeyStore requires configured ProjectId, a pre-configured KmsClient, " +
                    "or EnableDevelopmentInMemoryStub = true for testing environments.");
            }

            _secretClient = _options.SecretManagerClient ?? (!string.IsNullOrWhiteSpace(_options.ProjectId) ? SecretManagerServiceClient.Create() : null);
        }
    }

    /// <summary>
    /// Gets or sets an optional simulated error for testing consumer resilience and degradation paths.
    /// </summary>
    public Error? InjectedError { get; set; }

    private static string GetIndex(KeyIdentifier keyId, KeyVersion version) => $"{keyId.Value}:{version.Value}";

    private string FormatKeySecretId(KeyIdentifier keyId, KeyVersion version) =>
        $"{_options.SecretPrefix}kms-key-{keyId.Value.Trim().Replace(':', '-').Replace('_', '-')}-v{version.Value}";

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
            _inMemoryKeys![index] = (key.Metadata, key.GetKeyBytes().ToArray());
            return Result.Success();
        }

        if (_secretClient is null || string.IsNullOrWhiteSpace(_options.ProjectId))
        {
            return SecurityError.InvalidCiphertext("Google Cloud SecretManagerClient or ProjectId is required for durable key storage.");
        }

        var keyBytesToStore = key.GetKeyBytes().ToArray();
        if (_kmsClient is not null && !string.IsNullOrWhiteSpace(_options.KmsCryptoKeyId) && !string.IsNullOrWhiteSpace(_options.LocationId) && !string.IsNullOrWhiteSpace(_options.KeyRingId))
        {
            var cryptoKeyName = CryptoKeyName.FromProjectLocationKeyRingCryptoKey(_options.ProjectId, _options.LocationId, _options.KeyRingId, _options.KmsCryptoKeyId);
            var encryptRequest = new EncryptRequest
            {
                Name = cryptoKeyName.ToString(),
                Plaintext = ByteString.CopyFrom(keyBytesToStore)
            };
            var encryptResponse = await _kmsClient.EncryptAsync(encryptRequest, cancellationToken).ConfigureAwait(false);
            keyBytesToStore = encryptResponse.Ciphertext.ToByteArray();
        }

        var secretId = FormatKeySecretId(key.Metadata.KeyId, key.Metadata.Version);
        var jsonPayload = SerializeKeyRecord(key.Metadata, keyBytesToStore);
        var secretName = new SecretName(_options.ProjectId, secretId);
        var payload = new SecretPayload { Data = ByteString.CopyFromUtf8(jsonPayload) };

        try
        {
            await _secretClient.AddSecretVersionAsync(secretName, payload, cancellationToken).ConfigureAwait(false);
            return Result.Success();
        }
        catch (RpcException ex) when (ex.StatusCode == StatusCode.NotFound)
        {
            try
            {
                var projectName = new ProjectName(_options.ProjectId);
                var secret = new Secret
                {
                    Replication = new Replication { Automatic = new Replication.Types.Automatic() }
                };
                secret.Labels["erickson-key-id"] = key.Metadata.KeyId.Value.Replace(':', '-').ToLowerInvariant();
                secret.Labels["erickson-version"] = key.Metadata.Version.Value.ToString(CultureInfo.InvariantCulture);
                secret.Labels["erickson-purpose"] = key.Metadata.Purpose.ToString().ToLowerInvariant();

                await _secretClient.CreateSecretAsync(projectName, secretId, secret, cancellationToken).ConfigureAwait(false);
                await _secretClient.AddSecretVersionAsync(secretName, payload, cancellationToken).ConfigureAwait(false);
                return Result.Success();
            }
            catch (RpcException createEx)
            {
                return SecurityError.InvalidCiphertext($"Google Cloud KMS key secret create failed ({createEx.StatusCode}): {createEx.Status.Detail}");
            }
        }
        catch (RpcException ex)
        {
            return SecurityError.InvalidCiphertext($"Google Cloud KMS key save failed ({ex.StatusCode}): {ex.Status.Detail}");
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

        if (_secretClient is null || string.IsNullOrWhiteSpace(_options.ProjectId))
        {
            return SecurityError.InvalidCiphertext("Google Cloud SecretManagerClient or ProjectId is required for key retrieval.");
        }

        var secretId = FormatKeySecretId(keyId, version);
        var versionName = new SecretVersionName(_options.ProjectId, secretId, "latest");

        try
        {
            var response = await _secretClient.AccessSecretVersionAsync(versionName, cancellationToken).ConfigureAwait(false);
            var json = response.Payload.Data.ToStringUtf8();

            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;

            root.TryGetProperty("key_bytes", out var bytesProp);
            root.TryGetProperty("key_id", out var idProp);
            root.TryGetProperty("version", out var vProp);
            root.TryGetProperty("purpose", out var pProp);
            root.TryGetProperty("status", out var sProp);
            root.TryGetProperty("algorithm", out var aProp);
            root.TryGetProperty("created_at", out var cProp);
            root.TryGetProperty("expires_at", out var eProp);
            root.TryGetProperty("revoked_at", out var rProp);

            var rawBytes = bytesProp.ValueKind == JsonValueKind.String
                ? Convert.FromBase64String(bytesProp.GetString() ?? string.Empty)
                : Array.Empty<byte>();

            if (_kmsClient is not null && !string.IsNullOrWhiteSpace(_options.KmsCryptoKeyId) && !string.IsNullOrWhiteSpace(_options.LocationId) && !string.IsNullOrWhiteSpace(_options.KeyRingId))
            {
                var cryptoKeyName = CryptoKeyName.FromProjectLocationKeyRingCryptoKey(_options.ProjectId, _options.LocationId, _options.KeyRingId, _options.KmsCryptoKeyId);
                var decryptRequest = new DecryptRequest
                {
                    Name = cryptoKeyName.ToString(),
                    Ciphertext = ByteString.CopyFrom(rawBytes)
                };
                try
                {
                    var decryptResponse = await _kmsClient.DecryptAsync(decryptRequest, cancellationToken).ConfigureAwait(false);
                    rawBytes = decryptResponse.Plaintext.ToByteArray();
                }
                catch (RpcException decryptEx)
                {
                    return SecurityError.InvalidCiphertext($"Google Cloud KMS decryption failed: {decryptEx.Status.Detail}");
                }
            }

            var parsedKeyId = idProp.ValueKind == JsonValueKind.String && !string.IsNullOrWhiteSpace(idProp.GetString()) ? KeyIdentifier.Prefixed(idProp.GetString()!) : keyId;
            var parsedVersion = vProp.ValueKind == JsonValueKind.String && int.TryParse(vProp.GetString(), CultureInfo.InvariantCulture, out var vNum) ? new KeyVersion(vNum) : version;
            var purpose = pProp.ValueKind == JsonValueKind.String && Enum.TryParse<KeyPurpose>(pProp.GetString(), out var p) ? p : KeyPurpose.Encryption;
            var status = sProp.ValueKind == JsonValueKind.String && Enum.TryParse<KeyStatus>(sProp.GetString(), out var s) ? s : KeyStatus.Active;
            var algo = aProp.ValueKind == JsonValueKind.String ? (aProp.GetString() ?? "AES-256-GCM") : "AES-256-GCM";
            var created = cProp.ValueKind == JsonValueKind.String && DateTimeOffset.TryParse(cProp.GetString(), CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var cd) ? cd : DateTimeOffset.UtcNow;
            DateTimeOffset? expires = eProp.ValueKind == JsonValueKind.String && DateTimeOffset.TryParse(eProp.GetString(), CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var ed) ? ed : null;
            DateTimeOffset? revoked = rProp.ValueKind == JsonValueKind.String && DateTimeOffset.TryParse(rProp.GetString(), CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var rd) ? rd : null;

            var metadata = new KeyMetadata(parsedKeyId, parsedVersion, purpose, status, algo, created, expires, revoked);
            var keyBuffer = SecretBuffer.FromSpan(rawBytes);
            CryptographicOperations.ZeroMemory(rawBytes);

            return new CryptographicKey(metadata, keyBuffer);
        }
        catch (RpcException ex) when (ex.StatusCode == StatusCode.NotFound)
        {
            return SecurityError.KeyNotFound($"{keyId}:{version}");
        }
        catch (RpcException ex)
        {
            return SecurityError.InvalidCiphertext($"Google Cloud KMS retrieve failed ({ex.StatusCode}): {ex.Status.Detail}");
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
            var query = _inMemoryKeys!.Values.Select(v => v.Metadata);
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

        var getKeyResult = await GetKeyAsync(keyId, version, cancellationToken).ConfigureAwait(false);
        if (getKeyResult.IsFailure)
        {
            return getKeyResult.Error;
        }

        using var existingKey = getKeyResult.Value;
        var updatedMeta = existingKey.Metadata with
        {
            Status = newStatus,
            RevokedAtUtc = newStatus == KeyStatus.Revoked ? DateTimeOffset.UtcNow : existingKey.Metadata.RevokedAtUtc
        };

        var secretId = FormatKeySecretId(keyId, version);
        var jsonPayload = SerializeKeyRecord(updatedMeta, existingKey.GetKeyBytes().ToArray());
        var secretName = new SecretName(_options.ProjectId, secretId);
        var payload = new SecretPayload { Data = ByteString.CopyFromUtf8(jsonPayload) };

        try
        {
            await _secretClient!.AddSecretVersionAsync(secretName, payload, cancellationToken).ConfigureAwait(false);
            return Result.Success();
        }
        catch (RpcException ex)
        {
            return SecurityError.InvalidCiphertext($"Google Cloud KMS status update failed ({ex.StatusCode}): {ex.Status.Detail}");
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
