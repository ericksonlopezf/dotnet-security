// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.HashiCorpVault;

using System;
using System.Buffers;
using System.Globalization;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using EricksonLopez.Result;
using EricksonLopez.Security.Abstractions.Errors;
using EricksonLopez.Security.Abstractions.KeyManagement;
using EricksonLopez.Security.Abstractions.Primitives;

// Provides a production HTTP client for communicating with the HashiCorp Vault HTTP API.
// Supports AppRole authentication, static token authentication, Vault namespaces, and KV v2 secrets.
// Uses Utf8JsonWriter for zero-reflection Native AOT trimming compliance.
internal sealed class HashiCorpVaultClient : IDisposable
{
    private readonly HashiCorpVaultOptions _options;
    private readonly HttpClient _httpClient;
    private readonly bool _ownsHttpClient;
    private readonly SemaphoreSlim _authLock = new(1, 1);
    private string? _clientToken;
    private DateTimeOffset _tokenExpiresAtUtc = DateTimeOffset.MinValue;
    private bool _disposed;

    internal DateTimeOffset TokenExpiresAtUtc => _tokenExpiresAtUtc;
    internal string? ClientToken => _clientToken;

    public HashiCorpVaultClient(HashiCorpVaultOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        _options = options;

        if (_options.VaultUrl is null)
        {
            throw new InvalidOperationException("HashiCorpVaultOptions.VaultUrl must be configured for live Vault connections.");
        }

        if (string.IsNullOrWhiteSpace(_options.Token) &&
            (string.IsNullOrWhiteSpace(_options.RoleId) || string.IsNullOrWhiteSpace(_options.SecretId)))
        {
            throw new InvalidOperationException(
                "HashiCorpVault authentication requires either a static Token or both RoleId and SecretId (AppRole).");
        }

        if (_options.HttpClient is not null)
        {
            _httpClient = _options.HttpClient;
            // Stryker disable once Boolean : Client ownership flag
            _ownsHttpClient = false;
        }
        else
        {
            // Stryker disable once ObjectInitializer,Boolean : Default HttpClient initialization
            _httpClient = new HttpClient
            {
                BaseAddress = _options.VaultUrl,
                Timeout = TimeSpan.FromSeconds(30)
            };
            _ownsHttpClient = true;
        }

        if (!string.IsNullOrWhiteSpace(_options.Token))
        {
            _clientToken = _options.Token;
            _tokenExpiresAtUtc = DateTimeOffset.MaxValue;
        }
    }

    private static ByteArrayContent CreateJsonContent(byte[] utf8JsonBytes)
    {
        var content = new ByteArrayContent(utf8JsonBytes);
        content.Headers.ContentType = new MediaTypeHeaderValue("application/json") { CharSet = "utf-8" };
        return content;
    }

    internal static byte[] SerializeAppRoleLogin(string roleId, string secretId)
    {
        var buffer = new ArrayBufferWriter<byte>();
        using (var writer = new Utf8JsonWriter(buffer))
        {
            writer.WriteStartObject();
            writer.WriteString("role_id", roleId);
            writer.WriteString("secret_id", secretId);
            writer.WriteEndObject();
        }
        return buffer.WrittenMemory.ToArray();
    }

    internal static byte[] SerializeKvSecretWrite(string secretValue)
    {
        var buffer = new ArrayBufferWriter<byte>();
        using (var writer = new Utf8JsonWriter(buffer))
        {
            writer.WriteStartObject();
            writer.WriteStartObject("data");
            writer.WriteString("value", secretValue);
            writer.WriteEndObject();
            writer.WriteEndObject();
        }
        return buffer.WrittenMemory.ToArray();
    }

    internal static byte[] SerializeKeyDataWrite(KeyIdentifier keyId, KeyVersion version, KeyMetadata metadata, byte[] keyBytes)
    {
        var buffer = new ArrayBufferWriter<byte>();
        using (var writer = new Utf8JsonWriter(buffer))
        {
            writer.WriteStartObject();
            writer.WriteStartObject("data");
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
            writer.WriteEndObject();
        }
        return buffer.WrittenMemory.ToArray();
    }

    private async ValueTask<string> EnsureTokenAsync(CancellationToken cancellationToken)
    {
        if (!string.IsNullOrWhiteSpace(_clientToken) && DateTimeOffset.UtcNow < _tokenExpiresAtUtc)
        {
            return _clientToken;
        }

        await _authLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (!string.IsNullOrWhiteSpace(_clientToken) && DateTimeOffset.UtcNow < _tokenExpiresAtUtc)
            {
                return _clientToken;
            }

            var appRoleLoginPath = $"v1/auth/{_options.AppRoleMountPath}/login";
            var jsonBytes = SerializeAppRoleLogin(_options.RoleId ?? string.Empty, _options.SecretId ?? string.Empty);

            using var request = new HttpRequestMessage(HttpMethod.Post, appRoleLoginPath)
            {
                Content = CreateJsonContent(jsonBytes)
            };

            if (!string.IsNullOrWhiteSpace(_options.Namespace))
            {
                request.Headers.Add("X-Vault-Namespace", _options.Namespace);
            }

            using var response = await _httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
            {
                var errorBody = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
                throw new InvalidOperationException($"HashiCorp Vault AppRole login failed ({response.StatusCode}): {errorBody}");
            }

            var responseBody = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
            using var doc = JsonDocument.Parse(responseBody);

            var root = doc.RootElement;
            if (root.TryGetProperty("auth", out var authElement) &&
                authElement.TryGetProperty("client_token", out var tokenElement))
            {
                var token = tokenElement.GetString();
                if (string.IsNullOrWhiteSpace(token))
                {
                    throw new InvalidOperationException("HashiCorp Vault AppRole response did not contain a valid client_token.");
                }

                _clientToken = token;
                var leaseDuration = 3600;
                if (authElement.TryGetProperty("lease_duration", out var leaseProp) && leaseProp.TryGetInt32(out var lease))
                {
                    leaseDuration = lease;
                }

                _tokenExpiresAtUtc = DateTimeOffset.UtcNow.AddSeconds(Math.Max(30, leaseDuration - 30));
                return _clientToken;
            }

            throw new InvalidOperationException("HashiCorp Vault AppRole response lacked the 'auth' object.");
        }
        finally
        {
            _authLock.Release();
        }
    }

    private async ValueTask<HttpRequestMessage> CreateAuthenticatedRequestAsync(HttpMethod method, string path, CancellationToken cancellationToken)
    {
        var token = await EnsureTokenAsync(cancellationToken).ConfigureAwait(false);
        var request = new HttpRequestMessage(method, path);
        request.Headers.Add("X-Vault-Token", token);

        if (!string.IsNullOrWhiteSpace(_options.Namespace))
        {
            request.Headers.Add("X-Vault-Namespace", _options.Namespace);
        }

        return request;
    }

    public async ValueTask<Result<string>> ReadKvSecretAsync(string secretName, CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        var path = $"v1/{_options.KvMountPath}/data/{secretName}";
        using var request = await CreateAuthenticatedRequestAsync(HttpMethod.Get, path, cancellationToken).ConfigureAwait(false);

        using var response = await _httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
        if (response.StatusCode == HttpStatusCode.NotFound)
        {
            return SecurityError.SecretNotFound(secretName);
        }

        if (!response.IsSuccessStatusCode)
        {
            var err = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
            return SecurityError.InvalidCiphertext($"Vault read failed with status {response.StatusCode}: {err}");
        }

        var json = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        using var doc = JsonDocument.Parse(json);

        if (doc.RootElement.TryGetProperty("data", out var dataObj) &&
            dataObj.TryGetProperty("data", out var innerData))
        {
            if (innerData.TryGetProperty("value", out var valueProp))
            {
                return Result<string>.Success(valueProp.GetString() ?? string.Empty);
            }

            return Result<string>.Success(innerData.GetRawText());
        }

        return SecurityError.SecretNotFound(secretName);
    }

    public async ValueTask<Result> WriteKvSecretAsync(string secretName, string secretValue, CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        var path = $"v1/{_options.KvMountPath}/data/{secretName}";
        using var request = await CreateAuthenticatedRequestAsync(HttpMethod.Post, path, cancellationToken).ConfigureAwait(false);

        var jsonBytes = SerializeKvSecretWrite(secretValue);
        request.Content = CreateJsonContent(jsonBytes);

        using var response = await _httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            var err = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
            return SecurityError.InvalidCiphertext($"Vault write failed with status {response.StatusCode}: {err}");
        }

        return Result.Success();
    }

    public async ValueTask<Result> WriteKeyDataAsync(KeyIdentifier keyId, KeyVersion version, KeyMetadata metadata, byte[] keyBytes, CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        var keyPath = $"v1/{_options.KvMountPath}/data/{_options.SecretPathPrefix}keys/{keyId.Value}/v{version.Value}";
        using var request = await CreateAuthenticatedRequestAsync(HttpMethod.Post, keyPath, cancellationToken).ConfigureAwait(false);

        var jsonBytes = SerializeKeyDataWrite(keyId, version, metadata, keyBytes);
        request.Content = CreateJsonContent(jsonBytes);

        using var response = await _httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            var err = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
            return SecurityError.InvalidCiphertext($"Vault key write failed with status {response.StatusCode}: {err}");
        }

        return Result.Success();
    }

    public async ValueTask<Result<(KeyMetadata Metadata, byte[] KeyBytes)>> ReadKeyDataAsync(KeyIdentifier keyId, KeyVersion version, CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        var keyPath = $"v1/{_options.KvMountPath}/data/{_options.SecretPathPrefix}keys/{keyId.Value}/v{version.Value}";
        using var request = await CreateAuthenticatedRequestAsync(HttpMethod.Get, keyPath, cancellationToken).ConfigureAwait(false);

        using var response = await _httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
        if (response.StatusCode == HttpStatusCode.NotFound)
        {
            return SecurityError.KeyNotFound($"{keyId}:{version}");
        }

        if (!response.IsSuccessStatusCode)
        {
            var err = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
            return SecurityError.InvalidCiphertext($"Vault key read failed with status {response.StatusCode}: {err}");
        }

        var json = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        using var doc = JsonDocument.Parse(json);

        if (doc.RootElement.TryGetProperty("data", out var dataObj) &&
            dataObj.TryGetProperty("data", out var innerData))
        {
            innerData.TryGetProperty("key_bytes", out var bytesProp);
            innerData.TryGetProperty("key_id", out var idProp);
            innerData.TryGetProperty("version", out var vProp);
            innerData.TryGetProperty("purpose", out var pProp);
            innerData.TryGetProperty("status", out var sProp);
            innerData.TryGetProperty("algorithm", out var aProp);
            innerData.TryGetProperty("created_at", out var cProp);
            innerData.TryGetProperty("expires_at", out var eProp);
            innerData.TryGetProperty("revoked_at", out var rProp);

            var rawBytes = bytesProp.ValueKind == JsonValueKind.String
                ? Convert.FromBase64String(bytesProp.GetString() ?? string.Empty)
                : Array.Empty<byte>();
            var parsedKeyId = idProp.ValueKind == JsonValueKind.String && !string.IsNullOrWhiteSpace(idProp.GetString()) ? KeyIdentifier.Prefixed(idProp.GetString()!) : keyId;
            var parsedVersion = vProp.ValueKind == JsonValueKind.String && int.TryParse(vProp.GetString(), CultureInfo.InvariantCulture, out var vNum) ? new KeyVersion(vNum) : version;
            var purpose = pProp.ValueKind == JsonValueKind.String && Enum.TryParse<KeyPurpose>(pProp.GetString(), out var p) ? p : KeyPurpose.Encryption;
            var status = sProp.ValueKind == JsonValueKind.String && Enum.TryParse<KeyStatus>(sProp.GetString(), out var s) ? s : KeyStatus.Active;
            var algo = aProp.ValueKind == JsonValueKind.String ? (aProp.GetString() ?? "AES-256-GCM") : "AES-256-GCM";
            var created = cProp.ValueKind == JsonValueKind.String && DateTimeOffset.TryParse(cProp.GetString(), CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var cd) ? cd : DateTimeOffset.UtcNow;
            DateTimeOffset? expires = eProp.ValueKind == JsonValueKind.String && DateTimeOffset.TryParse(eProp.GetString(), CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var ed) ? ed : null;
            DateTimeOffset? revoked = rProp.ValueKind == JsonValueKind.String && DateTimeOffset.TryParse(rProp.GetString(), CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var rd) ? rd : null;

            var meta = new KeyMetadata(parsedKeyId, parsedVersion, purpose, status, algo, created, expires, revoked);
            return Result<(KeyMetadata Metadata, byte[] KeyBytes)>.Success((meta, rawBytes));
        }

        return SecurityError.KeyNotFound($"{keyId}:{version}");
    }

    public async ValueTask<Result> UpdateKeyStatusAsync(KeyIdentifier keyId, KeyVersion version, KeyStatus newStatus, CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        var readResult = await ReadKeyDataAsync(keyId, version, cancellationToken).ConfigureAwait(false);
        if (readResult.IsFailure)
        {
            return readResult.Error;
        }

        var (existingMeta, existingBytes) = readResult.Value;
        var updated = existingMeta with
        {
            Status = newStatus,
            RevokedAtUtc = newStatus == KeyStatus.Revoked ? DateTimeOffset.UtcNow : existingMeta.RevokedAtUtc
        };

        var writeResult = await WriteKeyDataAsync(keyId, version, updated, existingBytes, cancellationToken).ConfigureAwait(false);
        CryptographicOperations.ZeroMemory(existingBytes);
        return writeResult;
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _authLock.Dispose();
        // Stryker disable once Negate,Statement : Internal HttpClient disposal
        if (_ownsHttpClient)
        {
            _httpClient.Dispose();
        }

        _disposed = true;
    }
}
