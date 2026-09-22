// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.GoogleCloud;

using System;
using System.Collections.Concurrent;
using System.Threading;
using System.Threading.Tasks;
using EricksonLopez.Result;
using EricksonLopez.Security.Abstractions.Errors;
using EricksonLopez.Security.Abstractions.Primitives;
using EricksonLopez.Security.Abstractions.Secrets;
using Google.Api.Gax.ResourceNames;
using Google.Cloud.SecretManager.V1;
using Google.Protobuf;
using Grpc.Core;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

/// <summary>
/// Provides an <see cref="ISecretStore"/> adapter backed by Google Cloud Secret Manager.
/// </summary>
/// <remarks>
/// In production environments, this adapter connects directly to Google Cloud Secret Manager using <see cref="SecretManagerServiceClient"/>.
/// An in-memory development stub is optionally available for non-production environments when
/// <see cref="GoogleCloudSecurityOptions.EnableDevelopmentInMemoryStub"/> is set to <see langword="true"/>.
/// </remarks>
public sealed class GoogleCloudSecretManagerStore : ISecretStore
{
    private readonly GoogleCloudSecurityOptions _options;
    private readonly ConcurrentDictionary<string, string>? _secretsStorage;
    private readonly SecretManagerServiceClient? _client;

    /// <summary>
    /// Initializes a new instance of the <see cref="GoogleCloudSecretManagerStore"/> class with default null logger.
    /// </summary>
    /// <param name="options">The Google Cloud security options.</param>
    public GoogleCloudSecretManagerStore(IOptions<GoogleCloudSecurityOptions> options)
        : this(options, Microsoft.Extensions.Logging.Abstractions.NullLogger<GoogleCloudSecretManagerStore>.Instance)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="GoogleCloudSecretManagerStore"/> class.
    /// </summary>
    /// <param name="options">The Google Cloud security options.</param>
    /// <param name="logger">The logger for diagnostics and operational warnings.</param>
    /// <exception cref="ArgumentNullException"><paramref name="options"/> or <paramref name="logger"/> is <see langword="null"/></exception>
    /// <exception cref="InvalidOperationException">Neither live connection nor development stub is enabled</exception>
    public GoogleCloudSecretManagerStore(IOptions<GoogleCloudSecurityOptions> options, ILogger<GoogleCloudSecretManagerStore> logger)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(logger);
        _options = options.Value;

        if (_options.EnableDevelopmentInMemoryStub)
        {
            _secretsStorage = new ConcurrentDictionary<string, string>(StringComparer.Ordinal);
            logger.LogWarning(
                "[EricksonLopez.Security] GoogleCloudSecretManagerStore is running in IN-MEMORY STUB mode. " +
                "Secrets are stored in a ConcurrentDictionary and will be LOST on process restart.");
        }
        else
        {
            if (_options.SecretManagerClient is not null)
            {
                _client = _options.SecretManagerClient;
            }
            // Stryker disable once Block,String : Google Cloud SecretManager client factory via Application Default Credentials
            else if (!string.IsNullOrWhiteSpace(_options.ProjectId))
            {
                _client = SecretManagerServiceClient.Create();
            }
            else
            {
                throw new InvalidOperationException(
                    "GoogleCloudSecretManagerStore requires configured ProjectId, a pre-configured SecretManagerClient, " +
                    "or EnableDevelopmentInMemoryStub = true for testing environments.");
            }
        }
    }

    /// <summary>
    /// Gets or sets an optional simulated error for testing consumer resilience and degradation paths.
    /// </summary>
    public Error? InjectedError { get; set; }

    private string NormalizeKey(string secretName) =>
        $"{_options.SecretPrefix}{secretName.Trim().Replace('.', '-').Replace(':', '-').Replace('/', '-')}";

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
            if (_secretsStorage is not null && _secretsStorage.TryGetValue(normalized, out var secretValue))
            {
                return new Redacted<string>(secretValue);
            }

            return SecurityError.SecretNotFound(secretName);
        }

        try
        {
            var secretVersionName = new SecretVersionName(_options.ProjectId, normalized, "latest");
            var response = await _client!.AccessSecretVersionAsync(secretVersionName, cancellationToken).ConfigureAwait(false);
            var secretString = response.Payload.Data.ToStringUtf8();
            return new Redacted<string>(secretString);
        }
        catch (RpcException ex) when (ex.StatusCode == StatusCode.NotFound)
        {
            return SecurityError.SecretNotFound(secretName);
        }
        catch (RpcException ex)
        {
            return SecurityError.InvalidCiphertext($"Google Cloud Secret Manager error ({ex.StatusCode}): {ex.Status.Detail}");
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
            if (_secretsStorage is not null)
            {
                _secretsStorage[normalized] = secretValue;
            }
            return Result.Success();
        }

        var secretNameObj = new SecretName(_options.ProjectId, normalized);
        var payload = new SecretPayload { Data = ByteString.CopyFromUtf8(secretValue) };

        try
        {
            await _client!.AddSecretVersionAsync(secretNameObj, payload, cancellationToken).ConfigureAwait(false);
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
                await _client!.CreateSecretAsync(projectName, normalized, secret, cancellationToken).ConfigureAwait(false);
                await _client!.AddSecretVersionAsync(secretNameObj, payload, cancellationToken).ConfigureAwait(false);
                return Result.Success();
            }
            catch (RpcException createEx)
            {
                return SecurityError.InvalidCiphertext($"Google Cloud Secret Manager create failed ({createEx.StatusCode}): {createEx.Status.Detail}");
            }
        }
        catch (RpcException ex)
        {
            return SecurityError.InvalidCiphertext($"Google Cloud Secret Manager update failed ({ex.StatusCode}): {ex.Status.Detail}");
        }
    }
}
