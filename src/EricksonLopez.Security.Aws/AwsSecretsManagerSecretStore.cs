// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Aws;

using System;
using System.Collections.Concurrent;
using System.Threading;
using System.Threading.Tasks;
using Amazon;
using Amazon.SecretsManager;
using Amazon.SecretsManager.Model;
using EricksonLopez.Result;
using EricksonLopez.Security.Abstractions.Errors;
using EricksonLopez.Security.Abstractions.Primitives;
using EricksonLopez.Security.Abstractions.Secrets;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

/// <summary>
/// Provides an <see cref="ISecretStore"/> adapter backed by AWS Secrets Manager.
/// </summary>
/// <remarks>
/// In production environments, this adapter connects directly to AWS Secrets Manager using <see cref="IAmazonSecretsManager"/>.
/// An in-memory development stub is optionally available for non-production environments when
/// <see cref="AwsSecurityOptions.EnableDevelopmentInMemoryStub"/> is set to <see langword="true"/>.
/// </remarks>
public sealed class AwsSecretsManagerSecretStore : ISecretStore, IDisposable
{
    private readonly AwsSecurityOptions _options;
    private readonly ConcurrentDictionary<string, string>? _secretsStorage;
    private readonly IAmazonSecretsManager? _secretsManagerClient;
    private readonly bool _ownsClient;

    /// <summary>
    /// Initializes a new instance of the <see cref="AwsSecretsManagerSecretStore"/> class with default null logger.
    /// </summary>
    /// <param name="options">The AWS security options.</param>
    public AwsSecretsManagerSecretStore(IOptions<AwsSecurityOptions> options)
        : this(options, Microsoft.Extensions.Logging.Abstractions.NullLogger<AwsSecretsManagerSecretStore>.Instance)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="AwsSecretsManagerSecretStore"/> class.
    /// </summary>
    /// <param name="options">The AWS security options.</param>
    /// <param name="logger">The logger for diagnostics and operational warnings.</param>
    /// <exception cref="ArgumentNullException"><paramref name="options"/> or <paramref name="logger"/> is <see langword="null"/></exception>
    /// <exception cref="InvalidOperationException">Neither live connection nor development stub is enabled</exception>
    public AwsSecretsManagerSecretStore(IOptions<AwsSecurityOptions> options, ILogger<AwsSecretsManagerSecretStore> logger)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(logger);
        _options = options.Value;

        if (_options.EnableDevelopmentInMemoryStub)
        {
            _secretsStorage = new ConcurrentDictionary<string, string>(StringComparer.Ordinal);
            logger.LogWarning(
                "[EricksonLopez.Security] AwsSecretsManagerSecretStore is running in IN-MEMORY STUB mode. " +
                "Secrets are stored in a ConcurrentDictionary and will be LOST on process restart.");
        }
        else
        {
            if (_options.SecretsManagerClient is null && _options.Credentials is null && string.IsNullOrWhiteSpace(_options.SecretPrefix))
            {
                throw new InvalidOperationException(
                    "AwsSecretsManagerSecretStore requires configured Credentials, a pre-configured SecretsManagerClient, " +
                    "or EnableDevelopmentInMemoryStub = true for testing environments.");
            }

            if (_options.SecretsManagerClient is not null)
            {
                _secretsManagerClient = _options.SecretsManagerClient;
                _ownsClient = false;
            }
            else
            {
                var region = RegionEndpoint.GetBySystemName(_options.Region);
                // Stryker disable once Conditional,Equality,Boolean : AWS SDK client construction with or without explicit credentials
                _secretsManagerClient = _options.Credentials is not null
                    ? new AmazonSecretsManagerClient(_options.Credentials, region)
                    : new AmazonSecretsManagerClient(region);
                _ownsClient = true;
            }
        }
    }

    /// <summary>
    /// Gets or sets an optional simulated error for testing consumer resilience and degradation paths.
    /// </summary>
    public Error? InjectedError { get; set; }

    private string NormalizeKey(string secretName) => $"{_options.SecretPrefix}{secretName.Trim()}";

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
            var request = new GetSecretValueRequest { SecretId = normalized };
            var response = await _secretsManagerClient!.GetSecretValueAsync(request, cancellationToken).ConfigureAwait(false);
            return new Redacted<string>(response.SecretString ?? string.Empty);
        }
        catch (ResourceNotFoundException)
        {
            return SecurityError.SecretNotFound(secretName);
        }
        catch (AmazonSecretsManagerException ex)
        {
            return SecurityError.InvalidCiphertext($"AWS Secrets Manager request failed: {ex.Message}");
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

        try
        {
            var putRequest = new PutSecretValueRequest { SecretId = normalized, SecretString = secretValue };
            await _secretsManagerClient!.PutSecretValueAsync(putRequest, cancellationToken).ConfigureAwait(false);
            return Result.Success();
        }
        catch (ResourceNotFoundException)
        {
            try
            {
                var createRequest = new CreateSecretRequest { Name = normalized, SecretString = secretValue };
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
            return SecurityError.InvalidCiphertext($"AWS Secrets Manager update failed: {ex.Message}");
        }
    }

    /// <summary>
    /// Releases the resources used by this instance.
    /// </summary>
    public void Dispose()
    {
        // Stryker disable once Equality,Statement : Resource disposal for internally created AWS Secrets Manager client
        if (_ownsClient && _secretsManagerClient is not null)
        {
            _secretsManagerClient.Dispose();
        }
    }
}
