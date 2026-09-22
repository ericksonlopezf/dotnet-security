// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Secrets;

using System;
using System.Threading;
using System.Threading.Tasks;
using EricksonLopez.Result;
using EricksonLopez.Security.Abstractions.Errors;
using EricksonLopez.Security.Abstractions.Primitives;
using EricksonLopez.Security.Abstractions.Secrets;

/// <summary>
/// Provides an implementation of <see cref="ISecretStore"/> that reads and writes secrets from environment variables.
/// </summary>
public sealed class EnvironmentSecretStore : ISecretStore
{
    private readonly string _prefix;

    /// <summary>
    /// Initializes a new instance of the <see cref="EnvironmentSecretStore"/> class.
    /// </summary>
    /// <param name="prefix">The optional environment variable prefix (e.g., "APP_").</param>
    public EnvironmentSecretStore(string prefix = "")
    {
        _prefix = prefix ?? string.Empty;
    }

    private string NormalizeKey(string secretName) =>
        $"{_prefix}{secretName.Trim().Replace('.', '_').Replace(':', '_').Replace('-', '_').ToUpperInvariant()}";

    /// <inheritdoc />
    public ValueTask<Result<Redacted<string>>> GetSecretAsync(string secretName, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(secretName))
        {
            return ValueTask.FromResult<Result<Redacted<string>>>(SecurityError.SecretNotFound(secretName));
        }

        var normalizedKey = NormalizeKey(secretName);
        var rawValue = Environment.GetEnvironmentVariable(normalizedKey);

        if (string.IsNullOrEmpty(rawValue))
        {
            return ValueTask.FromResult<Result<Redacted<string>>>(SecurityError.SecretNotFound(secretName));
        }

        return ValueTask.FromResult<Result<Redacted<string>>>(new Redacted<string>(rawValue));
    }

    /// <inheritdoc />
    /// <remarks>
    /// <strong>Security Warning:</strong> Environment variables set at <see cref="EnvironmentVariableTarget.Process"/> scope
    /// are visible to native libraries in the current process and inherited by child processes spawned via <see cref="System.Diagnostics.Process.Start(string)"/>.
    /// </remarks>
    public ValueTask<Result> SetSecretAsync(string secretName, string secretValue, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(secretName))
        {
            return ValueTask.FromResult<Result>(SecurityError.SecretNotFound(secretName));
        }

        var normalizedKey = NormalizeKey(secretName);
        Environment.SetEnvironmentVariable(normalizedKey, secretValue, EnvironmentVariableTarget.Process);
        return ValueTask.FromResult(Result.Success());
    }
}
