// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Secrets;

using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using EricksonLopez.Result;
using EricksonLopez.Security.Abstractions.Errors;
using EricksonLopez.Security.Abstractions.Primitives;
using EricksonLopez.Security.Abstractions.Secrets;

/// <summary>
/// Resolves secrets across multiple backend providers based on URI scheme prefixes.
/// </summary>
/// <remarks>
/// Supports the following URI scheme prefixes:
/// <list type="bullet">
///   <item><c>env:VARIABLE_NAME</c> (retrieves from environment variables)</item>
///   <item><c>store:SECRET_NAME</c> (retrieves from registered <see cref="ISecretStore"/>)</item>
///   <item><c>raw:PLAINTEXT_VALUE</c> (returns raw value directly)</item>
/// </list>
/// </remarks>
public sealed class CompositeSecretResolver : ISecretResolver
{
    private readonly ISecretStore _secretStore;
    private readonly EnvironmentSecretStore _envStore;

    /// <summary>
    /// Initializes a new instance of the <see cref="CompositeSecretResolver"/> class.
    /// </summary>
    /// <param name="secretStore">The default secret store.</param>
    /// <param name="envStore">The optional environment secret store.</param>
    /// <exception cref="ArgumentNullException"><paramref name="secretStore"/> is <see langword="null"/></exception>
    public CompositeSecretResolver(ISecretStore secretStore, EnvironmentSecretStore? envStore = null)
    {
        _secretStore = secretStore ?? throw new ArgumentNullException(nameof(secretStore));
        _envStore = envStore ?? new EnvironmentSecretStore();
    }

    /// <inheritdoc />
    public async ValueTask<Result<Redacted<string>>> ResolveAsync(string secretReference, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(secretReference))
        {
            return SecurityError.SecretNotFound("Empty secret reference.");
        }

        var trimmed = secretReference.Trim();

        // Scheme 1: raw:value
        if (trimmed.StartsWith("raw:", StringComparison.OrdinalIgnoreCase))
        {
            return new Redacted<string>(trimmed[4..]);
        }

        // Scheme 2: env:VAR_NAME
        if (trimmed.StartsWith("env:", StringComparison.OrdinalIgnoreCase))
        {
            return await _envStore.GetSecretAsync(trimmed[4..], cancellationToken).ConfigureAwait(false);
        }

        // Scheme 3: store:SECRET_NAME
        if (trimmed.StartsWith("store:", StringComparison.OrdinalIgnoreCase))
        {
            return await _secretStore.GetSecretAsync(trimmed[6..], cancellationToken).ConfigureAwait(false);
        }

        // Default fallback to registered secret store
        return await _secretStore.GetSecretAsync(trimmed, cancellationToken).ConfigureAwait(false);
    }
}
