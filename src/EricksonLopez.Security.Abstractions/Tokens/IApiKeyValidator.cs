// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Abstractions.Tokens;

using System.Threading;
using System.Threading.Tasks;
using EricksonLopez.Result;
using EricksonLopez.Security.Abstractions.Primitives;

/// <summary>
/// Defines contracts for validating presented API keys against persistent storage using constant-time comparison and active status checks.
/// </summary>
public interface IApiKeyValidator
{
    /// <summary>
    /// Validates an incoming plaintext API key against the registered API key store.
    /// </summary>
    /// <param name="plaintextApiKey">The presented plaintext API key string to validate</param>
    /// <param name="cancellationToken">A token that can be used to cancel the asynchronous operation.</param>
    /// <returns>A value task representing the asynchronous operation. The task result contains a <see cref="Result{T}"/> with the validated <see cref="ApiKey"/> on success, or a failure error.</returns>
    ValueTask<Result<ApiKey>> ValidateApiKeyAsync(
        string plaintextApiKey,
        CancellationToken cancellationToken = default);
}
