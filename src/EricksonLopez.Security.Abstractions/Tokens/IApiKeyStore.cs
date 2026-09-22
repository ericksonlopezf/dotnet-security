// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Abstractions.Tokens;

using System.Threading;
using System.Threading.Tasks;
using EricksonLopez.Result;
using EricksonLopez.Security.Abstractions.Primitives;

/// <summary>
/// Defines repository operations for persisting, retrieving, and updating <see cref="ApiKey"/> entities.
/// </summary>
public interface IApiKeyStore
{
    /// <summary>
    /// Retrieves an API key entity by its lookup identifier.
    /// </summary>
    /// <param name="keyId">The unique lookup identifier of the API key</param>
    /// <param name="cancellationToken">A token that can be used to cancel the asynchronous operation.</param>
    /// <returns>A value task representing the asynchronous operation. The task result contains a <see cref="Result{T}"/> with the matching <see cref="ApiKey"/>, or a not-found error.</returns>
    ValueTask<Result<ApiKey>> GetByIdAsync(ApiKeyId keyId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Persists a newly issued API key entity.
    /// </summary>
    /// <param name="apiKey">The API key entity to persist</param>
    /// <param name="cancellationToken">A token that can be used to cancel the asynchronous operation.</param>
    /// <returns>A value task representing the asynchronous operation. The task result contains a <see cref="Result"/> indicating whether the operation succeeded.</returns>
    ValueTask<Result> SaveAsync(ApiKey apiKey, CancellationToken cancellationToken = default);

    /// <summary>
    /// Revokes an existing API key.
    /// </summary>
    /// <param name="keyId">The unique lookup identifier of the API key to revoke</param>
    /// <param name="cancellationToken">A token that can be used to cancel the asynchronous operation.</param>
    /// <returns>A value task representing the asynchronous operation. The task result contains a <see cref="Result"/> indicating whether the operation succeeded.</returns>
    ValueTask<Result> RevokeAsync(ApiKeyId keyId, CancellationToken cancellationToken = default);
}
