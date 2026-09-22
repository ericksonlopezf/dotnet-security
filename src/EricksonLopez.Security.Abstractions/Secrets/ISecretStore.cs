// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Abstractions.Secrets;

using System.Threading;
using System.Threading.Tasks;
using EricksonLopez.Result;
using EricksonLopez.Security.Abstractions.Primitives;

/// <summary>
/// Defines contracts for underlying secret storage providers (Environment, DPAPI, Azure Key Vault, AWS Secrets Manager, HashiCorp Vault).
/// </summary>
public interface ISecretStore
{
    /// <summary>
    /// Retrieves a secret by name as a memory-safe <see cref="Redacted{T}"/> string container.
    /// </summary>
    /// <param name="secretName">The unique secret key name.</param>
    /// <param name="cancellationToken">A token that can be used to cancel the asynchronous operation.</param>
    /// <returns>A value task representing the asynchronous operation. The task result contains a <see cref="Result{T}"/> containing the secret value.</returns>
    ValueTask<Result<Redacted<string>>> GetSecretAsync(string secretName, CancellationToken cancellationToken = default);

    /// <summary>
    /// Sets or updates a secret in the underlying store.
    /// </summary>
    /// <param name="secretName">The unique secret key name.</param>
    /// <param name="secretValue">The secret value to persist.</param>
    /// <param name="cancellationToken">A token that can be used to cancel the asynchronous operation.</param>
    /// <returns>A value task representing the asynchronous operation. The task result contains a <see cref="Result"/> indicating success or failure.</returns>
    ValueTask<Result> SetSecretAsync(string secretName, string secretValue, CancellationToken cancellationToken = default);
}
