// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Abstractions.Secrets;

using System.Threading;
using System.Threading.Tasks;
using EricksonLopez.Result;
using EricksonLopez.Security.Abstractions.Primitives;

/// <summary>
/// Defines contracts for resolving secret references (e.g. "env:DATABASE_PASSWORD", "vault:db-creds#secret")
/// across multiple registered provider stores.
/// </summary>
public interface ISecretResolver
{
    /// <summary>
    /// Resolves a secret reference string to its unredacted secret value.
    /// </summary>
    /// <param name="secretReference">The reference URI or key string.</param>
    /// <param name="cancellationToken">A token that can be used to cancel the asynchronous operation.</param>
    /// <returns>A value task representing the asynchronous operation. The task result contains a <see cref="Result{T}"/> containing the secret value.</returns>
    ValueTask<Result<Redacted<string>>> ResolveAsync(string secretReference, CancellationToken cancellationToken = default);
}
