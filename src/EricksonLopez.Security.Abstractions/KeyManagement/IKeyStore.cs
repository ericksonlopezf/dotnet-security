// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Abstractions.KeyManagement;

using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using EricksonLopez.Result;
using EricksonLopez.Security.Abstractions.Primitives;

/// <summary>
/// Defines contracts for underlying key persistence stores (In-Memory, Database, Vault, KMS, Cloud HSM).
/// </summary>
public interface IKeyStore
{
    /// <summary>
    /// Persists a new cryptographic key into the key store.
    /// </summary>
    /// <param name="key">The cryptographic key to save.</param>
    /// <param name="cancellationToken">A token that can be used to cancel the asynchronous operation.</param>
    /// <returns>A value task representing the asynchronous operation. The task result contains a <see cref="Result"/> indicating success or failure.</returns>
    ValueTask<Result> SaveKeyAsync(CryptographicKey key, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves a cryptographic key by identifier and version.
    /// </summary>
    /// <param name="keyId">The key identifier.</param>
    /// <param name="version">The key version.</param>
    /// <param name="cancellationToken">A token that can be used to cancel the asynchronous operation.</param>
    /// <returns>A value task representing the asynchronous operation. The task result contains a <see cref="Result{T}"/> containing the <see cref="CryptographicKey"/>.</returns>
    ValueTask<Result<CryptographicKey>> GetKeyAsync(KeyIdentifier keyId, KeyVersion version, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves all key metadata stored in the repository.
    /// </summary>
    /// <param name="purpose">Optional purpose filter.</param>
    /// <param name="cancellationToken">A token that can be used to cancel the asynchronous operation.</param>
    /// <returns>A value task representing the asynchronous operation. The task result contains a result with a list of key metadata records.</returns>
    ValueTask<Result<IReadOnlyList<KeyMetadata>>> ListMetadataAsync(KeyPurpose? purpose = null, CancellationToken cancellationToken = default);

    /// <summary>
    /// Updates the lifecycle status of a specific key.
    /// </summary>
    /// <param name="keyId">The key identifier.</param>
    /// <param name="version">The key version.</param>
    /// <param name="newStatus">The new lifecycle status.</param>
    /// <param name="cancellationToken">A token that can be used to cancel the asynchronous operation.</param>
    /// <returns>A value task representing the asynchronous operation. The task result contains a <see cref="Result"/> indicating the outcome.</returns>
    ValueTask<Result> UpdateStatusAsync(KeyIdentifier keyId, KeyVersion version, KeyStatus newStatus, CancellationToken cancellationToken = default);
}
