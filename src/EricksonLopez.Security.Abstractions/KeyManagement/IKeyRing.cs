// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Abstractions.KeyManagement;

using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using EricksonLopez.Result;
using EricksonLopez.Security.Abstractions.Primitives;

/// <summary>
/// Defines contracts for querying, resolving, and caching active and legacy cryptographic keys
/// across purpose boundaries and version hierarchies.
/// </summary>
public interface IKeyRing
{
    /// <summary>
    /// Synchronously retrieves the current active key for a given purpose.
    /// </summary>
    /// <param name="purpose">The key purpose.</param>
    /// <returns>A <see cref="Result{T}"/> containing the active <see cref="CryptographicKey"/>.</returns>
    /// <remarks>
    /// This synchronous overload blocks the calling thread by calling
    /// <c>GetActiveKeyAsync(...).AsTask().GetAwaiter().GetResult()</c>.
    /// In environments with a <c>SynchronizationContext</c> (ASP.NET Framework, WPF, WinForms, Blazor Server)
    /// this can deadlock. Prefer <see cref="GetActiveKeyAsync"/> instead.
    /// </remarks>
    Result<CryptographicKey> GetActiveKey(KeyPurpose purpose);

    /// <summary>
    /// Synchronously retrieves a specific versioned key for decryption or verification.
    /// </summary>
    /// <param name="keyId">The key identifier.</param>
    /// <param name="version">The key version.</param>
    /// <returns>A <see cref="Result{T}"/> containing the requested <see cref="CryptographicKey"/>.</returns>
    /// <remarks>
    /// This synchronous overload blocks the calling thread by calling
    /// <c>GetKeyAsync(...).AsTask().GetAwaiter().GetResult()</c>.
    /// In environments with a <c>SynchronizationContext</c> this can deadlock.
    /// Prefer <see cref="GetKeyAsync"/> instead.
    /// </remarks>
    Result<CryptographicKey> GetKey(KeyIdentifier keyId, KeyVersion version);

    /// <summary>
    /// Asynchronously retrieves the current active key for a given purpose.
    /// </summary>
    /// <param name="purpose">The key purpose.</param>
    /// <param name="cancellationToken">A token that can be used to cancel the asynchronous operation.</param>
    /// <returns>A value task representing the asynchronous operation. The task result contains a <see cref="Result{T}"/> containing the active <see cref="CryptographicKey"/>.</returns>
    ValueTask<Result<CryptographicKey>> GetActiveKeyAsync(KeyPurpose purpose, CancellationToken cancellationToken = default);

    /// <summary>
    /// Asynchronously retrieves a specific versioned key for decryption or verification.
    /// </summary>
    /// <param name="keyId">The key identifier.</param>
    /// <param name="version">The key version.</param>
    /// <param name="cancellationToken">A token that can be used to cancel the asynchronous operation.</param>
    /// <returns>A value task representing the asynchronous operation. The task result contains a <see cref="Result{T}"/> containing the requested <see cref="CryptographicKey"/>.</returns>
    ValueTask<Result<CryptographicKey>> GetKeyAsync(KeyIdentifier keyId, KeyVersion version, CancellationToken cancellationToken = default);

    /// <summary>
    /// Asynchronously lists all known key metadata descriptors currently loaded in the key ring.
    /// </summary>
    /// <param name="purpose">Optional purpose filter.</param>
    /// <param name="cancellationToken">A token that can be used to cancel the asynchronous operation.</param>
    /// <returns>A value task representing the asynchronous operation. The task result contains a result with a list of key metadata records.</returns>
    ValueTask<Result<IReadOnlyList<KeyMetadata>>> ListMetadataAsync(KeyPurpose? purpose = null, CancellationToken cancellationToken = default);

    /// <summary>
    /// Immediately evicts and scrubs a specific versioned key from the local cache.
    /// </summary>
    /// <param name="keyId">The identifier of the key to evict.</param>
    /// <param name="version">The version of the key to evict.</param>
    void InvalidateKey(KeyIdentifier keyId, KeyVersion version);

    /// <summary>
    /// Immediately evicts and scrubs the active key for a given purpose from the local cache.
    /// </summary>
    /// <param name="purpose">The key purpose whose active cached key should be evicted.</param>
    void InvalidateActiveKey(KeyPurpose purpose);

    /// <summary>
    /// Immediately evicts and scrubs all cached keys and metadata from the local cache.
    /// </summary>
    void InvalidateAll();
}

