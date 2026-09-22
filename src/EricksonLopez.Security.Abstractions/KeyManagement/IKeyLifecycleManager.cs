// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Abstractions.KeyManagement;

using System;
using System.Threading;
using System.Threading.Tasks;
using EricksonLopez.Result;
using EricksonLopez.Security.Abstractions.Primitives;

/// <summary>
/// Defines contracts for automated cryptographic key lifecycle transitions: generation, rotation, retirement, and revocation.
/// </summary>
public interface IKeyLifecycleManager
{
    /// <summary>
    /// Generates and activates a new cryptographic key for the specified purpose and algorithm.
    /// </summary>
    /// <param name="purpose">The key purpose.</param>
    /// <param name="algorithmId">The algorithm identifier (e.g. "AES-256-GCM").</param>
    /// <param name="validityPeriod">Optional key expiration validity duration.</param>
    /// <param name="cancellationToken">A token that can be used to cancel the asynchronous operation.</param>
    /// <returns>A value task representing the asynchronous operation. The task result contains a <see cref="Result{T}"/> containing the generated and activated <see cref="CryptographicKey"/>.</returns>
    ValueTask<Result<CryptographicKey>> GenerateAndActivateKeyAsync(
        KeyPurpose purpose,
        string algorithmId = "AES-256-GCM",
        TimeSpan? validityPeriod = null,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Rotates the active key for a given purpose: marks the current active key as <see cref="KeyStatus.Retired"/>
    /// and generates a new active key with incremented version.
    /// </summary>
    /// <param name="purpose">The key purpose to rotate.</param>
    /// <param name="validityPeriod">Optional validity period for the new key.</param>
    /// <param name="cancellationToken">A token that can be used to cancel the asynchronous operation.</param>
    /// <returns>A value task representing the asynchronous operation. The task result contains a <see cref="Result{T}"/> containing the newly active <see cref="CryptographicKey"/>.</returns>
    ValueTask<Result<CryptographicKey>> RotateKeyAsync(
        KeyPurpose purpose,
        TimeSpan? validityPeriod = null,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Revokes a specific key immediately, disabling it from all future encryption, signing, and decryption operations.
    /// </summary>
    /// <param name="keyId">The key identifier.</param>
    /// <param name="version">The key version.</param>
    /// <param name="reason">The revocation reason.</param>
    /// <param name="cancellationToken">A token that can be used to cancel the asynchronous operation.</param>
    /// <returns>A value task representing the asynchronous operation. The task result contains a <see cref="Result"/> indicating success or failure.</returns>
    ValueTask<Result> RevokeKeyAsync(
        KeyIdentifier keyId,
        KeyVersion version,
        string reason,
        CancellationToken cancellationToken = default);
}
