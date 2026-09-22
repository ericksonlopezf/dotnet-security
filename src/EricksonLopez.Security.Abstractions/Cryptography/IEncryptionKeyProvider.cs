// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Abstractions.Cryptography;

using System.Threading;
using System.Threading.Tasks;
using EricksonLopez.Result;
using EricksonLopez.Security.Abstractions.Primitives;

/// <summary>
/// Defines the contract for providing cryptographic keys for encryption and decryption operations based on purpose and version.
/// </summary>
public interface IEncryptionKeyProvider
{
    /// <summary>
    /// Gets the current active key for encryption operations.
    /// </summary>
    /// <param name="purpose">The key purpose (defaults to Encryption).</param>
    /// <param name="cancellationToken">A token that can be used to cancel the asynchronous operation.</param>
    /// <returns>A value task representing the asynchronous operation. The task result contains a <see cref="Result{T}"/> containing the active <see cref="CryptographicKey"/>.</returns>
    ValueTask<Result<CryptographicKey>> GetActiveEncryptionKeyAsync(
        KeyPurpose purpose = KeyPurpose.Encryption,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets a specific versioned key for decryption operations.
    /// </summary>
    /// <param name="keyId">The key identifier.</param>
    /// <param name="version">The key version.</param>
    /// <param name="cancellationToken">A token that can be used to cancel the asynchronous operation.</param>
    /// <returns>A value task representing the asynchronous operation. The task result contains a <see cref="Result{T}"/> containing the requested <see cref="CryptographicKey"/>.</returns>
    ValueTask<Result<CryptographicKey>> GetDecryptionKeyAsync(
        KeyIdentifier keyId,
        KeyVersion version,
        CancellationToken cancellationToken = default);
}
