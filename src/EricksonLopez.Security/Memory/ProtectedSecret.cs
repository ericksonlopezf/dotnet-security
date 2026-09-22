// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Memory;

using System;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
using EricksonLopez.Result;
using EricksonLopez.Security.Abstractions.Cryptography;
using EricksonLopez.Security.Abstractions.KeyManagement;
using EricksonLopez.Security.Abstractions.Primitives;
using EricksonLopez.Security.Abstractions.Secrets;

/// <summary>
/// Encapsulates an encrypted secret payload held in memory at rest, supporting deferred,
/// on-demand unprotection via an injected or provided <see cref="ISecretProtector"/>.
/// </summary>
[DebuggerDisplay("[PROTECTED SECRET: {KeyId}:{KeyVersion}]")]
public sealed class ProtectedSecret
{
    /// <summary>
    /// Gets the key identifier that encrypted this secret.
    /// </summary>
    public KeyIdentifier KeyId { get; }

    /// <summary>
    /// Gets the version of the key that encrypted this secret.
    /// </summary>
    public KeyVersion KeyVersion { get; }

    /// <summary>
    /// Gets the encrypted envelope payload bytes.
    /// </summary>
    public ReadOnlyMemory<byte> ProtectedBytes { get; }

    /// <summary>
    /// Initializes a new instance of the <see cref="ProtectedSecret"/> class.
    /// </summary>
    /// <param name="keyId">The key identifier.</param>
    /// <param name="keyVersion">The key version.</param>
    /// <param name="protectedBytes">The encrypted envelope payload bytes.</param>
    public ProtectedSecret(KeyIdentifier keyId, KeyVersion keyVersion, ReadOnlyMemory<byte> protectedBytes)
    {
        KeyId = keyId;
        KeyVersion = keyVersion;
        ProtectedBytes = protectedBytes;
    }

    /// <summary>
    /// Asynchronously unprotects and decrypts this secret using the specified secret protector.
    /// </summary>
    /// <param name="protector">The secret protector service.</param>
    /// <param name="expectedAssociatedData">The optional authenticated associated data.</param>
    /// <param name="cancellationToken">A token that can be used to cancel the asynchronous operation.</param>
    /// <returns>
    /// A task representing the asynchronous operation. The task result contains a <see cref="Result{T}"/> containing the decrypted plaintext byte array.
    /// </returns>
    /// <exception cref="ArgumentNullException"><paramref name="protector"/> is <see langword="null"/></exception>
    public ValueTask<Result<byte[]>> UnprotectAsync(
        ISecretProtector protector,
        AuthenticatedContext expectedAssociatedData = default,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(protector);
        return protector.UnprotectAsync(ProtectedBytes, expectedAssociatedData, cancellationToken);
    }

    /// <inheritdoc />
    public override string ToString() => "[REDACTED PROTECTED SECRET]";
}
