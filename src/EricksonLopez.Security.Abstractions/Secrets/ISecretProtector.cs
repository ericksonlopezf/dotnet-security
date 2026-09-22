// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Abstractions.Secrets;

using System;
using System.Threading;
using System.Threading.Tasks;
using EricksonLopez.Result;
using EricksonLopez.Security.Abstractions.Cryptography;
using EricksonLopez.Security.Abstractions.Primitives;

/// <summary>
/// Defines contracts for high-level envelope-based secret protection (encryption and authentication)
/// of sensitive data payloads at rest and in transit.
/// </summary>
public interface ISecretProtector
{
    /// <summary>
    /// Encrypts and authenticates a secret byte buffer into a protected cryptographic envelope payload.
    /// </summary>
    /// <param name="secret">Plaintext secret memory.</param>
    /// <param name="purpose">Cryptographic key purpose (defaults to <see cref="KeyPurpose.SecretProtection"/>).</param>
    /// <param name="expectedAssociatedData">Optional authenticated associated data.</param>
    /// <param name="cancellationToken">A token that can be used to cancel the asynchronous operation.</param>
    /// <returns>A value task representing the asynchronous operation. The task result contains a <see cref="Result{T}"/> containing the serialized protected binary envelope on success.</returns>
    ValueTask<Result<byte[]>> ProtectAsync(
        ReadOnlyMemory<byte> secret,
        KeyPurpose purpose = KeyPurpose.SecretProtection,
        AuthenticatedContext expectedAssociatedData = default,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Decrypts and authenticates a protected cryptographic envelope payload back into plaintext secret bytes.
    /// </summary>
    /// <param name="protectedData">Protected binary envelope memory.</param>
    /// <param name="expectedAssociatedData">Optional authenticated associated data to verify.</param>
    /// <param name="cancellationToken">A token that can be used to cancel the asynchronous operation.</param>
    /// <returns>A value task representing the asynchronous operation. The task result contains a <see cref="Result{T}"/> containing the decrypted plaintext byte array on success.</returns>
    ValueTask<Result<byte[]>> UnprotectAsync(
        ReadOnlyMemory<byte> protectedData,
        AuthenticatedContext expectedAssociatedData = default,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Decrypts and authenticates a protected cryptographic envelope payload into an unmanaged secret buffer
    /// whose memory is zeroized upon disposal.
    /// </summary>
    /// <param name="protectedData">Protected binary envelope memory.</param>
    /// <param name="expectedAssociatedData">Optional authenticated associated data to verify.</param>
    /// <param name="cancellationToken">A token that can be used to cancel the asynchronous operation.</param>
    /// <returns>A value task representing the asynchronous operation. The task result contains a <see cref="Result{T}"/> containing the decrypted <see cref="ISecretBuffer"/> on success.</returns>
    ValueTask<Result<ISecretBuffer>> UnprotectToSecretBufferAsync(
        ReadOnlyMemory<byte> protectedData,
        AuthenticatedContext expectedAssociatedData = default,
        CancellationToken cancellationToken = default);

    /// <summary>Encrypts and authenticates a plaintext secret span into a newly allocated protected payload.</summary>
    /// <param name="secret">Plaintext secret byte span.</param>
    /// <param name="purpose">Cryptographic key purpose for encryption (defaults to <see cref="KeyPurpose.SecretProtection"/>).</param>
    /// <param name="expectedAssociatedData">Optional authenticated associated data bound to the envelope.</param>
    /// <returns>A <see cref="Result{T}"/> containing the serialized protected binary envelope on success.</returns>
    Result<byte[]> Protect(
        ReadOnlySpan<byte> secret,
        KeyPurpose purpose = KeyPurpose.SecretProtection,
        AuthenticatedContext expectedAssociatedData = default);

    /// <summary>Decrypts and authenticates a protected envelope span back into plaintext secret bytes.</summary>
    /// <param name="protectedData">Protected binary envelope byte span.</param>
    /// <param name="expectedAssociatedData">Optional authenticated associated data to verify against the envelope.</param>
    /// <returns>A <see cref="Result{T}"/> containing the decrypted plaintext byte array on success.</returns>
    Result<byte[]> Unprotect(
        ReadOnlySpan<byte> protectedData,
        AuthenticatedContext expectedAssociatedData = default);
}
