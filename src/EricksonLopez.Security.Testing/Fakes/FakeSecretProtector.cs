// Copyright © Erickson Lopez. MIT License.

using System;
using System.Threading;
using System.Threading.Tasks;
using EricksonLopez.Result;
using EricksonLopez.Security.Abstractions.Cryptography;
using EricksonLopez.Security.Abstractions.Primitives;
using EricksonLopez.Security.Abstractions.Secrets;
using EricksonLopez.Security.Memory;

namespace EricksonLopez.Security.Testing.Fakes;

/// <summary>
/// Provides an in-memory test double implementation of <see cref="ISecretProtector"/> using simple XOR masking for fast unit testing.
/// </summary>
public sealed class FakeSecretProtector : ISecretProtector
{
    private const byte MaskByte = 0xAA;

    /// <summary>
    /// Gets or sets an optional simulated error to return on protect/unprotect operations.
    /// </summary>
    public Error? InjectedError { get; set; }

    /// <inheritdoc />
    public ValueTask<Result<byte[]>> ProtectAsync(
        ReadOnlyMemory<byte> secret,
        KeyPurpose purpose = KeyPurpose.SecretProtection,
        AuthenticatedContext expectedAssociatedData = default,
        CancellationToken cancellationToken = default)
    {
        if (InjectedError is not null)
        {
            return ValueTask.FromResult<Result<byte[]>>(InjectedError);
        }

        var result = new byte[secret.Length];
        for (int i = 0; i < secret.Length; i++)
        {
            result[i] = (byte)(secret.Span[i] ^ MaskByte);
        }

        return ValueTask.FromResult<Result<byte[]>>(result);
    }

    /// <inheritdoc />
    public ValueTask<Result<byte[]>> UnprotectAsync(
        ReadOnlyMemory<byte> protectedData,
        AuthenticatedContext expectedAssociatedData = default,
        CancellationToken cancellationToken = default)
    {
        if (InjectedError is not null)
        {
            return ValueTask.FromResult<Result<byte[]>>(InjectedError);
        }

        var result = new byte[protectedData.Length];
        for (int i = 0; i < protectedData.Length; i++)
        {
            result[i] = (byte)(protectedData.Span[i] ^ MaskByte);
        }

        return ValueTask.FromResult<Result<byte[]>>(result);
    }

    /// <inheritdoc />
    public Result<byte[]> Protect(
        ReadOnlySpan<byte> secret,
        KeyPurpose purpose = KeyPurpose.SecretProtection,
        AuthenticatedContext expectedAssociatedData = default)
    {
        if (InjectedError is not null)
        {
            return InjectedError;
        }

        var result = new byte[secret.Length];
        for (int i = 0; i < secret.Length; i++)
        {
            result[i] = (byte)(secret[i] ^ MaskByte);
        }

        return result;
    }

    /// <inheritdoc />
    public Result<byte[]> Unprotect(
        ReadOnlySpan<byte> protectedData,
        AuthenticatedContext expectedAssociatedData = default)
    {
        if (InjectedError is not null)
        {
            return InjectedError;
        }

        var result = new byte[protectedData.Length];
        for (int i = 0; i < protectedData.Length; i++)
        {
            result[i] = (byte)(protectedData[i] ^ MaskByte);
        }

        return result;
    }

    /// <inheritdoc />
    public ValueTask<Result<ISecretBuffer>> UnprotectToSecretBufferAsync(
        ReadOnlyMemory<byte> protectedData,
        AuthenticatedContext expectedAssociatedData = default,
        CancellationToken cancellationToken = default)
    {
        if (InjectedError is not null)
        {
            return ValueTask.FromResult<Result<ISecretBuffer>>(InjectedError);
        }

        var buffer = new SecretBuffer(protectedData.Length);
        var span = buffer.GetWritableSpan();
        for (int i = 0; i < protectedData.Length; i++)
        {
            span[i] = (byte)(protectedData.Span[i] ^ MaskByte);
        }

        return ValueTask.FromResult<Result<ISecretBuffer>>(Result<ISecretBuffer>.Success(buffer));
    }
}
