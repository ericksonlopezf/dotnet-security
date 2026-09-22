// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Tests.Memory;

using System;
using System.Threading;
using System.Threading.Tasks;
using EricksonLopez.Result;
using EricksonLopez.Security.Abstractions.Cryptography;
using EricksonLopez.Security.Abstractions.Primitives;
using EricksonLopez.Security.Abstractions.Secrets;
using EricksonLopez.Security.Memory;
using EricksonLopez.Security.Testing.Assertions;
using Xunit;

public sealed class ProtectedSecretTests
{
    private sealed class TrackingSecretProtector : ISecretProtector
    {
        public ReadOnlyMemory<byte> ReceivedProtectedData { get; private set; }
        public AuthenticatedContext ReceivedAssociatedData { get; private set; }
        public CancellationToken ReceivedCancellationToken { get; private set; }
        public byte[] ResultToReturn { get; set; } = [];

        ValueTask<Result<byte[]>> ISecretProtector.ProtectAsync(ReadOnlyMemory<byte> secret, KeyPurpose purpose, AuthenticatedContext expectedAssociatedData, CancellationToken cancellationToken) =>
            ValueTask.FromResult<Result<byte[]>>(ResultToReturn);

        ValueTask<Result<byte[]>> ISecretProtector.UnprotectAsync(ReadOnlyMemory<byte> protectedData, AuthenticatedContext expectedAssociatedData, CancellationToken cancellationToken)
        {
            ReceivedProtectedData = protectedData;
            ReceivedAssociatedData = expectedAssociatedData;
            ReceivedCancellationToken = cancellationToken;
            return ValueTask.FromResult<Result<byte[]>>(ResultToReturn);
        }

        ValueTask<Result<ISecretBuffer>> ISecretProtector.UnprotectToSecretBufferAsync(ReadOnlyMemory<byte> protectedData, AuthenticatedContext expectedAssociatedData, CancellationToken cancellationToken)
        {
            ReceivedProtectedData = protectedData;
            ReceivedAssociatedData = expectedAssociatedData;
            ReceivedCancellationToken = cancellationToken;
            var buffer = new SecretBuffer(ResultToReturn.Length);
            ResultToReturn.CopyTo(buffer.GetWritableSpan());
            return ValueTask.FromResult<Result<ISecretBuffer>>(Result<ISecretBuffer>.Success(buffer));
        }

        Result<byte[]> ISecretProtector.Protect(ReadOnlySpan<byte> secret, KeyPurpose purpose, AuthenticatedContext expectedAssociatedData) => ResultToReturn;

        Result<byte[]> ISecretProtector.Unprotect(ReadOnlySpan<byte> protectedData, AuthenticatedContext expectedAssociatedData) => ResultToReturn;
    }

    [Fact]
    public void ProtectedSecret_Properties_Match()
    {
        var keyId = KeyIdentifier.New();
        var version = KeyVersion.Initial;
        byte[] payload = [10, 20, 30, 40, 50];
        var protectedSecret = new ProtectedSecret(keyId, version, payload);

        Assert.Equal(keyId, protectedSecret.KeyId);
        Assert.Equal(version, protectedSecret.KeyVersion);
        Assert.True(protectedSecret.ProtectedBytes.Span.SequenceEqual(payload));
        Assert.Equal("[REDACTED PROTECTED SECRET]", protectedSecret.ToString());
        SecurityAssert.IsRedacted(protectedSecret);
    }

    [Fact]
    public async Task ProtectedSecret_UnprotectAsync_NullProtector_ThrowsArgumentNullException()
    {
        var protectedSecret = new ProtectedSecret(KeyIdentifier.New(), KeyVersion.Initial, new byte[] { 1, 2, 3 });

        var ex = await Assert.ThrowsAsync<ArgumentNullException>(async () => await protectedSecret.UnprotectAsync(null!));
        Assert.Equal("protector", ex.ParamName);
    }

    [Fact]
    public async Task ProtectedSecret_UnprotectAsync_DelegatesWithParametersToProtector()
    {
        var keyId = KeyIdentifier.New();
        var version = KeyVersion.Initial;
        byte[] payload = [1, 2, 3, 4, 5];
        byte[] aad = [99, 88];
        var protectedSecret = new ProtectedSecret(keyId, version, payload);

        byte[] decrypted = [42, 43, 44];
        var protector = new TrackingSecretProtector { ResultToReturn = decrypted };
        using var cts = new CancellationTokenSource();
        var aadContext = AuthenticatedContext.FromBytes(aad);

        var result = await protectedSecret.UnprotectAsync(protector, aadContext, cts.Token);

        Assert.True(result.IsSuccess);
        Assert.Equal(decrypted, result.Value);
        Assert.True(protector.ReceivedProtectedData.Span.SequenceEqual(payload));
        Assert.True(protector.ReceivedAssociatedData.Span.SequenceEqual(aadContext.Span));
        Assert.Equal(cts.Token, protector.ReceivedCancellationToken);
    }
}
