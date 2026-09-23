// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Testing.Tests;

using System;
using System.Threading.Tasks;
using AwesomeAssertions;
using EricksonLopez.Security.Abstractions.Cryptography;
using EricksonLopez.Security.Abstractions.Errors;
using EricksonLopez.Security.Abstractions.Primitives;
using EricksonLopez.Security.Testing.Fakes;
using Xunit;

public sealed class FakeSecretProtectorTests
{
    [Fact]
    public async Task ProtectAndUnprotect_Bytes_RoundtripsSuccessfully()
    {
        var protector = new FakeSecretProtector();
        byte[] original = [10, 20, 30, 40, 50];

        var protectResult = await protector.ProtectAsync(original);
        protectResult.IsSuccess.Should().BeTrue();
        protectResult.Value.Should().NotEqual(original);

        var unprotectResult = await protector.UnprotectAsync(protectResult.Value);
        unprotectResult.IsSuccess.Should().BeTrue();
        unprotectResult.Value.Should().Equal(original);
    }

    [Fact]
    public async Task ProtectAndUnprotect_WithAssociatedData_RoundtripsSuccessfully()
    {
        var protector = new FakeSecretProtector();
        byte[] secret = [1, 2, 3, 4];
        byte[] aad = [9, 8, 7];

        var aadContext = AuthenticatedContext.FromBytes(aad);

        var protectResult = await protector.ProtectAsync(secret, KeyPurpose.SecretProtection, aadContext);
        protectResult.IsSuccess.Should().BeTrue();

        var unprotectResult = await protector.UnprotectAsync(protectResult.Value, aadContext);
        unprotectResult.IsSuccess.Should().BeTrue();
        unprotectResult.Value.Should().Equal(secret);
    }

    [Fact]
    public async Task InjectedError_ReturnsFailureOnAllMethods()
    {
        var protector = new FakeSecretProtector
        {
            InjectedError = SecurityError.InvalidCiphertext("Simulated encryption failure")
        };

        byte[] data = [1, 2, 3];
        (await protector.ProtectAsync(data)).IsFailure.Should().BeTrue();
        (await protector.UnprotectAsync(data)).IsFailure.Should().BeTrue();
        protector.Protect(data).IsFailure.Should().BeTrue();
        protector.Unprotect(data).IsFailure.Should().BeTrue();
    }

    [Fact]
    public void SynchronousProtectAndUnprotect_RoundtripsSuccessfully()
    {
        var protector = new FakeSecretProtector();
        byte[] original = [10, 20, 30, 40, 50];
        byte[] aad = [1, 2, 3];

        var aadContext = AuthenticatedContext.FromBytes(aad);

        var protectResult = protector.Protect(original, KeyPurpose.SecretProtection, aadContext);
        protectResult.IsSuccess.Should().BeTrue();
        protectResult.Value.Should().NotEqual(original);

        var unprotectResult = protector.Unprotect(protectResult.Value, aadContext);
        unprotectResult.IsSuccess.Should().BeTrue();
        unprotectResult.Value.Should().Equal(original);
    }

    [Fact]
    public async Task UnprotectToSecretBufferAsync_RoundtripsSuccessfully()
    {
        var protector = new FakeSecretProtector();
        byte[] original = [10, 20, 30, 40, 50];

        var protectResult = await protector.ProtectAsync(original);
        protectResult.IsSuccess.Should().BeTrue();

        var unprotectBufferResult = await protector.UnprotectToSecretBufferAsync(protectResult.Value);
        unprotectBufferResult.IsSuccess.Should().BeTrue();
        using var buffer = unprotectBufferResult.Value;
        buffer.Length.Should().Be(original.Length);
        buffer.Span.ToArray().Should().Equal(original);
    }

    [Fact]
    public async Task UnprotectToSecretBufferAsync_WithInjectedError_ReturnsFailure()
    {
        var protector = new FakeSecretProtector
        {
            InjectedError = SecurityError.InvalidCiphertext("Simulated secret buffer unprotect failure")
        };

        byte[] data = [1, 2, 3];
        var result = await protector.UnprotectToSecretBufferAsync(data);
        result.IsFailure.Should().BeTrue();
        result.Error.Description.Should().Be("Simulated secret buffer unprotect failure");
    }
}
