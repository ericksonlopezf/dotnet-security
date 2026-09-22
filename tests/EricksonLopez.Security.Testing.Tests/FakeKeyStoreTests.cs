// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Testing.Tests;

using System;
using System.Threading.Tasks;
using AwesomeAssertions;
using EricksonLopez.Result;
using EricksonLopez.Security.Abstractions.Errors;
using EricksonLopez.Security.Abstractions.KeyManagement;
using EricksonLopez.Security.Abstractions.Primitives;
using EricksonLopez.Security.Memory;
using EricksonLopez.Security.Testing.Fakes;
using Xunit;

public sealed class FakeKeyStoreTests
{
    private static CryptographicKey CreateTestKey(string id = "test-key", int version = 1, KeyPurpose purpose = KeyPurpose.Encryption)
    {
        var metadata = new KeyMetadata(
            KeyId: new KeyIdentifier(id),
            Version: new KeyVersion(version),
            Purpose: purpose,
            Status: KeyStatus.Active,
            AlgorithmId: "AES-256-GCM",
            CreatedAtUtc: DateTimeOffset.UtcNow,
            ExpiresAtUtc: DateTimeOffset.UtcNow.AddDays(30),
            RevokedAtUtc: null);

        var secretBuffer = SecretBuffer.FromSpan(new byte[32]);
        return new CryptographicKey(metadata, secretBuffer);
    }

    [Fact]
    public async Task SaveKeyAsync_And_GetKeyAsync_RoundtripsSuccessfully()
    {
        var store = new FakeKeyStore();
        using var key = CreateTestKey("k1", 1);

        var saveResult = await store.SaveKeyAsync(key);
        saveResult.IsSuccess.Should().BeTrue();
        store.Count.Should().Be(1);

        var getResult = await store.GetKeyAsync(new KeyIdentifier("k1"), new KeyVersion(1));
        getResult.IsSuccess.Should().BeTrue();
        getResult.Value.Metadata.KeyId.Value.Should().Be("k1");
        getResult.Value.Metadata.Version.Value.Should().Be(1);
    }

    [Fact]
    public async Task GetKeyAsync_NonExistentKey_ReturnsNotFound()
    {
        var store = new FakeKeyStore();

        var result = await store.GetKeyAsync(new KeyIdentifier("missing"), new KeyVersion(1));
        result.IsFailure.Should().BeTrue();
        result.Error.Description.Should().Contain("missing");
        result.Error.Description.Should().Contain("1");
    }

    [Fact]
    public async Task SaveKeyAsync_NullKey_ThrowsArgumentNullException()
    {
        var store = new FakeKeyStore();
        var act = async () => await store.SaveKeyAsync(null!);
        await act.Should().ThrowAsync<ArgumentNullException>();
    }

    [Fact]
    public async Task ListMetadataAsync_FiltersAndSortsCorrectly()
    {
        var store = new FakeKeyStore();
        using var key1 = CreateTestKey("k1", 1, KeyPurpose.Encryption);
        using var key2 = CreateTestKey("k1", 2, KeyPurpose.Encryption);
        using var key3 = CreateTestKey("k2", 1, KeyPurpose.Signing);

        await store.SaveKeyAsync(key1);
        await store.SaveKeyAsync(key2);
        await store.SaveKeyAsync(key3);

        var allResult = await store.ListMetadataAsync();
        allResult.IsSuccess.Should().BeTrue();
        allResult.Value.Count.Should().Be(3);
        allResult.Value[0].Version.Value.Should().Be(2);
        allResult.Value[1].Version.Value.Should().Be(1);

        var encResult = await store.ListMetadataAsync(KeyPurpose.Encryption);
        encResult.IsSuccess.Should().BeTrue();
        encResult.Value.Count.Should().Be(2);
        encResult.Value[0].Version.Value.Should().Be(2);
        encResult.Value[1].Version.Value.Should().Be(1);

        var signResult = await store.ListMetadataAsync(KeyPurpose.Signing);
        signResult.IsSuccess.Should().BeTrue();
        signResult.Value.Count.Should().Be(1);
    }

    [Fact]
    public async Task UpdateStatusAsync_UpdatesStatusAndRevocationTimestamp()
    {
        var store = new FakeKeyStore();
        using var key = CreateTestKey("k1", 1);
        await store.SaveKeyAsync(key);

        var updateResult = await store.UpdateStatusAsync(new KeyIdentifier("k1"), new KeyVersion(1), KeyStatus.Revoked);
        updateResult.IsSuccess.Should().BeTrue();

        var getResult = await store.GetKeyAsync(new KeyIdentifier("k1"), new KeyVersion(1));
        getResult.IsSuccess.Should().BeTrue();
        getResult.Value.Metadata.Status.Should().Be(KeyStatus.Revoked);
        getResult.Value.Metadata.RevokedAtUtc.Should().NotBeNull();
    }

    [Fact]
    public async Task UpdateStatusAsync_NonRevokedStatus_PreservesRevocationTimestamp()
    {
        var store = new FakeKeyStore();
        using var key = CreateTestKey("k1", 1);
        await store.SaveKeyAsync(key);

        var updateResult = await store.UpdateStatusAsync(new KeyIdentifier("k1"), new KeyVersion(1), KeyStatus.Retired);
        updateResult.IsSuccess.Should().BeTrue();

        var getResult = await store.GetKeyAsync(new KeyIdentifier("k1"), new KeyVersion(1));
        getResult.IsSuccess.Should().BeTrue();
        getResult.Value.Metadata.Status.Should().Be(KeyStatus.Retired);
        getResult.Value.Metadata.RevokedAtUtc.Should().BeNull();
    }

    [Fact]
    public async Task UpdateStatusAsync_NonExistentKey_ReturnsNotFound()
    {
        var store = new FakeKeyStore();

        var result = await store.UpdateStatusAsync(new KeyIdentifier("missing"), new KeyVersion(1), KeyStatus.Revoked);
        result.IsFailure.Should().BeTrue();
        result.Error.Description.Should().Contain("missing");
        result.Error.Description.Should().Contain("1");
    }

    [Fact]
    public async Task InjectedError_ForcesFailuresOnAllOperations()
    {
        var store = new FakeKeyStore
        {
            InjectedError = SecurityError.InvalidCiphertext("Injected test failure")
        };

        using var key = CreateTestKey();
        var saveResult = await store.SaveKeyAsync(key);
        saveResult.IsFailure.Should().BeTrue();
        saveResult.Error.Should().Be(store.InjectedError);

        var getResult = await store.GetKeyAsync(new KeyIdentifier("k1"), new KeyVersion(1));
        getResult.IsFailure.Should().BeTrue();
        getResult.Error.Should().Be(store.InjectedError);

        var listResult = await store.ListMetadataAsync();
        listResult.IsFailure.Should().BeTrue();
        listResult.Error.Should().Be(store.InjectedError);

        var updateResult = await store.UpdateStatusAsync(new KeyIdentifier("k1"), new KeyVersion(1), KeyStatus.Retired);
        updateResult.IsFailure.Should().BeTrue();
        updateResult.Error.Should().Be(store.InjectedError);
    }

    [Fact]
    public async Task Reset_ClearsAllKeysAndError()
    {
        var store = new FakeKeyStore();
        using var key = CreateTestKey("k1", 1);
        await store.SaveKeyAsync(key);
        store.Count.Should().Be(1);

        store.InjectedError = SecurityError.InvalidCiphertext("error");

        store.Reset();
        store.Count.Should().Be(0);
        store.InjectedError.Should().BeNull();
    }
}
