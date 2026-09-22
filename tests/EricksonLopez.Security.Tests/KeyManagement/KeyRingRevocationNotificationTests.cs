// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Tests.KeyManagement;

using System;
using System.Threading.Tasks;
using AwesomeAssertions;
using EricksonLopez.Security.Abstractions.KeyManagement;
using EricksonLopez.Security.Abstractions.Primitives;
using EricksonLopez.Security.KeyManagement;
using Xunit;

/// <summary>
/// Regression and verification tests for SEC-LOW-001:
/// Real-time key revocation notification and instant KeyRing cache eviction.
/// </summary>
public sealed class KeyRingRevocationNotificationTests
{
    [Fact]
    public async Task RevokeKeyAsync_WithNotifier_ImmediatelyEvictsCachedKeyFromKeyRing()
    {
        // Arrange: KeyRing configured with a long cache TTL (60 seconds)
        var store = new InMemoryKeyStore();
        var notifier = new InProcessKeyRevocationNotifier();
        var options = new KeyRingOptions { CacheTtl = TimeSpan.FromSeconds(60) };

        using var keyRing = new KeyRing(store, options, notifier);
        var manager = new KeyLifecycleManager(store, null, false, notifier);

        // Generate and activate key in store
        var generateResult = await manager.GenerateAndActivateKeyAsync(KeyPurpose.Encryption);
        generateResult.IsSuccess.Should().BeTrue();
        var key = generateResult.Value;

        // Warm both active key and key cache in KeyRing
        var activeFirstCall = await keyRing.GetActiveKeyAsync(KeyPurpose.Encryption);
        activeFirstCall.IsSuccess.Should().BeTrue();
        activeFirstCall.Value.Metadata.KeyId.Should().Be(key.Metadata.KeyId);
        activeFirstCall.Value.Dispose();

        var keyFirstCall = await keyRing.GetKeyAsync(key.Metadata.KeyId, key.Metadata.Version);
        keyFirstCall.IsSuccess.Should().BeTrue();
        keyFirstCall.Value.Dispose();

        keyRing.ActiveKeyCacheCount.Should().Be(1);
        keyRing.KeyCacheCount.Should().Be(1);

        // Act: Revoke the key via manager. This broadcasts the revocation to the notifier.
        var revokeResult = await manager.RevokeKeyAsync(key.Metadata.KeyId, key.Metadata.Version, "Security Incident Compromise");
        revokeResult.IsSuccess.Should().BeTrue();

        // Assert: KeyRing's in-memory caches must be evicted immediately without waiting 60s
        keyRing.ActiveKeyCacheCount.Should().Be(0);
        keyRing.KeyCacheCount.Should().Be(0);

        var activeAfterRevocation = await keyRing.GetActiveKeyAsync(KeyPurpose.Encryption);
        activeAfterRevocation.IsFailure.Should().BeTrue(
            because: "revocation notification must immediately evict the active key from the local cache");

        key.Dispose();
    }

    [Fact]
    public async Task RevokeKeyAsync_WithNotifier_BroadcastsToMultipleKeyRings()
    {
        // Arrange: Multiple KeyRing instances sharing the same notifier
        var store = new InMemoryKeyStore();
        var notifier = new InProcessKeyRevocationNotifier();
        var options = new KeyRingOptions { CacheTtl = TimeSpan.FromMinutes(5) };

        using var keyRing1 = new KeyRing(store, options, notifier);
        using var keyRing2 = new KeyRing(store, options, notifier);
        var manager = new KeyLifecycleManager(store, null, false, notifier);

        var keyResult = await manager.GenerateAndActivateKeyAsync(KeyPurpose.Signing);
        keyResult.IsSuccess.Should().BeTrue();
        var key = keyResult.Value;

        // Warm caches in both key rings
        using (var k1 = (await keyRing1.GetActiveKeyAsync(KeyPurpose.Signing)).Value)
        {
            k1.Metadata.KeyId.Should().Be(key.Metadata.KeyId);
        }

        using (var k2 = (await keyRing2.GetActiveKeyAsync(KeyPurpose.Signing)).Value)
        {
            k2.Metadata.KeyId.Should().Be(key.Metadata.KeyId);
        }

        // Act: Revoke key
        var revokeResult = await manager.RevokeKeyAsync(key.Metadata.KeyId, key.Metadata.Version, "Scheduled Key Revocation");
        revokeResult.IsSuccess.Should().BeTrue();

        // Assert: Both key rings must be evicted synchronously
        var check1 = await keyRing1.GetActiveKeyAsync(KeyPurpose.Signing);
        var check2 = await keyRing2.GetActiveKeyAsync(KeyPurpose.Signing);

        check1.IsFailure.Should().BeTrue();
        check2.IsFailure.Should().BeTrue();

        key.Dispose();
    }

    [Fact]
    public async Task Manual_InvalidateKey_And_InvalidateActiveKey_EvictsCorrectly()
    {
        // Arrange
        var store = new InMemoryKeyStore();
        var options = new KeyRingOptions { CacheTtl = TimeSpan.FromMinutes(10) };
        using var keyRing = new KeyRing(store, options);
        var manager = new KeyLifecycleManager(store);

        var keyResult = await manager.GenerateAndActivateKeyAsync(KeyPurpose.TokenProtection);
        keyResult.IsSuccess.Should().BeTrue();
        var key = keyResult.Value;

        // Warm cache
        using (var k = (await keyRing.GetActiveKeyAsync(KeyPurpose.TokenProtection)).Value)
        {
            k.Metadata.KeyId.Should().Be(key.Metadata.KeyId);
        }

        // Act: Invalidate active key
        keyRing.InvalidateActiveKey(KeyPurpose.TokenProtection);

        // Update status in store to retired
        await store.UpdateStatusAsync(key.Metadata.KeyId, key.Metadata.Version, KeyStatus.Retired);

        // Assert: Next GetActiveKeyAsync hits store (since cache was cleared) and returns KeyNotFound
        var activeCheck = await keyRing.GetActiveKeyAsync(KeyPurpose.TokenProtection);
        activeCheck.IsFailure.Should().BeTrue();

        key.Dispose();
    }
}
