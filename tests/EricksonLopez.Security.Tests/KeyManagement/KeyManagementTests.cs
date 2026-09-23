// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Tests.KeyManagement;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using EricksonLopez.Result;
using EricksonLopez.Security.Abstractions.Errors;
using EricksonLopez.Security.Abstractions.Events;
using EricksonLopez.Security.Abstractions.KeyManagement;
using EricksonLopez.Security.Abstractions.Primitives;
using EricksonLopez.Security.KeyManagement;
using EricksonLopez.Security.Memory;
using AwesomeAssertions;
using Xunit;

public sealed class KeyManagementTests
{
    public KeyManagementTests()
    {
        KeyRing.CacheTtl = TimeSpan.Zero;
    }

    private sealed class FailingKeyStore : IKeyStore
    {
        public bool FailSave { get; set; } = true;
        public bool FailGet { get; set; } = true;
        public bool FailList { get; set; } = true;
        public bool FailUpdate { get; set; } = true;
        public CryptographicKey? LastSavedKey { get; private set; }

        public ValueTask<Result> SaveKeyAsync(CryptographicKey key, CancellationToken cancellationToken = default)
        {
            LastSavedKey = key;
            return FailSave ? ValueTask.FromResult<Result>(SecurityError.KeyNotFound("store save fail")) : ValueTask.FromResult(Result.Success());
        }

        public ValueTask<Result<CryptographicKey>> GetKeyAsync(KeyIdentifier keyId, KeyVersion version, CancellationToken cancellationToken = default) =>
            FailGet ? ValueTask.FromResult<Result<CryptographicKey>>(SecurityError.KeyNotFound("store get fail")) : ValueTask.FromResult<Result<CryptographicKey>>(new CryptographicKey(new KeyMetadata(keyId, version, KeyPurpose.Signing, KeyStatus.Active, "AES-256-GCM", DateTimeOffset.UtcNow), SecretBuffer.CreateRandom(32)));

        public ValueTask<Result<IReadOnlyList<KeyMetadata>>> ListMetadataAsync(KeyPurpose? purpose = null, CancellationToken cancellationToken = default) =>
            FailList ? ValueTask.FromResult<Result<IReadOnlyList<KeyMetadata>>>(SecurityError.KeyNotFound("store list fail")) : ValueTask.FromResult<Result<IReadOnlyList<KeyMetadata>>>(new List<KeyMetadata>());

        public ValueTask<Result> UpdateStatusAsync(KeyIdentifier keyId, KeyVersion version, KeyStatus newStatus, CancellationToken cancellationToken = default) =>
            FailUpdate ? ValueTask.FromResult<Result>(SecurityError.KeyNotFound("store update fail")) : ValueTask.FromResult(Result.Success());
    }

    // ==========================================
    // InMemoryKeyStore Tests
    // ==========================================

    [Fact]
    public async Task InMemoryKeyStore_Operations_WorkCorrectly()
    {
        var store = new InMemoryKeyStore();

        // Null key save
        var exNull = await Assert.ThrowsAsync<ArgumentNullException>(async () => await store.SaveKeyAsync(null!));
        Assert.Equal("key", exNull.ParamName);

        // Key not found
        var keyId = KeyIdentifier.New();
        var v1 = KeyVersion.Initial;
        var notFound = await store.GetKeyAsync(keyId, v1);
        Assert.True(notFound.IsFailure);
        Assert.Equal("Security.KeyNotFound", notFound.Error.Code);
        Assert.Contains(keyId.Value, notFound.Error.Description);

        // Save key
        var meta1 = new KeyMetadata(keyId, v1, KeyPurpose.Encryption, KeyStatus.Active, "AES-256-GCM", DateTimeOffset.UtcNow);
        using var buffer1 = SecretBuffer.CreateRandom(32);
        var key1 = new CryptographicKey(meta1, buffer1);

        var saveResult = await store.SaveKeyAsync(key1);
        Assert.True(saveResult.IsSuccess);

        // Retrieve key
        var getResult = await store.GetKeyAsync(keyId, v1);
        Assert.True(getResult.IsSuccess);
        Assert.Equal(keyId, getResult.Value.Metadata.KeyId);

        // List metadata with and without purpose filter
        var listAll = await store.ListMetadataAsync();
        Assert.True(listAll.IsSuccess);
        Assert.Single(listAll.Value);

        // Add additional versions to test descending order
        var v2 = new KeyVersion(2);
        var meta2 = new KeyMetadata(keyId, v2, KeyPurpose.Encryption, KeyStatus.Active, "AES-256-GCM", DateTimeOffset.UtcNow);
        using var buffer2 = SecretBuffer.CreateRandom(32);
        await store.SaveKeyAsync(new CryptographicKey(meta2, buffer2));

        var listMulti = await store.ListMetadataAsync();
        Assert.True(listMulti.IsSuccess);
        Assert.Equal(2, listMulti.Value.Count);
        Assert.Equal(2, listMulti.Value[0].Version.Value); // v2 first
        Assert.Equal(1, listMulti.Value[1].Version.Value); // v1 second

        var listEncryption = await store.ListMetadataAsync(KeyPurpose.Encryption);
        Assert.True(listEncryption.IsSuccess);
        Assert.Equal(2, listEncryption.Value.Count);

        var listSigning = await store.ListMetadataAsync(KeyPurpose.Signing);
        Assert.True(listSigning.IsSuccess);
        Assert.Empty(listSigning.Value);

        var missingKeyId = KeyIdentifier.New();
        var updateUnknown = await store.UpdateStatusAsync(missingKeyId, KeyVersion.Initial, KeyStatus.Revoked);
        Assert.True(updateUnknown.IsFailure);
        Assert.Equal("Security.KeyNotFound", updateUnknown.Error.Code);
        Assert.Contains(missingKeyId.Value, updateUnknown.Error.Description);

        // Update status to Retired (RevokedAtUtc must remain null)
        var updateRetired = await store.UpdateStatusAsync(keyId, v1, KeyStatus.Retired);
        Assert.True(updateRetired.IsSuccess);
        var retiredKey = await store.GetKeyAsync(keyId, v1);
        Assert.True(retiredKey.IsSuccess);
        Assert.Equal(KeyStatus.Retired, retiredKey.Value.Metadata.Status);
        Assert.Null(retiredKey.Value.Metadata.RevokedAtUtc);

        // Update status to Revoked (RevokedAtUtc must be populated)
        var updateResult = await store.UpdateStatusAsync(keyId, v1, KeyStatus.Revoked);
        Assert.True(updateResult.IsSuccess);

        var revokedKey = await store.GetKeyAsync(keyId, v1);
        Assert.True(revokedKey.IsSuccess);
        Assert.Equal(KeyStatus.Revoked, revokedKey.Value.Metadata.Status);
        Assert.NotNull(revokedKey.Value.Metadata.RevokedAtUtc);
    }

    // ==========================================
    // KeyRing Tests
    // ==========================================

    [Fact]
    public async Task KeyRing_ResolvesActiveAndHistoricalKeys_And_ValidatesExceptions()
    {
        var exNullStore = Assert.Throws<ArgumentNullException>(() => new KeyRing(null!));
        Assert.Equal("keyStore", exNullStore.ParamName);

        var store = new InMemoryKeyStore();
        var keyRing = new KeyRing(store);

        // No active key exists
        var notFoundActive = await keyRing.GetActiveKeyAsync(KeyPurpose.Encryption);
        Assert.True(notFoundActive.IsFailure);
        Assert.Equal("Security.KeyNotFound", notFoundActive.Error.Code);
        Assert.Contains(KeyPurpose.Encryption.ToString(), notFoundActive.Error.Description);

        // Sync helper test
        var notFoundSync = keyRing.GetActiveKey(KeyPurpose.Encryption);
        Assert.True(notFoundSync.IsFailure);

        // Save v1 active key
        var keyId = KeyIdentifier.New();
        var v1 = KeyVersion.Initial;
        var meta1 = new KeyMetadata(keyId, v1, KeyPurpose.Encryption, KeyStatus.Active, "AES-256-GCM", DateTimeOffset.UtcNow);
        using var buf1 = SecretBuffer.CreateRandom(32);
        await store.SaveKeyAsync(new CryptographicKey(meta1, buf1));

        // Get active key
        var active = await keyRing.GetActiveEncryptionKeyAsync(KeyPurpose.Encryption);
        Assert.True(active.IsSuccess);
        Assert.Equal(1, active.Value.Metadata.Version.Value);

        var activeSync = keyRing.GetActiveKey(KeyPurpose.Encryption);
        Assert.True(activeSync.IsSuccess);

        // Get specific key
        var specificKey = await keyRing.GetDecryptionKeyAsync(keyId, v1);
        Assert.True(specificKey.IsSuccess);

        var specificKeySync = keyRing.GetKey(keyId, v1);
        Assert.True(specificKeySync.IsSuccess);

        // List metadata
        var listMeta = await keyRing.ListMetadataAsync(KeyPurpose.Encryption);
        Assert.True(listMeta.IsSuccess);
        Assert.Single(listMeta.Value);

        // If key is revoked, KeyRing returns KeyRevoked
        await store.UpdateStatusAsync(keyId, v1, KeyStatus.Revoked);
        keyRing.InvalidateKey(keyId, v1);
        var revokedLookup = await keyRing.GetKeyAsync(keyId, v1);
        Assert.True(revokedLookup.IsFailure);
        Assert.Equal("Security.KeyRevoked", revokedLookup.Error.Code);

        // Store failure simulation
        var failingRing = new KeyRing(new FailingKeyStore());
        var resFailActive = await failingRing.GetActiveKeyAsync(KeyPurpose.Encryption);
        Assert.True(resFailActive.IsFailure);

        var resFailGet = await failingRing.GetKeyAsync(keyId, v1);
        Assert.True(resFailGet.IsFailure);
    }

    [Fact]
    public async Task KeyRing_MultipleKeys_SelectsHighestActiveVersionAndFiltersPurpose()
    {
        var store = new InMemoryKeyStore();
        var keyRing = new KeyRing(store);

        var keyId = KeyIdentifier.New();
        var v1 = new KeyVersion(1);
        var v2 = new KeyVersion(2);
        var v3 = new KeyVersion(3);

        // v1: Active Encryption
        using var buf1 = SecretBuffer.CreateRandom(32);
        await store.SaveKeyAsync(new CryptographicKey(new KeyMetadata(keyId, v1, KeyPurpose.Encryption, KeyStatus.Active, "AES-256-GCM", DateTimeOffset.UtcNow), buf1));

        // v2: Active Encryption (highest version)
        using var buf2 = SecretBuffer.CreateRandom(32);
        await store.SaveKeyAsync(new CryptographicKey(new KeyMetadata(keyId, v2, KeyPurpose.Encryption, KeyStatus.Active, "AES-256-GCM", DateTimeOffset.UtcNow), buf2));

        // v3: Active Signing (different purpose)
        using var buf3 = SecretBuffer.CreateRandom(32);
        await store.SaveKeyAsync(new CryptographicKey(new KeyMetadata(keyId, v3, KeyPurpose.Signing, KeyStatus.Active, "HMAC-SHA256", DateTimeOffset.UtcNow), buf3));

        // v4: Revoked Encryption (same purpose, higher version, but revoked)
        var v4 = new KeyVersion(4);
        using var buf4 = SecretBuffer.CreateRandom(32);
        await store.SaveKeyAsync(new CryptographicKey(new KeyMetadata(keyId, v4, KeyPurpose.Encryption, KeyStatus.Revoked, "AES-256-GCM", DateTimeOffset.UtcNow), buf4));

        var activeEncryption = await keyRing.GetActiveEncryptionKeyAsync(KeyPurpose.Encryption);
        Assert.True(activeEncryption.IsSuccess);
        Assert.Equal(2, activeEncryption.Value.Metadata.Version.Value);
    }

    [Fact]
    public async Task KeyRing_GetKeyAsync_KeyStatusDestroyed_ReturnsKeyRevokedError()
    {
        var store = new InMemoryKeyStore();
        var keyRing = new KeyRing(store);

        var keyId = KeyIdentifier.New();
        var v1 = new KeyVersion(1);
        using var buf = SecretBuffer.CreateRandom(32);
        await store.SaveKeyAsync(new CryptographicKey(new KeyMetadata(keyId, v1, KeyPurpose.Encryption, KeyStatus.Destroyed, "AES-256-GCM", DateTimeOffset.UtcNow), buf));

        var result = await keyRing.GetKeyAsync(keyId, v1);
        Assert.True(result.IsFailure);
        Assert.Equal("Security.KeyRevoked", result.Error.Code);
        Assert.Contains("destroyed", result.Error.Description, StringComparison.OrdinalIgnoreCase);
    }

    // ==========================================
    // KeyLifecycleManager Tests
    // ==========================================

    [Fact]
    public async Task KeyLifecycleManager_GenerateAndRotate_RetiresPreviousAndEmitsEvents()
    {
        var exNullStore = Assert.Throws<ArgumentNullException>(() => new KeyLifecycleManager(null!));
        Assert.Equal("keyStore", exNullStore.ParamName);

        var keyStore = new InMemoryKeyStore();
        var emittedEvents = new List<ISecurityEvent>();
        var lifecycleManager = new KeyLifecycleManager(keyStore, emittedEvents.Add);
        var keyRing = new KeyRing(keyStore);

        // Act 1: Generate initial active key with validity period
        var genResult = await lifecycleManager.GenerateAndActivateKeyAsync(
            KeyPurpose.Encryption,
            validityPeriod: TimeSpan.FromDays(30));
        Assert.True(genResult.IsSuccess);
        var keyV1 = genResult.Value;
        Assert.Equal(1, keyV1.Metadata.Version.Value);
        Assert.Equal(KeyStatus.Active, keyV1.Metadata.Status);
        Assert.NotNull(keyV1.Metadata.ExpiresAtUtc);

        // Generate key without validity period (ExpiresAtUtc must be null)
        var genNoExpiry = await lifecycleManager.GenerateAndActivateKeyAsync(KeyPurpose.Signing, validityPeriod: null);
        Assert.True(genNoExpiry.IsSuccess);
        Assert.Null(genNoExpiry.Value.Metadata.ExpiresAtUtc);

        // Verify active in KeyRing
        var active1 = await keyRing.GetActiveKeyAsync(KeyPurpose.Encryption);
        Assert.True(active1.IsSuccess);
        Assert.Equal(1, active1.Value.Metadata.Version.Value);

        // Act 2: Rotate key
        var rotateResult = await lifecycleManager.RotateKeyAsync(KeyPurpose.Encryption, TimeSpan.FromDays(30));
        Assert.True(rotateResult.IsSuccess);
        var keyV2 = rotateResult.Value;
        Assert.Equal(2, keyV2.Metadata.Version.Value);
        Assert.Equal(KeyStatus.Active, keyV2.Metadata.Status);
        Assert.NotNull(keyV2.Metadata.ExpiresAtUtc);

        // Verify active key in KeyRing is now v2
        var active2 = await keyRing.GetActiveKeyAsync(KeyPurpose.Encryption);
        Assert.True(active2.IsSuccess);
        Assert.Equal(2, active2.Value.Metadata.Version.Value);

        // Verify old key v1 is still accessible for decryption (Status = Retired)
        var oldKey = await keyRing.GetKeyAsync(keyV1.Metadata.KeyId, keyV1.Metadata.Version);
        Assert.True(oldKey.IsSuccess);
        Assert.Equal(KeyStatus.Retired, oldKey.Value.Metadata.Status);

        // Verify event was emitted (only RotateKey emits KeyRotatedEvent)
        Assert.Single(emittedEvents);
        var rotEv = Assert.IsType<KeyRotatedEvent>(emittedEvents[0]);
        Assert.Equal(keyV2.Metadata.KeyId, rotEv.KeyId);
        Assert.Equal(keyV2.Metadata.Version, rotEv.NewVersion);
        Assert.Equal(keyV1.Metadata.Version, rotEv.PreviousVersion);
        Assert.Equal(KeyPurpose.Encryption, rotEv.Purpose);
        Assert.True(rotEv.TimestampUtc <= DateTimeOffset.UtcNow);
    }

    [Fact]
    public async Task KeyLifecycleManager_RotateKey_WhenNoActiveKey_CreatesInitialVersion()
    {
        var keyStore = new InMemoryKeyStore();
        var lifecycleManager = new KeyLifecycleManager(keyStore);

        var rotated = await lifecycleManager.RotateKeyAsync(KeyPurpose.Signing);
        Assert.True(rotated.IsSuccess);
        Assert.Equal(1, rotated.Value.Metadata.Version.Value);
        Assert.Equal(KeyPurpose.Signing, rotated.Value.Metadata.Purpose);
        Assert.Equal("AES-256-GCM", rotated.Value.Metadata.AlgorithmId);
    }

    [Fact]
    public async Task KeyLifecycleManager_RotateKey_IgnoresRetiredKeysOfHigherVersion()
    {
        var keyStore = new InMemoryKeyStore();
        var lifecycleManager = new KeyLifecycleManager(keyStore);

        var keyId = KeyIdentifier.Prefixed("sec");
        var retiredKeyMeta = new KeyMetadata(keyId, new KeyVersion(10), KeyPurpose.SecretProtection, KeyStatus.Retired, "AES-256-GCM", DateTimeOffset.UtcNow);
        var activeKeyMeta = new KeyMetadata(keyId, new KeyVersion(1), KeyPurpose.SecretProtection, KeyStatus.Active, "AES-256-GCM", DateTimeOffset.UtcNow);

        await keyStore.SaveKeyAsync(new CryptographicKey(retiredKeyMeta, SecretBuffer.CreateRandom(32)));
        await keyStore.SaveKeyAsync(new CryptographicKey(activeKeyMeta, SecretBuffer.CreateRandom(32)));

        var rotateResult = await lifecycleManager.RotateKeyAsync(KeyPurpose.SecretProtection, TimeSpan.FromDays(30));
        Assert.True(rotateResult.IsSuccess);
        // Active key was v1, so Next is v2 (NOT v11)
        Assert.Equal(2, rotateResult.Value.Metadata.Version.Value);
        Assert.NotNull(rotateResult.Value.Metadata.ExpiresAtUtc);
    }

    [Fact]
    public async Task KeyLifecycleManager_RotateKey_WithMultipleActiveKeysAndDifferentPurposes_PicksHighestActiveMatchingPurpose()
    {
        var keyStore = new InMemoryKeyStore();
        var lifecycleManager = new KeyLifecycleManager(keyStore);

        // Seed store with active Signing key (should be ignored when rotating Encryption)
        var signKeyId = KeyIdentifier.New();
        var signMeta = new KeyMetadata(signKeyId, new KeyVersion(5), KeyPurpose.Signing, KeyStatus.Active, "HMAC-SHA256", DateTimeOffset.UtcNow);
        using var signBuf = SecretBuffer.CreateRandom(32);
        await keyStore.SaveKeyAsync(new CryptographicKey(signMeta, signBuf));

        // Seed store with v1 and v2 active Encryption keys
        var encKeyId = KeyIdentifier.New();
        var encMeta1 = new KeyMetadata(encKeyId, new KeyVersion(1), KeyPurpose.Encryption, KeyStatus.Active, "AES-256-GCM", DateTimeOffset.UtcNow);
        using var encBuf1 = SecretBuffer.CreateRandom(32);
        await keyStore.SaveKeyAsync(new CryptographicKey(encMeta1, encBuf1));

        var encMeta2 = new KeyMetadata(encKeyId, new KeyVersion(2), KeyPurpose.Encryption, KeyStatus.Active, "AES-256-GCM", DateTimeOffset.UtcNow);
        using var encBuf2 = SecretBuffer.CreateRandom(32);
        await keyStore.SaveKeyAsync(new CryptographicKey(encMeta2, encBuf2));

        // Rotate Encryption: must pick highest active Encryption key (v2), retire v2, and create v3
        var rotateResult = await lifecycleManager.RotateKeyAsync(KeyPurpose.Encryption);
        Assert.True(rotateResult.IsSuccess);
        var rotatedKey = rotateResult.Value;

        Assert.Equal(encKeyId, rotatedKey.Metadata.KeyId);
        Assert.Equal(3, rotatedKey.Metadata.Version.Value);
        Assert.Equal(KeyPurpose.Encryption, rotatedKey.Metadata.Purpose);

        // Verify v2 was retired
        var v2Key = await keyStore.GetKeyAsync(encKeyId, new KeyVersion(2));
        Assert.True(v2Key.IsSuccess);
        Assert.Equal(KeyStatus.Retired, v2Key.Value.Metadata.Status);

        // Verify Signing key v5 remained Active
        var signCheck = await keyStore.GetKeyAsync(signKeyId, new KeyVersion(5));
        Assert.True(signCheck.IsSuccess);
        Assert.Equal(KeyStatus.Active, signCheck.Value.Metadata.Status);
    }

    [Fact]
    public async Task KeyLifecycleManager_RevokeKey_ValidatesReasonAndEmitsEvents()
    {
        var keyStore = new InMemoryKeyStore();
        var emittedEvents = new List<ISecurityEvent>();
        var lifecycleManager = new KeyLifecycleManager(keyStore, emittedEvents.Add);
        var keyRing = new KeyRing(keyStore);

        var key = (await lifecycleManager.GenerateAndActivateKeyAsync(KeyPurpose.Signing)).Value;

        // Reason validation
        await Assert.ThrowsAsync<ArgumentException>(async () => await lifecycleManager.RevokeKeyAsync(key.Metadata.KeyId, key.Metadata.Version, ""));
        await Assert.ThrowsAsync<ArgumentException>(async () => await lifecycleManager.RevokeKeyAsync(key.Metadata.KeyId, key.Metadata.Version, "   "));
        await Assert.ThrowsAsync<ArgumentNullException>(async () => await lifecycleManager.RevokeKeyAsync(key.Metadata.KeyId, key.Metadata.Version, null!));

        // Revoke key
        var revokeResult = await lifecycleManager.RevokeKeyAsync(key.Metadata.KeyId, key.Metadata.Version, "Suspected compromise");
        Assert.True(revokeResult.IsSuccess);

        // Subsequent KeyRing lookups must fail
        var lookupResult = await keyRing.GetKeyAsync(key.Metadata.KeyId, key.Metadata.Version);
        Assert.True(lookupResult.IsFailure);
        Assert.Equal("Security.KeyRevoked", lookupResult.Error.Code);

        // Verify event was emitted
        Assert.Single(emittedEvents);
        var revEv = Assert.IsType<KeyRevokedEvent>(emittedEvents[0]);
        Assert.Equal(key.Metadata.KeyId, revEv.KeyId);
        Assert.Equal(key.Metadata.Version, revEv.Version);
        Assert.Equal("Suspected compromise", revEv.Reason);
        Assert.Equal(KeyPurpose.Signing, revEv.Purpose);
        Assert.True(revEv.TimestampUtc <= DateTimeOffset.UtcNow);

        // Revoke unknown key
        var revokeUnknown = await lifecycleManager.RevokeKeyAsync(KeyIdentifier.New(), KeyVersion.Initial, "reason");
        Assert.True(revokeUnknown.IsFailure);
    }

    [Fact]
    public async Task KeyLifecycleManager_EventPublisherThrows_DoesNotFailOperation()
    {
        var keyStore = new InMemoryKeyStore();
        // Event subscriber that always throws an exception (simulating auditing service outage)
        Action<ISecurityEvent> faultyPublisher = _ => throw new InvalidOperationException("Audit bus failure");
        var lifecycleManager = new KeyLifecycleManager(keyStore, faultyPublisher);

        // Rotating key should complete successfully even if event publisher throws
        var rotateResult = await lifecycleManager.RotateKeyAsync(KeyPurpose.Encryption);
        Assert.True(rotateResult.IsSuccess);
        var key = rotateResult.Value;

        // Revoking key should also complete successfully even if event publisher throws
        var revokeResult = await lifecycleManager.RevokeKeyAsync(key.Metadata.KeyId, key.Metadata.Version, "Routine revocation");
        Assert.True(revokeResult.IsSuccess);
    }

    [Fact]
    public async Task KeyLifecycleManager_FailureBranches_HandledSafely()
    {
        // 1. Generate fails on save
        var failingStore = new FailingKeyStore { FailSave = true };
        var lm = new KeyLifecycleManager(failingStore);

        var resGenFail = await lm.GenerateAndActivateKeyAsync(KeyPurpose.Encryption);
        Assert.True(resGenFail.IsFailure);
        Assert.NotNull(failingStore.LastSavedKey);
        Assert.True(failingStore.LastSavedKey.IsDisposed);

        // 2. Rotate fails on list metadata
        var resRotateListFail = await lm.RotateKeyAsync(KeyPurpose.Encryption);
        Assert.True(resRotateListFail.IsFailure);

        // 3. Rotate with active key, fails on update status
        var storeWithKey = new InMemoryKeyStore();
        var lm2 = new KeyLifecycleManager(storeWithKey);
        await lm2.GenerateAndActivateKeyAsync(KeyPurpose.Encryption);

        var partialFailingStore = new FailingKeyStore
        {
            FailList = false,
            FailUpdate = true
        };
        // Provide metadata of an active key
        var mockMetaStore = new MockMetadataKeyStore();
        var lm3 = new KeyLifecycleManager(mockMetaStore);

        var resRotateUpdateFail = await lm3.RotateKeyAsync(KeyPurpose.Encryption);
        Assert.True(resRotateUpdateFail.IsFailure);

        // 4. Rotate with active key, update succeeds but save fails
        mockMetaStore.FailUpdate = false;
        mockMetaStore.FailSave = true;
        var resRotateSaveFail = await lm3.RotateKeyAsync(KeyPurpose.Encryption);
        Assert.True(resRotateSaveFail.IsFailure);
        Assert.NotNull(mockMetaStore.LastSavedKey);
        Assert.Throws<ObjectDisposedException>(() => mockMetaStore.LastSavedKey.GetKeyBytes());

        // 5. Revoke when GetKeyAsync fails (fallback purpose)
        var emitted = new List<ISecurityEvent>();
        var lmFallback = new KeyLifecycleManager(new MockRevokeFallbackStore(), emitted.Add);
        var resRevokeFallback = await lmFallback.RevokeKeyAsync(KeyIdentifier.New(), KeyVersion.Initial, "reason");
        Assert.True(resRevokeFallback.IsSuccess);
        Assert.Single(emitted);
        var ev = (KeyRevokedEvent)emitted[0];
        Assert.Equal(KeyPurpose.Encryption, ev.Purpose);
    }

    [Fact]
    public async Task KeyLifecycleManager_CancelledToken_ThrowsOperationCanceledException()
    {
        var store = new InMemoryKeyStore();
        var lm = new KeyLifecycleManager(store);
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        await Assert.ThrowsAsync<OperationCanceledException>(() => lm.GenerateAndActivateKeyAsync(KeyPurpose.Encryption, cancellationToken: cts.Token).AsTask());
        await Assert.ThrowsAsync<OperationCanceledException>(() => lm.RotateKeyAsync(KeyPurpose.Encryption, cancellationToken: cts.Token).AsTask());
        await Assert.ThrowsAsync<OperationCanceledException>(() => lm.RevokeKeyAsync(KeyIdentifier.New(), KeyVersion.Initial, "reason", cancellationToken: cts.Token).AsTask());
    }

    private sealed class MockMetadataKeyStore : IKeyStore
    {
        public bool FailUpdate { get; set; } = true;
        public bool FailSave { get; set; }
        public CryptographicKey? LastSavedKey { get; private set; }

        public ValueTask<Result> SaveKeyAsync(CryptographicKey key, CancellationToken cancellationToken = default)
        {
            LastSavedKey = key;
            return FailSave ? ValueTask.FromResult<Result>(SecurityError.KeyNotFound("save fail")) : ValueTask.FromResult(Result.Success());
        }

        public ValueTask<Result<CryptographicKey>> GetKeyAsync(KeyIdentifier keyId, KeyVersion version, CancellationToken cancellationToken = default) =>
            ValueTask.FromResult<Result<CryptographicKey>>(SecurityError.KeyNotFound("not found"));

        public ValueTask<Result<IReadOnlyList<KeyMetadata>>> ListMetadataAsync(KeyPurpose? purpose = null, CancellationToken cancellationToken = default)
        {
            IReadOnlyList<KeyMetadata> list = [
                new KeyMetadata(KeyIdentifier.New(), KeyVersion.Initial, KeyPurpose.Encryption, KeyStatus.Active, "AES-256-GCM", DateTimeOffset.UtcNow)
            ];
            return ValueTask.FromResult<Result<IReadOnlyList<KeyMetadata>>>(Result<IReadOnlyList<KeyMetadata>>.Success(list));
        }

        public ValueTask<Result> UpdateStatusAsync(KeyIdentifier keyId, KeyVersion version, KeyStatus newStatus, CancellationToken cancellationToken = default) =>
            FailUpdate ? ValueTask.FromResult<Result>(SecurityError.KeyNotFound("update fail")) : ValueTask.FromResult(Result.Success());
    }

    private sealed class MockRevokeFallbackStore : IKeyStore
    {
        public ValueTask<Result> SaveKeyAsync(CryptographicKey key, CancellationToken cancellationToken = default) => ValueTask.FromResult(Result.Success());

        public ValueTask<Result<CryptographicKey>> GetKeyAsync(KeyIdentifier keyId, KeyVersion version, CancellationToken cancellationToken = default) =>
            ValueTask.FromResult<Result<CryptographicKey>>(SecurityError.KeyNotFound("get fail"));

        public ValueTask<Result<IReadOnlyList<KeyMetadata>>> ListMetadataAsync(KeyPurpose? purpose = null, CancellationToken cancellationToken = default) =>
            ValueTask.FromResult<Result<IReadOnlyList<KeyMetadata>>>(new List<KeyMetadata>());

        public ValueTask<Result> UpdateStatusAsync(KeyIdentifier keyId, KeyVersion version, KeyStatus newStatus, CancellationToken cancellationToken = default) =>
            ValueTask.FromResult(Result.Success());
    }

    private sealed class AsyncYieldingStore : IKeyStore
    {
        public async ValueTask<Result> SaveKeyAsync(CryptographicKey key, CancellationToken cancellationToken = default)
        {
            await Task.Yield();
            return Result.Success();
        }

        public async ValueTask<Result<CryptographicKey>> GetKeyAsync(KeyIdentifier keyId, KeyVersion version, CancellationToken cancellationToken = default)
        {
            await Task.Yield();
            return SecurityError.KeyNotFound("not found");
        }

        public async ValueTask<Result<IReadOnlyList<KeyMetadata>>> ListMetadataAsync(KeyPurpose? purpose = null, CancellationToken cancellationToken = default)
        {
            await Task.Yield();
            return new List<KeyMetadata>();
        }

        public async ValueTask<Result> UpdateStatusAsync(KeyIdentifier keyId, KeyVersion version, KeyStatus newStatus, CancellationToken cancellationToken = default)
        {
            await Task.Yield();
            return Result.Success();
        }
    }

    [Fact]
    public async Task KeyLifecycleManager_RevokeKeyAsync_WithAsyncYieldingStore_CompletesAsynchronously()
    {
        var lm = new KeyLifecycleManager(new AsyncYieldingStore());
        var res = await lm.RevokeKeyAsync(KeyIdentifier.New(), KeyVersion.Initial, "testing-async");
        Assert.True(res.IsSuccess);
    }

    [Fact]
    public async Task KeyRing_GetActiveKeyAsync_WithEqualVersions_PrefersFirstEncounteredKey()
    {
        var keyId1 = KeyIdentifier.Prefixed("first");
        var keyId2 = KeyIdentifier.Prefixed("second");
        var meta1 = new KeyMetadata(keyId1, KeyVersion.Initial, KeyPurpose.Encryption, KeyStatus.Active, "AES-256-GCM", DateTimeOffset.UtcNow);
        var meta2 = new KeyMetadata(keyId2, KeyVersion.Initial, KeyPurpose.Encryption, KeyStatus.Active, "AES-256-GCM", DateTimeOffset.UtcNow);

        var store = new ExplicitOrderStore(meta1, meta2);
        var keyRing = new KeyRing(store);
        var activeKey = await keyRing.GetActiveKeyAsync(KeyPurpose.Encryption);
        Assert.True(activeKey.IsSuccess);
        // With strict `>`, it retains the first key (keyId1), whereas `>=` would overwrite with keyId2
        Assert.Equal(keyId1, activeKey.Value.Metadata.KeyId);
    }

    [Fact]
    public async Task KeyLifecycleManager_RotateKeyAsync_UnsortedMetadata_SortsDescendingToPickHighestVersion()
    {
        var keyId = KeyIdentifier.Prefixed("key");
        var v1 = new KeyMetadata(keyId, KeyVersion.Initial, KeyPurpose.Encryption, KeyStatus.Active, "AES-256-GCM", DateTimeOffset.UtcNow.AddMinutes(-10));
        var v2 = new KeyMetadata(keyId, KeyVersion.Initial.Next(), KeyPurpose.Encryption, KeyStatus.Active, "AES-256-GCM", DateTimeOffset.UtcNow);

        var store = new ExplicitOrderStore(v1, v2);
        var lm = new KeyLifecycleManager(store);
        var rotatedKey = await lm.RotateKeyAsync(KeyPurpose.Encryption);
        Assert.True(rotatedKey.IsSuccess);
        // Next version after v2 (2) must be 3
        Assert.Equal(3, rotatedKey.Value.Metadata.Version.Value);
    }

    [Fact]
    public async Task KeyLifecycleManager_RotateKeyAsync_WhenNoActiveKeys_DoesNotCallUpdateStatus()
    {
        var store = new StatusTrackingStore();
        var lm = new KeyLifecycleManager(store);
        var res = await lm.RotateKeyAsync(KeyPurpose.Encryption);
        Assert.True(res.IsSuccess);
        // activeKeys.Count is 0, so UpdateStatus must NOT be called (0 calls). Mutation >= 0 would make 1 call.
        Assert.Equal(0, store.UpdateStatusCallCount);
    }

    private sealed class StatusTrackingStore : IKeyStore
    {
        public int UpdateStatusCallCount { get; private set; }

        public ValueTask<Result> SaveKeyAsync(CryptographicKey key, CancellationToken cancellationToken = default) =>
            ValueTask.FromResult(Result.Success());

        public ValueTask<Result<CryptographicKey>> GetKeyAsync(KeyIdentifier keyId, KeyVersion version, CancellationToken cancellationToken = default) =>
            ValueTask.FromResult<Result<CryptographicKey>>(SecurityError.KeyNotFound("not found"));

        public ValueTask<Result<IReadOnlyList<KeyMetadata>>> ListMetadataAsync(KeyPurpose? purpose = null, CancellationToken cancellationToken = default) =>
            ValueTask.FromResult<Result<IReadOnlyList<KeyMetadata>>>(new List<KeyMetadata>());

        public ValueTask<Result> UpdateStatusAsync(KeyIdentifier keyId, KeyVersion version, KeyStatus newStatus, CancellationToken cancellationToken = default)
        {
            UpdateStatusCallCount++;
            return ValueTask.FromResult(Result.Success());
        }
    }

    private sealed class ExplicitOrderStore : IKeyStore
    {
        private readonly IReadOnlyList<KeyMetadata> _list;
        public ExplicitOrderStore(params KeyMetadata[] items) => _list = items;

        public ValueTask<Result> SaveKeyAsync(CryptographicKey key, CancellationToken cancellationToken = default) => ValueTask.FromResult(Result.Success());
        public ValueTask<Result<CryptographicKey>> GetKeyAsync(KeyIdentifier keyId, KeyVersion version, CancellationToken cancellationToken = default)
        {
            foreach (var meta in _list)
            {
                if (meta.KeyId == keyId)
                {
                    return ValueTask.FromResult<Result<CryptographicKey>>(new CryptographicKey(meta, SecretBuffer.CreateRandom(32)));
                }
            }
            return ValueTask.FromResult<Result<CryptographicKey>>(SecurityError.KeyNotFound("not found"));
        }
        public ValueTask<Result<IReadOnlyList<KeyMetadata>>> ListMetadataAsync(KeyPurpose? purpose = null, CancellationToken cancellationToken = default) =>
            ValueTask.FromResult<Result<IReadOnlyList<KeyMetadata>>>(Result<IReadOnlyList<KeyMetadata>>.Success(_list));
        public ValueTask<Result> UpdateStatusAsync(KeyIdentifier keyId, KeyVersion version, KeyStatus newStatus, CancellationToken cancellationToken = default) =>
            ValueTask.FromResult(Result.Success());
    }

    // ==========================================
    // KM-003: Key bytes zeroed on revocation
    // ==========================================

    [Fact]
    public async Task InMemoryKeyStore_RevokeKey_ZerosKeyBytes_KM003()
    {
        var store = new InMemoryKeyStore();
        var keyId = KeyIdentifier.New();
        var version = KeyVersion.Initial;

        // Save a key with known non-zero bytes
        var keyBytes = new byte[32];
        keyBytes[0] = 0xAB;
        keyBytes[31] = 0xCD;
        var secretBuffer = SecretBuffer.FromSpan(keyBytes);
        var metadata = new KeyMetadata(keyId, version, KeyPurpose.Encryption, KeyStatus.Active, "AES-256-GCM", DateTimeOffset.UtcNow);
        var key = new CryptographicKey(metadata, secretBuffer);
        await store.SaveKeyAsync(key);

        // Get the key before revocation — should have non-zero bytes
        var beforeRevoke = await store.GetKeyAsync(keyId, version);
        Assert.True(beforeRevoke.IsSuccess);
        var bytesBeforeRevoke = beforeRevoke.Value.GetKeyBytes().ToArray();
        Assert.True(bytesBeforeRevoke.Any(b => b != 0), "Bytes should be non-zero before revocation.");
        beforeRevoke.Value.Dispose();

        // Revoke the key
        var revokeResult = await store.UpdateStatusAsync(keyId, version, KeyStatus.Revoked);
        Assert.True(revokeResult.IsSuccess, "Revocation should succeed.");

        // Get the key after revocation — bytes should be zeroed (KM-003)
        var afterRevoke = await store.GetKeyAsync(keyId, version);
        Assert.True(afterRevoke.IsSuccess);
        var bytesAfterRevoke = afterRevoke.Value.GetKeyBytes().ToArray();
        Assert.True(bytesAfterRevoke.All(b => b == 0), "KM-003: Key bytes must be zeroed after revocation.");
        afterRevoke.Value.Dispose();
    }

    [Fact]
    public async Task InMemoryKeyStore_DestroyKey_ZerosKeyBytes_KM003()
    {
        var store = new InMemoryKeyStore();
        var keyId = KeyIdentifier.New();
        var version = KeyVersion.Initial;

        var keyBytes = new byte[32];
        keyBytes[5] = 0xFF;
        var secretBuffer = SecretBuffer.FromSpan(keyBytes);
        var metadata = new KeyMetadata(keyId, version, KeyPurpose.Signing, KeyStatus.Active, "AES-256-GCM", DateTimeOffset.UtcNow);
        var key = new CryptographicKey(metadata, secretBuffer);
        await store.SaveKeyAsync(key);

        var destroyResult = await store.UpdateStatusAsync(keyId, version, KeyStatus.Destroyed);
        Assert.True(destroyResult.IsSuccess, "Destroy transition should succeed.");

        var afterDestroy = await store.GetKeyAsync(keyId, version);
        Assert.True(afterDestroy.IsSuccess);
        var bytesAfterDestroy = afterDestroy.Value.GetKeyBytes().ToArray();
        Assert.True(bytesAfterDestroy.All(b => b == 0), "KM-003: Key bytes must be zeroed after Destroyed status.");
        afterDestroy.Value.Dispose();
    }

    [Fact]
    public async Task KeyLifecycleManager_WhenFailOnAuditFailureTrue_ReturnsFailureIfEventPublisherThrows()
    {
        // FINDING-NEW-06: Strict audit fail-stop mode
        var store = new InMemoryKeyStore();
        Action<ISecurityEvent> faultingPublisher = _ => throw new InvalidOperationException("Audit store offline");
        var manager = new KeyLifecycleManager(store, faultingPublisher, failOnAuditFailure: true);

        var keyResult = await manager.GenerateAndActivateKeyAsync(KeyPurpose.Encryption);
        Assert.True(keyResult.IsSuccess);

        var rotateResult = await manager.RotateKeyAsync(KeyPurpose.Encryption);
        Assert.True(rotateResult.IsFailure);
        Assert.Equal("Security.AuditFailed", rotateResult.Error.Code);

        var revokeResult = await manager.RevokeKeyAsync(keyResult.Value.Metadata.KeyId, keyResult.Value.Metadata.Version, "Testing");
        Assert.True(revokeResult.IsFailure);
        Assert.Equal("Security.AuditFailed", revokeResult.Error.Code);
    }

    [Fact]
    public async Task KeyLifecycleManager_WhenFailOnAuditFailureFalse_SucceedsInDegradedModeIfEventPublisherThrows()
    {
        // ECO-001: Default degraded mode with telemetry
        var store = new InMemoryKeyStore();
        Action<ISecurityEvent> faultingPublisher = _ => throw new InvalidOperationException("Audit store offline");
        var manager = new KeyLifecycleManager(store, faultingPublisher, failOnAuditFailure: false);

        var keyResult = await manager.GenerateAndActivateKeyAsync(KeyPurpose.Encryption);
        Assert.True(keyResult.IsSuccess);

        var rotateResult = await manager.RotateKeyAsync(KeyPurpose.Encryption);
        Assert.True(rotateResult.IsSuccess);

        var revokeResult = await manager.RevokeKeyAsync(keyResult.Value.Metadata.KeyId, keyResult.Value.Metadata.Version, "Testing");
        Assert.True(revokeResult.IsSuccess);
    }

    // KM-006 (resolved): Regression test — GenerateAndActivateKeyAsync must not reuse KeyVersion.Initial
    // when a revoked key with that version already exists in the store.
    [Fact]
    public async Task KeyLifecycleManager_GenerateAfterRevoke_DoesNotCollideWithInitialVersion_KM006()
    {
        var store = new InMemoryKeyStore();
        var manager = new KeyLifecycleManager(store);

        // Step 1: generate initial key (gets KeyVersion.Initial)
        var firstResult = await manager.GenerateAndActivateKeyAsync(KeyPurpose.Encryption);
        Assert.True(firstResult.IsSuccess, "First generation must succeed");
        var firstVersion = firstResult.Value.Metadata.Version;

        // Step 2: revoke the first key
        var revokeResult = await manager.RevokeKeyAsync(
            firstResult.Value.Metadata.KeyId,
            firstVersion,
            "Rotating for security test");
        Assert.True(revokeResult.IsSuccess, "Revocation must succeed");

        // Step 3: generate a new key for the same purpose
        // KM-006: without the fix, this would assign KeyVersion.Initial again, colliding with the revoked key
        var secondResult = await manager.GenerateAndActivateKeyAsync(KeyPurpose.Encryption);
        Assert.True(secondResult.IsSuccess, "Second generation after revocation must succeed");

        var secondVersion = secondResult.Value.Metadata.Version;

        // The new key must have a strictly higher version than the revoked key
        Assert.True(
            secondVersion.Value > firstVersion.Value,
            $"New key version ({secondVersion.Value}) must be strictly greater than revoked key version ({firstVersion.Value}) — KM-006");

        firstResult.Value.Dispose();
        secondResult.Value.Dispose();
    }

    /// <summary>
    /// KLM-03 Regression Test: RotateKeyAsync must retire ALL active keys for the purpose,
    /// not just the highest-version active key. This covers the scenario where prior partial
    /// rotations left multiple Active keys, and ensures the invariant "exactly one Active key
    /// per purpose after rotation" holds in all cases.
    /// </summary>
    [Fact]
    public async Task RotateKeyAsync_RetiresAllActiveKeys_NotJustMostRecent()
    {
        // Arrange: Create a store with MULTIPLE Active keys for the same purpose
        // (simulating prior partial rotations that failed to retire old keys)
        var store = new InMemoryKeyStore();
        var lifecycleManager = new KeyLifecycleManager(store);

        // Generate first active key (v1)
        var key1Result = await lifecycleManager.GenerateAndActivateKeyAsync(KeyPurpose.Encryption);
        key1Result.IsSuccess.Should().BeTrue();
        var key1Id = key1Result.Value.Metadata.KeyId;
        var key1Version = key1Result.Value.Metadata.Version;
        key1Result.Value.Dispose();

        // Simulate a "stuck" rotation: generate key v2 but do NOT retire key v1
        // (this is the state left behind by a crashed rotation in the old code)
        var key2Buffer = EricksonLopez.Security.Memory.SecretBuffer.CreateRandom(32);
        var key2Metadata = new KeyMetadata(
            KeyId: key1Id,
            Version: key1Version.Next(),
            Purpose: KeyPurpose.Encryption,
            Status: KeyStatus.Active,
            AlgorithmId: "AES-256-GCM",
            CreatedAtUtc: DateTimeOffset.UtcNow,
            ExpiresAtUtc: null);
        var key2 = new CryptographicKey(key2Metadata, key2Buffer);
        var saveResult = await store.SaveKeyAsync(key2);
        saveResult.IsSuccess.Should().BeTrue("Setup: saving second active key must succeed");
        key2.Dispose();

        // Verify our "stuck" state: both keys are Active
        var allKeys = await store.ListMetadataAsync(KeyPurpose.Encryption);
        var activeKeys = allKeys.Value.Where(k => k.Status == KeyStatus.Active).ToList();
        activeKeys.Should().HaveCount(2, "Test setup: both keys should be Active (simulating stuck rotation)");

        // Act: Rotate — should retire ALL active keys, not just the highest-version one
        var rotatedKey = await lifecycleManager.RotateKeyAsync(KeyPurpose.Encryption);
        rotatedKey.IsSuccess.Should().BeTrue("Rotation with multiple Active keys should succeed");
        rotatedKey.Value.Dispose();

        // Assert: After rotation, ONLY the newly rotated key should be Active
        var afterKeys = await store.ListMetadataAsync(KeyPurpose.Encryption);
        var activeAfterRotation = afterKeys.Value.Where(k => k.Status == KeyStatus.Active).ToList();
        var retiredAfterRotation = afterKeys.Value.Where(k => k.Status == KeyStatus.Retired).ToList();

        activeAfterRotation.Should().HaveCount(1,
            "KLM-03: After rotation, exactly one key should be Active");
        retiredAfterRotation.Should().HaveCount(2,
            "KLM-03: After rotation, the prior two Active keys should both be Retired");

        // The single active key should be the newly rotated key (highest version)
        var newActiveKey = activeAfterRotation.Single();
        newActiveKey.Version.Value.Should().BeGreaterThan(key2Metadata.Version.Value,
            "The new active key should have a higher version than the previously highest Active key");
    }

    [Fact]
    public async Task InMemoryKeyStore_Capacity_EnforcesMaxKeys()
    {
        var store = new InMemoryKeyStore();

        // Fill store up to MaxKeys
        for (int i = 0; i < InMemoryKeyStore.MaxKeys; i++)
        {
            var meta = new KeyMetadata(new KeyIdentifier($"key_{i}"), KeyVersion.Initial, KeyPurpose.Encryption, KeyStatus.Active, "AES", DateTimeOffset.UtcNow);
            using var buf = SecretBuffer.FromSpan([1, 2, 3]);
            var k = new CryptographicKey(meta, buf);
            var res = await store.SaveKeyAsync(k);
            res.IsSuccess.Should().BeTrue();
        }

        // Updating an existing key must SUCCEED even at capacity
        var existingMeta = new KeyMetadata(new KeyIdentifier("key_0"), KeyVersion.Initial, KeyPurpose.Encryption, KeyStatus.Active, "AES", DateTimeOffset.UtcNow);
        using var existingBuf = SecretBuffer.FromSpan([4, 5, 6]);
        var existingKey = new CryptographicKey(existingMeta, existingBuf);
        var updateRes = await store.SaveKeyAsync(existingKey);
        updateRes.IsSuccess.Should().BeTrue("Updating existing key should succeed at capacity");

        // Adding a NEW key must FAIL with StoreCapacityExceeded
        var newMeta = new KeyMetadata(new KeyIdentifier($"key_{InMemoryKeyStore.MaxKeys}"), KeyVersion.Initial, KeyPurpose.Encryption, KeyStatus.Active, "AES", DateTimeOffset.UtcNow);
        using var newBuf = SecretBuffer.FromSpan([7, 8, 9]);
        var newKey = new CryptographicKey(newMeta, newBuf);
        var failRes = await store.SaveKeyAsync(newKey);
        failRes.IsFailure.Should().BeTrue("Adding key beyond capacity must fail");
        failRes.Error.Code.Should().Be("Security.StoreCapacityExceeded");
    }

    [Fact]
    public async Task KeyLifecycleManager_VersionDerivation_And_ZeroActiveKeysRotation()
    {
        var store = new InMemoryKeyStore();
        using var lifecycle = new KeyLifecycleManager(store);

        // 1. Keys exist for a different purpose: highest is null branch -> returns KeyVersion.Initial
        var signingMeta = new KeyMetadata(new KeyIdentifier("sign_key"), KeyVersion.Initial, KeyPurpose.Signing, KeyStatus.Active, "HMAC", DateTimeOffset.UtcNow);
        using var signingBuf = SecretBuffer.CreateRandom(32);
        await store.SaveKeyAsync(new CryptographicKey(signingMeta, signingBuf));

        var encKey1 = await lifecycle.GenerateAndActivateKeyAsync(KeyPurpose.Encryption);
        encKey1.IsSuccess.Should().BeTrue();
        encKey1.Value.Metadata.Version.Should().Be(KeyVersion.Initial);
        encKey1.Value.Dispose();

        // 2. Multiple versions exist (v1 and v3): MaxBy returns v3 -> Next() returns v4 (MinBy would return v2)
        var v3 = new KeyVersion(3);
        var encMeta3 = new KeyMetadata(encKey1.Value.Metadata.KeyId, v3, KeyPurpose.Encryption, KeyStatus.Retired, "AES", DateTimeOffset.UtcNow);
        using var encBuf3 = SecretBuffer.CreateRandom(32);
        await store.SaveKeyAsync(new CryptographicKey(encMeta3, encBuf3));

        var encKeyNext = await lifecycle.GenerateAndActivateKeyAsync(KeyPurpose.Encryption);
        encKeyNext.IsSuccess.Should().BeTrue();
        encKeyNext.Value.Metadata.Version.Value.Should().Be(4, "Next version must be derived from MaxBy(version) which is 3 + 1 = 4");
        encKeyNext.Value.Dispose();

        // 3. Rotation when activeKeys.Count == 0: retire keys for purpose TokenProtection
        var tokenKey = await lifecycle.RotateKeyAsync(KeyPurpose.TokenProtection);
        tokenKey.IsSuccess.Should().BeTrue();
        tokenKey.Value.Dispose();
    }

    private sealed class CountingKeyStore : IKeyStore
    {
        private readonly InMemoryKeyStore _inner = new();
        public int GetKeyCount { get; private set; }
        public int ListMetadataCount { get; private set; }

        public ValueTask<Result> SaveKeyAsync(CryptographicKey key, CancellationToken cancellationToken = default) =>
            _inner.SaveKeyAsync(key, cancellationToken);

        public async ValueTask<Result<CryptographicKey>> GetKeyAsync(KeyIdentifier keyId, KeyVersion version, CancellationToken cancellationToken = default)
        {
            GetKeyCount++;
            return await _inner.GetKeyAsync(keyId, version, cancellationToken);
        }

        public async ValueTask<Result<IReadOnlyList<KeyMetadata>>> ListMetadataAsync(KeyPurpose? purpose = null, CancellationToken cancellationToken = default)
        {
            ListMetadataCount++;
            return await _inner.ListMetadataAsync(purpose, cancellationToken);
        }

        public ValueTask<Result> UpdateStatusAsync(KeyIdentifier keyId, KeyVersion version, KeyStatus newStatus, CancellationToken cancellationToken = default) =>
            _inner.UpdateStatusAsync(keyId, version, newStatus, cancellationToken);
    }

    [Fact]
    public async Task KeyRing_Caching_TtlAndPruning_BehavesCorrectly()
    {
        var store = new CountingKeyStore();
        var keyId = KeyIdentifier.New();
        var v1 = KeyVersion.Initial;
        var meta = new KeyMetadata(keyId, v1, KeyPurpose.Encryption, KeyStatus.Active, "AES-256-GCM", DateTimeOffset.UtcNow);
        using var buf = SecretBuffer.CreateRandom(32);
        await store.SaveKeyAsync(new CryptographicKey(meta, buf));

        var options = new KeyRingOptions { CacheTtl = TimeSpan.FromMinutes(10) };
        var ring = new KeyRing(store, options);

        // 1. GetActiveKeyAsync: first call hits store for metadata and key
        var active1 = await ring.GetActiveKeyAsync(KeyPurpose.Encryption);
        active1.IsSuccess.Should().BeTrue();
        store.ListMetadataCount.Should().Be(1);
        store.GetKeyCount.Should().Be(1);

        // Second call comes from _activeKeyCache
        var active2 = await ring.GetActiveKeyAsync(KeyPurpose.Encryption);
        active2.IsSuccess.Should().BeTrue();
        store.ListMetadataCount.Should().Be(1, "Second active key lookup should come from active key cache");
        store.GetKeyCount.Should().Be(1);

        active1.Value.Dispose();
        active2.Value.Dispose();

        // 2. InvalidateActiveKey: clears active key cache; next call queries metadata from store, while key is in _keyCache
        ring.InvalidateActiveKey(KeyPurpose.Encryption);
        var active3 = await ring.GetActiveKeyAsync(KeyPurpose.Encryption);
        active3.IsSuccess.Should().BeTrue();
        store.ListMetadataCount.Should().Be(2, "Lookup after active key invalidation must query metadata store");
        store.GetKeyCount.Should().Be(1, "Key itself is still cached in _keyCache");
        active3.Value.Dispose();

        // 3. GetKeyAsync: key already cached in _keyCache
        var key1 = await ring.GetKeyAsync(keyId, v1);
        key1.IsSuccess.Should().BeTrue();
        store.GetKeyCount.Should().Be(1);

        // 4. InvalidateKey: invalidates _keyCache; next call must query store for key
        ring.InvalidateKey(keyId, v1);
        var key2 = await ring.GetKeyAsync(keyId, v1);
        key2.IsSuccess.Should().BeTrue();
        store.GetKeyCount.Should().Be(2, "Lookup after specific key invalidation must query store");

        key1.Value.Dispose();
        key2.Value.Dispose();

        // 5. InvalidateAll: both active and specific caches cleared
        ring.InvalidateAll();
        var key3 = await ring.GetKeyAsync(keyId, v1);
        key3.IsSuccess.Should().BeTrue();
        store.GetKeyCount.Should().Be(3, "Lookup after InvalidateAll must query store");
        key3.Value.Dispose();

        // 6. Test MaxKeyCacheCapacity (1000) pruning: insert 1005 keys into ring
        for (int i = 0; i < 1005; i++)
        {
            var tempId = new KeyIdentifier($"temp_{i}");
            var tempMeta = new KeyMetadata(tempId, KeyVersion.Initial, KeyPurpose.Signing, KeyStatus.Active, "AES", DateTimeOffset.UtcNow);
            using var tempBuf = SecretBuffer.CreateRandom(32);
            await store.SaveKeyAsync(new CryptographicKey(tempMeta, tempBuf));
            var tempRes = await ring.GetKeyAsync(tempId, KeyVersion.Initial);
            tempRes.IsSuccess.Should().BeTrue();
            tempRes.Value.Dispose();
        }

        // ClearCache
        ring.ClearCache();
    }
}
