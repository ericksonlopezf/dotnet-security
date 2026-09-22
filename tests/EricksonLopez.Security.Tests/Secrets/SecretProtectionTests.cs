// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Tests.Secrets;

using System;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using EricksonLopez.Result;
using EricksonLopez.Security.Abstractions.Cryptography;
using EricksonLopez.Security.Abstractions.Errors;
using EricksonLopez.Security.Abstractions.KeyManagement;
using EricksonLopez.Security.Abstractions.Primitives;
using EricksonLopez.Security.Abstractions.Secrets;
using EricksonLopez.Security.Cryptography;
using EricksonLopez.Security.KeyManagement;
using EricksonLopez.Security.Memory;
using EricksonLopez.Security.Secrets;
using Xunit;

public sealed class SecretProtectionTests
{
    public SecretProtectionTests()
    {
        KeyRing.CacheTtl = TimeSpan.Zero;
    }

    private sealed class FakeSingleSecretStore : ISecretStore
    {
        public ValueTask<Result<Redacted<string>>> GetSecretAsync(string secretName, CancellationToken cancellationToken = default)
        {
            if (secretName == "db_password")
            {
                return ValueTask.FromResult<Result<Redacted<string>>>(new Redacted<string>("store-secret-pwd"));
            }

            return ValueTask.FromResult<Result<Redacted<string>>>(SecurityError.SecretNotFound(secretName));
        }

        public ValueTask<Result> SetSecretAsync(string secretName, string secretValue, CancellationToken cancellationToken = default) =>
            ValueTask.FromResult(Result.Success());
    }

    private sealed class FailingEncryptionEngine : IAuthenticatedEncryptionEngine
    {
        public AeadAlgorithm Algorithm => AeadAlgorithm.Aes256Gcm;
        public int KeySizeBytes => 32;
        public int NonceSizeBytes => 12;
        public int TagSizeBytes => 16;

        public Result<EncryptedData> Encrypt(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> key, ReadOnlySpan<byte> associatedData = default) =>
            SecurityError.EncryptionFailed("Engine failure simulation");

        public Result Encrypt(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> key, Span<byte> nonceDestination, Span<byte> ciphertextDestination, Span<byte> tagDestination, ReadOnlySpan<byte> associatedData = default) =>
            SecurityError.EncryptionFailed("Engine failure simulation");

        public Result Decrypt(ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> tag, ReadOnlySpan<byte> associatedData, Span<byte> plaintextDestination, out int bytesWritten)
        {
            bytesWritten = 0;
            return SecurityError.DecryptionFailed("Engine failure simulation");
        }
    }

    // ==========================================
    // EnvironmentSecretStore Tests
    // ==========================================

    [Fact]
    public async Task EnvironmentSecretStore_GetAndSet_OperatesCorrectly()
    {
        var store = new EnvironmentSecretStore("TEST_PREFIX_");

        // Null prefix fallback to empty string
        var nullPrefixStore = new EnvironmentSecretStore(null!);
        Environment.SetEnvironmentVariable("RAW_UNPREFIXED_TEST_KEY", "raw-env-val");
        try
        {
            var rawGetRes = await nullPrefixStore.GetSecretAsync("RAW_UNPREFIXED_TEST_KEY");
            Assert.True(rawGetRes.IsSuccess);
            Assert.Equal("raw-env-val", rawGetRes.Value.UnsafeValue);
        }
        finally
        {
            Environment.SetEnvironmentVariable("RAW_UNPREFIXED_TEST_KEY", null);
        }

        var setNullPrefixRes = await nullPrefixStore.SetSecretAsync("NULL_PREFIX_TEST_KEY", "null-prefix-val");
        Assert.True(setNullPrefixRes.IsSuccess);
        var getNullPrefixRes = await nullPrefixStore.GetSecretAsync("NULL_PREFIX_TEST_KEY");
        Assert.True(getNullPrefixRes.IsSuccess);
        Assert.Equal("null-prefix-val", getNullPrefixRes.Value.UnsafeValue);
        var nullRes = await nullPrefixStore.GetSecretAsync("NON_EXISTING_KEY_XYZ");
        Assert.True(nullRes.IsFailure);

        // Invalid secret names
        var resNull = await store.GetSecretAsync(null!);
        Assert.True(resNull.IsFailure);

        var resEmpty = await store.GetSecretAsync("   ");
        Assert.True(resEmpty.IsFailure);

        var resSetNull = await store.SetSecretAsync("", "val");
        Assert.True(resSetNull.IsFailure);

        // Non-existent variable
        var resNotFound = await store.GetSecretAsync("NON_EXISTENT_VAR_123");
        Assert.True(resNotFound.IsFailure);
        Assert.Equal("Security.SecretNotFound", resNotFound.Error.Code);

        // Set and get (tests normalization of dots, colons, hyphens)
        var setRes = await store.SetSecretAsync("database:connection.string-secret", "my-db-conn-string");
        Assert.True(setRes.IsSuccess);

        var getRes = await store.GetSecretAsync("database:connection.string-secret");
        Assert.True(getRes.IsSuccess);
        Assert.Equal("my-db-conn-string", getRes.Value.UnsafeValue);
    }

    // ==========================================
    // CompositeSecretResolver Tests
    // ==========================================

    [Fact]
    public async Task CompositeSecretResolver_ResolvesDifferentSchemesAndValidates()
    {
        var exNull = Assert.Throws<ArgumentNullException>(() => new CompositeSecretResolver(null!));
        Assert.Equal("secretStore", exNull.ParamName);

        var mockStore = new FakeSingleSecretStore();
        var envStore = new EnvironmentSecretStore(prefix: "TEST_SEC_");
        var resolver = new CompositeSecretResolver(mockStore, envStore);

        Environment.SetEnvironmentVariable("TEST_SEC_API_KEY", "env-secret-value-777");

        // 1. raw: scheme
        var rawResult = await resolver.ResolveAsync("raw:inline-secret-value");
        Assert.True(rawResult.IsSuccess);
        Assert.Equal("inline-secret-value", rawResult.Value.UnsafeValue);

        // 2. env: scheme
        var envResult = await resolver.ResolveAsync("env:API_KEY");
        Assert.True(envResult.IsSuccess);
        Assert.Equal("env-secret-value-777", envResult.Value.UnsafeValue);

        // 3. store: scheme
        var storeResult = await resolver.ResolveAsync("store:db_password");
        Assert.True(storeResult.IsSuccess);
        Assert.Equal("store-secret-pwd", storeResult.Value.UnsafeValue);

        // 4. fallback scheme (without prefix)
        var fallbackResult = await resolver.ResolveAsync("db_password");
        Assert.True(fallbackResult.IsSuccess);
        Assert.Equal("store-secret-pwd", fallbackResult.Value.UnsafeValue);

        // 5. Empty or whitespace
        var emptyResult = await resolver.ResolveAsync("");
        Assert.True(emptyResult.IsFailure);
        Assert.Equal("The secret 'Empty secret reference.' was not found.", emptyResult.Error.Description);

        var wsResult = await resolver.ResolveAsync("   ");
        Assert.True(wsResult.IsFailure);
        Assert.Equal("The secret 'Empty secret reference.' was not found.", wsResult.Error.Description);
    }

    private sealed class TrackingSerializer : ISecurityEnvelopeSerializer
    {
        public bool SerializeCalled { get; private set; }
        public byte[] Serialize(SecurityEnvelope envelope)
        {
            SerializeCalled = true;
            return BinarySecurityEnvelopeSerializer.Shared.Serialize(envelope);
        }
        public bool TrySerialize(SecurityEnvelope envelope, Span<byte> destination, out int bytesWritten)
        {
            SerializeCalled = true;
            return BinarySecurityEnvelopeSerializer.Shared.TrySerialize(envelope, destination, out bytesWritten);
        }
        public Result<SecurityEnvelope> Deserialize(ReadOnlySpan<byte> payload) =>
            BinarySecurityEnvelopeSerializer.Shared.Deserialize(payload);
    }

    [Fact]
    public async Task AesGcmSecretProtector_CustomSerializer_UsedWhenProvided()
    {
        var keyStore = new InMemoryKeyStore();
        var lifecycleManager = new KeyLifecycleManager(keyStore);
        var keyRing = new KeyRing(keyStore);
        await lifecycleManager.GenerateAndActivateKeyAsync(KeyPurpose.SecretProtection);

        var customSerializer = new TrackingSerializer();
        var protector = new AesGcmSecretProtector(keyRing, AesGcmEncryptionEngine.Shared, customSerializer);
        var result = await protector.ProtectAsync(new byte[] { 1, 2, 3 });
        Assert.True(result.IsSuccess);
        Assert.True(customSerializer.SerializeCalled);
    }

    // ==========================================
    // AesGcmSecretProtector Tests
    // ==========================================

    [Fact]
    public async Task AesGcmSecretProtector_ProtectAndUnprotect_RoundtripsSuccessfully()
    {
        var keyStore = new InMemoryKeyStore();
        var lifecycleManager = new KeyLifecycleManager(keyStore);
        var keyRing = new KeyRing(keyStore);

        await lifecycleManager.GenerateAndActivateKeyAsync(KeyPurpose.SecretProtection);

        var protector = new AesGcmSecretProtector(keyRing, AesGcmEncryptionEngine.Shared, BinarySecurityEnvelopeSerializer.Shared);
        byte[] secretBytes = Encoding.UTF8.GetBytes("SuperSecretConnectionString123");
        byte[] aad = Encoding.UTF8.GetBytes("tenant-99");

        // Async roundtrip with AAD in envelope
        var protectResult = await protector.ProtectAsync(secretBytes, KeyPurpose.SecretProtection, AuthenticatedContext.FromBytes(aad));
        Assert.True(protectResult.IsSuccess);

        // SEC-002: Unprotect with matching caller AAD succeeds
        var unprotectResult = await protector.UnprotectAsync(protectResult.Value, AuthenticatedContext.FromBytes(aad));
        Assert.True(unprotectResult.IsSuccess);
        Assert.Equal("SuperSecretConnectionString123", Encoding.UTF8.GetString(unprotectResult.Value));

        // SEC-002: Unprotect without passing caller AAD when envelope has AAD MUST fail with AssociatedDataMismatch
        var unprotectWithoutAadResult = await protector.UnprotectAsync(protectResult.Value);
        Assert.True(unprotectWithoutAadResult.IsFailure);
        Assert.Equal("Security.AssociatedDataMismatch", unprotectWithoutAadResult.Error.Code);

        // Sync roundtrip with AAD
        var protectSync = protector.Protect(secretBytes, KeyPurpose.SecretProtection, AuthenticatedContext.FromBytes(aad));
        Assert.True(protectSync.IsSuccess);

        var unprotectSync = protector.Unprotect(protectSync.Value, AuthenticatedContext.FromBytes(aad));
        Assert.True(unprotectSync.IsSuccess);
        Assert.Equal("SuperSecretConnectionString123", Encoding.UTF8.GetString(unprotectSync.Value));

        // Sync roundtrip without AAD
        var protectSyncNoAad = protector.Protect(secretBytes);
        Assert.True(protectSyncNoAad.IsSuccess);

        var unprotectSyncNoAad = protector.Unprotect(protectSyncNoAad.Value);
        Assert.True(unprotectSyncNoAad.IsSuccess);
        Assert.Equal("SuperSecretConnectionString123", Encoding.UTF8.GetString(unprotectSyncNoAad.Value));
    }

    [Fact]
    public async Task AesGcmSecretProtector_KeyRotation_AllowsSeamlessDecryptionOfLegacySecrets()
    {
        var keyStore = new InMemoryKeyStore();
        var lifecycleManager = new KeyLifecycleManager(keyStore);
        var keyRing = new KeyRing(keyStore);

        var protector = new AesGcmSecretProtector(keyRing);

        // Generate v1 key
        await lifecycleManager.GenerateAndActivateKeyAsync(KeyPurpose.SecretProtection);
        byte[] legacyPayload = Encoding.UTF8.GetBytes("Encrypted with Key v1");

        var protectResult = await protector.ProtectAsync(legacyPayload, KeyPurpose.SecretProtection);
        Assert.True(protectResult.IsSuccess);
        var protectedWithV1 = protectResult.Value;

        // Rotate key to v2
        await lifecycleManager.RotateKeyAsync(KeyPurpose.SecretProtection);

        // Unprotect legacy secret using current protector
        var unprotectResult = await protector.UnprotectAsync(protectedWithV1);

        Assert.True(unprotectResult.IsSuccess);
        Assert.Equal("Encrypted with Key v1", Encoding.UTF8.GetString(unprotectResult.Value));
    }

    [Fact]
    public async Task AesGcmSecretProtector_ErrorBranches_HandledSafely()
    {
        var nullKeyProviderEx = Assert.Throws<ArgumentNullException>(() => new AesGcmSecretProtector(null!));
        Assert.Equal("keyProvider", nullKeyProviderEx.ParamName);

        // 1. Missing active encryption key
        var emptyKeyRing = new KeyRing(new InMemoryKeyStore());
        var protectorNoKeys = new AesGcmSecretProtector(emptyKeyRing);

        var resNoKey = await protectorNoKeys.ProtectAsync(new byte[] { 1, 2, 3 });
        Assert.True(resNoKey.IsFailure);
        Assert.Equal("Security.KeyNotFound", resNoKey.Error.Code);

        // 2. Corrupted protected data on unprotect (serializer failure)
        var resCorrupt = await protectorNoKeys.UnprotectAsync(new byte[] { 1, 2 });
        Assert.True(resCorrupt.IsFailure);
        Assert.Equal("Security.InvalidCiphertext", resCorrupt.Error.Code);

        // 3. Decryption key not found for envelope
        var keyStore = new InMemoryKeyStore();
        var lifecycleManager = new KeyLifecycleManager(keyStore);
        var keyRing = new KeyRing(keyStore);
        await lifecycleManager.GenerateAndActivateKeyAsync(KeyPurpose.SecretProtection);

        var protector = new AesGcmSecretProtector(keyRing);
        var protectResult = await protector.ProtectAsync(new byte[] { 1, 2, 3 });
        Assert.True(protectResult.IsSuccess);
        var protectedBytes = protectResult.Value;

        // Revoke the key so decryption key lookup fails
        var listResult = await keyStore.ListMetadataAsync(KeyPurpose.SecretProtection);
        Assert.True(listResult.IsSuccess);
        var keyMeta = listResult.Value[0];
        await keyStore.UpdateStatusAsync(keyMeta.KeyId, keyMeta.Version, KeyStatus.Revoked);

        var resRevoked = await protector.UnprotectAsync(protectedBytes);
        Assert.True(resRevoked.IsFailure);
        Assert.Equal("Security.KeyRevoked", resRevoked.Error.Code);

        // Restore active key status
        await keyStore.UpdateStatusAsync(keyMeta.KeyId, keyMeta.Version, KeyStatus.Active);

        // 4. Failing engine on protect and unprotect
        var failingProtector = new AesGcmSecretProtector(keyRing, new FailingEncryptionEngine());
        var resFailProtect = await failingProtector.ProtectAsync(new byte[] { 1, 2, 3 });
        Assert.True(resFailProtect.IsFailure);
        Assert.Equal("Security.EncryptionFailed", resFailProtect.Error.Code);

        var resFailDecrypt = await failingProtector.UnprotectAsync(protectedBytes);
        Assert.True(resFailDecrypt.IsFailure);
        Assert.Equal("Security.DecryptionFailed", resFailDecrypt.Error.Code);

        // 5. Caller-supplied associated data when envelope AAD is empty
        var protectorDefault = new AesGcmSecretProtector(keyRing);
        var resNoAadProtect = await protectorDefault.ProtectAsync(new byte[] { 9, 8, 7 }, expectedAssociatedData: AuthenticatedContext.Empty);
        Assert.True(resNoAadProtect.IsSuccess);

        // Calling unprotect with non-matching caller AAD fails auth tag check
        var resMismatchAad = await protectorDefault.UnprotectAsync(resNoAadProtect.Value, expectedAssociatedData: AuthenticatedContext.FromBytes(Encoding.UTF8.GetBytes("mismatched-caller-aad")));
        Assert.True(resMismatchAad.IsFailure);

        // 6. Synchronous Protect / Unprotect error counterparts
        var syncNoKey = protectorNoKeys.Protect(new byte[] { 1, 2, 3 });
        Assert.True(syncNoKey.IsFailure);
        Assert.Equal("Security.KeyNotFound", syncNoKey.Error.Code);

        var syncCorrupt = protectorNoKeys.Unprotect(new byte[] { 1, 2 });
        Assert.True(syncCorrupt.IsFailure);
        Assert.Equal("Security.InvalidCiphertext", syncCorrupt.Error.Code);

        await keyStore.UpdateStatusAsync(keyMeta.KeyId, keyMeta.Version, KeyStatus.Revoked);
        var syncRevoked = protector.Unprotect(protectedBytes);
        Assert.True(syncRevoked.IsFailure);
        Assert.Equal("Security.KeyRevoked", syncRevoked.Error.Code);
        await keyStore.UpdateStatusAsync(keyMeta.KeyId, keyMeta.Version, KeyStatus.Active);

        var syncFailProtect = failingProtector.Protect(new byte[] { 1, 2, 3 });
        Assert.True(syncFailProtect.IsFailure);
        Assert.Equal("Security.EncryptionFailed", syncFailProtect.Error.Code);

        var syncFailDecrypt = failingProtector.Unprotect(protectedBytes);
        Assert.True(syncFailDecrypt.IsFailure);
        Assert.Equal("Security.DecryptionFailed", syncFailDecrypt.Error.Code);

        var syncMismatchAad = protectorDefault.Unprotect(resNoAadProtect.Value, expectedAssociatedData: AuthenticatedContext.FromBytes(Encoding.UTF8.GetBytes("mismatched-caller-aad")));
        Assert.True(syncMismatchAad.IsFailure);

        // 7. Synchronous Protect with non-empty AssociatedData and roundtrip Unprotect
        byte[] explicitAad = [11, 22, 33];
        var syncWithAad = protectorDefault.Protect(new byte[] { 7, 8, 9 }, expectedAssociatedData: AuthenticatedContext.FromBytes(explicitAad));
        Assert.True(syncWithAad.IsSuccess);
        var syncUnprotectWithAad = protectorDefault.Unprotect(syncWithAad.Value, AuthenticatedContext.FromBytes(explicitAad));
        Assert.True(syncUnprotectWithAad.IsSuccess);
        Assert.Equal(new byte[] { 7, 8, 9 }, syncUnprotectWithAad.Value);
    }

    [Fact]
    public void AesGcmSecretProtector_SynchronousProtectAndUnprotect_WithNonKeyRingProvider()
    {
        // MEM-007: CryptographicKey is disposed after each Protect/Unprotect call.
        // StandaloneKeyProvider must create a new instance on each call to avoid ObjectDisposedException.
        var meta = new KeyMetadata(KeyIdentifier.New(), KeyVersion.Initial, KeyPurpose.SecretProtection, KeyStatus.Active, "AES-256-GCM", DateTimeOffset.UtcNow);
        var provider = new StandaloneKeyProvider(meta, 32);
        var protector = new AesGcmSecretProtector(provider);

        byte[] payload = [1, 2, 3, 4, 5];
        var protectResult = protector.Protect(payload);
        Assert.True(protectResult.IsSuccess);

        var unprotectResult = protector.Unprotect(protectResult.Value);
        Assert.True(unprotectResult.IsSuccess);
        Assert.Equal(payload, unprotectResult.Value);
    }

    private sealed class StandaloneKeyProvider : IEncryptionKeyProvider
    {
        private readonly KeyMetadata _meta;
        private readonly byte[] _keyBytes;

        /// <summary>
        /// MEM-007: Stores raw key bytes so a fresh <see cref="CryptographicKey"/> can be created
        /// on each call. AesGcmSecretProtector disposes the key after each Protect/Unprotect call,
        /// so returning the same instance would cause ObjectDisposedException on the second call.
        /// </summary>
        public StandaloneKeyProvider(KeyMetadata meta, int keyLengthBytes)
        {
            _meta = meta;
            _keyBytes = System.Security.Cryptography.RandomNumberGenerator.GetBytes(keyLengthBytes);
        }

        private CryptographicKey CreateFreshKey()
        {
            var buffer = SecretBuffer.FromSpan(_keyBytes);
            return new CryptographicKey(_meta, buffer);
        }

        public ValueTask<Result<CryptographicKey>> GetActiveEncryptionKeyAsync(KeyPurpose purpose, CancellationToken cancellationToken = default) =>
            ValueTask.FromResult<Result<CryptographicKey>>(CreateFreshKey());

        public ValueTask<Result<CryptographicKey>> GetDecryptionKeyAsync(KeyIdentifier keyId, KeyVersion version, CancellationToken cancellationToken = default) =>
            ValueTask.FromResult<Result<CryptographicKey>>(CreateFreshKey());
    }
}
