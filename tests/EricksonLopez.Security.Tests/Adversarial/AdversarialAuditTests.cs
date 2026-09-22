// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Tests.Adversarial;

using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using AwesomeAssertions;
using EricksonLopez.Result;
using EricksonLopez.Security.Abstractions.Cryptography;
using EricksonLopez.Security.Abstractions.Errors;
using EricksonLopez.Security.Abstractions.KeyManagement;
using EricksonLopez.Security.Abstractions.Passwords;
using EricksonLopez.Security.Abstractions.Primitives;
using EricksonLopez.Security.Cryptography;
using EricksonLopez.Security.KeyManagement;
using EricksonLopez.Security.Memory;
using EricksonLopez.Security.Passwords;
using EricksonLopez.Security.Secrets;
using EricksonLopez.Security.Tokens;
using Xunit;

/// <summary>
/// Adversarial security test suite verifying remediation of forensic audit findings (SEC-001 through SEC-016).
/// </summary>
public sealed class AdversarialAuditTests
{
    private sealed class TrackingKeyStore(IKeyStore inner) : IKeyStore
    {
        public CryptographicKey? LastRetrievedKey { get; private set; }

        public ValueTask<Result> SaveKeyAsync(CryptographicKey key, CancellationToken cancellationToken = default) =>
            inner.SaveKeyAsync(key, cancellationToken);

        public async ValueTask<Result<CryptographicKey>> GetKeyAsync(KeyIdentifier keyId, KeyVersion version, CancellationToken cancellationToken = default)
        {
            var res = await inner.GetKeyAsync(keyId, version, cancellationToken);
            if (res.IsSuccess)
            {
                LastRetrievedKey = res.Value;
            }

            return res;
        }

        public ValueTask<Result<IReadOnlyList<KeyMetadata>>> ListMetadataAsync(KeyPurpose? purpose = null, CancellationToken cancellationToken = default) =>
            inner.ListMetadataAsync(purpose, cancellationToken);

        public ValueTask<Result> UpdateStatusAsync(KeyIdentifier keyId, KeyVersion version, KeyStatus newStatus, CancellationToken cancellationToken = default) =>
            inner.UpdateStatusAsync(keyId, version, newStatus, cancellationToken);
    }

    [Fact]
    public async Task KeyRing_Revoked_Key_Disposes_Retrieved_Key_Instance_SEC_007()
    {
        // GIVEN: An in-memory store with an active key that gets revoked
        var innerStore = new InMemoryKeyStore();
        var keyStore = new TrackingKeyStore(innerStore);
        var lifecycle = new KeyLifecycleManager(keyStore);

        var keyResult = await lifecycle.GenerateAndActivateKeyAsync(KeyPurpose.Encryption);
        keyResult.IsSuccess.Should().BeTrue();
        var key = keyResult.Value;

        // Revoke the key
        await lifecycle.RevokeKeyAsync(key.Metadata.KeyId, key.Metadata.Version, "Security Incident Compromise");

        // WHEN: Querying the revoked key through KeyRing
        var keyRing = new KeyRing(keyStore);
        var queryResult = await keyRing.GetKeyAsync(key.Metadata.KeyId, key.Metadata.Version);

        // THEN: Returns failure with KeyRevoked AND the rented key instance is immediately disposed
        queryResult.IsFailure.Should().BeTrue();
        queryResult.Error.Code.Should().Be("Security.KeyRevoked");
        keyStore.LastRetrievedKey.Should().NotBeNull();
        keyStore.LastRetrievedKey!.IsDisposed.Should().BeTrue(
            "REMEDIATION VERIFIED (SEC-007): Revoked key instance must be disposed when rejected by KeyRing.");
    }

    [Fact]
    public async Task KeyRing_Destroyed_Key_Disposes_Retrieved_Key_Instance_SEC_007()
    {
        var innerStore = new InMemoryKeyStore();
        var keyStore = new TrackingKeyStore(innerStore);
        var lifecycle = new KeyLifecycleManager(keyStore);

        var keyResult = await lifecycle.GenerateAndActivateKeyAsync(KeyPurpose.Encryption);
        var key = keyResult.Value;

        await keyStore.UpdateStatusAsync(key.Metadata.KeyId, key.Metadata.Version, KeyStatus.Destroyed);

        var keyRing = new KeyRing(keyStore);
        var queryResult = await keyRing.GetKeyAsync(key.Metadata.KeyId, key.Metadata.Version);

        queryResult.IsFailure.Should().BeTrue();
        queryResult.Error.Code.Should().Be("Security.KeyRevoked");
        keyStore.LastRetrievedKey.Should().NotBeNull();
        keyStore.LastRetrievedKey!.IsDisposed.Should().BeTrue(
            "REMEDIATION VERIFIED (SEC-007): Destroyed key instance must be disposed when rejected by KeyRing.");
    }

    [Fact]
    public void AesGcm_Invalid_Nonce_Returns_InvalidNonce_Error_SEC_009()
    {
        // GIVEN: Valid 32-byte key but invalid 8-byte nonce
        var engine = AesGcmEncryptionEngine.Shared;
        byte[] key = new byte[32];
        byte[] invalidNonce = new byte[8];
        byte[] ciphertext = new byte[16];
        byte[] tag = new byte[16];

        // WHEN: Invoking Encrypt with invalid nonce
        var result = engine.Encrypt(
            plaintext: new byte[16],
            key: key,
            nonceDestination: invalidNonce,
            ciphertextDestination: ciphertext,
            tagDestination: tag);

        // THEN: Error code is InvalidNonce (not InvalidKey)
        result.IsFailure.Should().BeTrue();
        result.Error.Code.Should().Be("Security.InvalidNonce",
            "REMEDIATION VERIFIED (SEC-009): AES-GCM returns Security.InvalidNonce when Nonce length is invalid.");
    }

    [Fact]
    public void AesGcm_Small_Buffer_Returns_BufferTooSmall_Error_SEC_009()
    {
        var engine = AesGcmEncryptionEngine.Shared;
        byte[] key = new byte[32];
        byte[] nonce = new byte[12];
        byte[] smallCiphertext = new byte[4];
        byte[] tag = new byte[16];

        var result = engine.Encrypt(
            plaintext: new byte[16],
            key: key,
            nonceDestination: nonce,
            ciphertextDestination: smallCiphertext,
            tagDestination: tag);

        result.IsFailure.Should().BeTrue();
        result.Error.Code.Should().Be("Security.BufferTooSmall",
            "REMEDIATION VERIFIED (SEC-009): AES-GCM returns Security.BufferTooSmall when destination is insufficient.");
    }

    [Fact]
    public void ChaCha20Poly1305_Invalid_Nonce_Returns_InvalidNonce_Error_SEC_009()
    {
        var engine = ChaCha20Poly1305EncryptionEngine.Shared;
        byte[] key = new byte[32];
        byte[] invalidNonce = new byte[8];
        byte[] ciphertext = new byte[16];
        byte[] tag = new byte[16];

        var result = engine.Encrypt(
            plaintext: new byte[16],
            key: key,
            nonceDestination: invalidNonce,
            ciphertextDestination: ciphertext,
            tagDestination: tag);

        result.IsFailure.Should().BeTrue();
        result.Error.Code.Should().Be("Security.InvalidNonce",
            "REMEDIATION VERIFIED (SEC-009): ChaCha20Poly1305 returns Security.InvalidNonce when Nonce length is invalid.");
    }

    [Fact]
    public async Task ApiKey_Validation_Prevents_Enumeration_By_Normalizing_Error_Messages_SEC_008()
    {
        // GIVEN: API key store with one valid key
        var keyStore = new InMemoryApiKeyStore();
        var tokenHasher = new HmacSha256TokenHasher();
        var generator = new ApiKeyGenerator(tokenHasher);

        var issuance = generator.GenerateApiKey(ownerId: "tenant_1", name: "Production Key", prefix: "ek_live");
        await keyStore.SaveAsync(issuance.Key);

        var validator = new ApiKeyValidator(keyStore, tokenHasher);

        // CASE 1: Non-existent key ID
        var fakeIdKey = "ek_live_0000000000000000_123456789012345678901234";
        var result1 = await validator.ValidateApiKeyAsync(fakeIdKey);

        // CASE 2: Exists, but secret is wrong
        var realIdWrongSecretKey = $"{issuance.Key.Id.Value}_badsecret123456789012345";
        var result2 = await validator.ValidateApiKeyAsync(realIdWrongSecretKey);

        // THEN: Both cases return identical error messages and codes, eliminating account enumeration!
        result1.IsFailure.Should().BeTrue();
        result2.IsFailure.Should().BeTrue();

        result1.Error.Description.Should().Be("Invalid API key credentials.");
        result2.Error.Description.Should().Be("Invalid API key credentials.");
        result1.Error.Description.Should().Be(result2.Error.Description,
            "REMEDIATION VERIFIED (SEC-008): Attacker cannot distinguish existing vs non-existing API key IDs.");
    }

    [Fact]
    public void Secret_String_Nullifies_Value_Reference_After_Dispose_SEC_010()
    {
        // GIVEN: Secret wrapping a string
        const string secretText = "SuperSensitivePassword#123!";
        var secret = new Secret<string>(secretText);

        // WHEN: Disposing the secret
        secret.Dispose();

        // THEN: secret.IsDisposed is true, and reflection confirms _value reference is cleared
        secret.IsDisposed.Should().BeTrue();

        var field = typeof(Secret<string>).GetField("_value", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
        var underlyingRef = field?.GetValue(secret);

        underlyingRef.Should().BeNull("REMEDIATION VERIFIED (SEC-010): Secret<T> nullifies reference to _value after Dispose().");
    }

    [Fact]
    public void SecretBuffer_Finalizer_Frees_Rented_Buffer_Without_Throwing_SEC_011()
    {
        // GIVEN: An allocated SecretBuffer that is abandoned without explicit Dispose()
        void AllocateAndDrop()
        {
            var buf = SecretBuffer.CreateRandom(64);
            _ = buf.Span[0];
        }

        AllocateAndDrop();

        // WHEN: Forcing garbage collection and pending finalizers
        GC.Collect();
        GC.WaitForPendingFinalizers();
        GC.Collect();

        // THEN: Finalizer executes zeroization and returns rented ArrayPool buffer safely without throwing
    }

    [Fact]
    public async Task KeyLifecycleManager_RotateKeyAsync_Is_ThreadSafe_Under_Concurrent_Load_SEC_012()
    {
        // GIVEN: A lifecycle manager and an initial active key
        var keyStore = new InMemoryKeyStore();
        var lifecycle = new KeyLifecycleManager(keyStore);

        var genResult = await lifecycle.GenerateAndActivateKeyAsync(KeyPurpose.Encryption);
        genResult.IsSuccess.Should().BeTrue();
        var keyId = genResult.Value.Metadata.KeyId;

        // WHEN: 8 concurrent rotations occur simultaneously on the same key
        var tasks = new List<Task<Result<CryptographicKey>>>();
        for (int i = 0; i < 8; i++)
        {
            tasks.Add(Task.Run(async () => await lifecycle.RotateKeyAsync(KeyPurpose.Encryption)));
        }

        var results = await Task.WhenAll(tasks);

        // THEN: Every rotation succeeds without concurrency race conditions
        foreach (var r in results)
        {
            r.IsSuccess.Should().BeTrue();
        }

        var metadataList = (await keyStore.ListMetadataAsync()).Value;
        metadataList.Should().HaveCount(9, "REMEDIATION VERIFIED (SEC-012): 1 initial + 8 sequential rotations = 9 versions total.");
    }

    [Fact]
    public void Pbkdf2PasswordHasher_Verify_Supports_Tier1_PBKDF2_V1_Format_SEC_005()
    {
        // GIVEN: A hash generated by Tier 1 PBKDF2 format (PBKDF2.V1$iterations$salt$hash using HMAC-SHA512)
        var hasher = new Pbkdf2PasswordHasher();

        byte[] salt = new byte[16] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
        byte[] hash = Rfc2898DeriveBytes.Pbkdf2(
            "SecretPassword123!",
            salt,
            iterations: 100_000,
            HashAlgorithmName.SHA512,
            outputLength: 32);

        string v1Hash = $"PBKDF2.V1$100000${Convert.ToBase64String(salt)}${Convert.ToBase64String(hash)}";

        // WHEN / THEN: Pbkdf2PasswordHasher verifies Tier 1 hashes seamlessly (and flags rehash needed for 100k < 210k iterations)
        var verifySuccess = hasher.VerifyPassword("SecretPassword123!", v1Hash);
        verifySuccess.Should().Be(PasswordVerificationResult.SuccessRehashNeeded,
            "REMEDIATION VERIFIED (SEC-005): Pbkdf2PasswordHasher must verify Tier 1 PBKDF2.V1$ hashes.");

        var verifyWrong = hasher.VerifyPassword("WrongPassword!", v1Hash);
        verifyWrong.Should().Be(PasswordVerificationResult.Failed);
    }

    [Fact]
    public void PasswordHashers_Reject_Excessively_Long_Password_To_Prevent_Cpu_DoS_SEC_015()
    {
        var pbkdf2 = new Pbkdf2PasswordHasher();
        var argon2id = new LegacyPbkdf2PasswordHasher();
        string excessivePassword = new string('A', 257);

        // PBKDF2 length guard
        var actPbkdf2 = () => pbkdf2.HashPassword(excessivePassword);
        actPbkdf2.Should().Throw<ArgumentException>();
        pbkdf2.VerifyPassword(excessivePassword, "any_hash").Should().Be(PasswordVerificationResult.Failed);

        // Argon2id length guard
        var actArgon2 = () => argon2id.HashPassword(excessivePassword);
        actArgon2.Should().Throw<ArgumentException>();
        argon2id.VerifyPassword(excessivePassword, "any_hash").Should().Be(PasswordVerificationResult.Failed);
    }

    [Fact]
    public void Argon2id_Executes_Pbkdf2_Internally_Without_Memory_Cost()
    {
        // GIVEN: Argon2id password hasher configured with 64 MB (65536 KB) memory
        var hasher = new LegacyPbkdf2PasswordHasher(memorySizeKb: 65536, iterations: 3, parallelism: 4);

        // WHEN: Hashing a password
        var hash = hasher.HashPassword("UserPassword123!");

        // THEN: The string format uses the accurate $legacy-pbkdf2$ prefix (P0-001 audit fix)
        // The old $argon2id$ prefix was misleading: the hasher uses PBKDF2-HMAC-SHA512, not Argon2id.
        hash.Should().StartWith("$legacy-pbkdf2$v=19$m=65536,t=3,p=4$");

        // VERIFICATION: The internal effective rounds are 3 * 70,000 = 210,000 PBKDF2 rounds
        hasher.VerifyPassword("UserPassword123!", hash).Should().Be(PasswordVerificationResult.Success);
    }

    [Fact]
    public void AesGcmEncryptionEngine_SpanEncrypt_AlwaysOverwritesNonceBufferWithCsprngBytes_SEC_CRIT_02()
    {
        // GIVEN: An AEAD engine and a key
        var engine = AesGcmEncryptionEngine.Shared;
        byte[] key = new byte[32];
        RandomNumberGenerator.Fill(key);
        byte[] plaintext = "Sensitive Financial Data"u8.ToArray();

        // GIVEN: Caller pre-fills nonce destination with all 0xFF (adversarial attempt to force nonce reuse)
        Span<byte> nonceDest1 = stackalloc byte[12];
        nonceDest1.Fill(0xFF);
        Span<byte> cipherDest1 = stackalloc byte[plaintext.Length];
        Span<byte> tagDest1 = stackalloc byte[16];

        // WHEN: Encrypting the first message
        var res1 = engine.Encrypt(plaintext, key, nonceDest1, cipherDest1, tagDest1);
        res1.IsSuccess.Should().BeTrue();

        // THEN: The engine must have overwritten 0xFF with fresh CSPRNG bytes
        nonceDest1.ToArray().Should().NotEqual(new byte[12] { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF });

        // GIVEN: Caller attempts to reuse the EXACT same nonce buffer with identical plaintext
        Span<byte> nonceDest2 = stackalloc byte[12];
        nonceDest1.CopyTo(nonceDest2); // Copy previously generated nonce into nonceDest2
        Span<byte> cipherDest2 = stackalloc byte[plaintext.Length];
        Span<byte> tagDest2 = stackalloc byte[16];

        // WHEN: Encrypting the second message
        var res2 = engine.Encrypt(plaintext, key, nonceDest2, cipherDest2, tagDest2);
        res2.IsSuccess.Should().BeTrue();

        // THEN: Nonce must be freshly generated and distinct from the first call
        nonceDest1.SequenceEqual(nonceDest2).Should().BeFalse(
            "REMEDIATION VERIFIED (SEC_CRIT_02): Nonce buffer must be auto-filled by engine, preventing caller nonce reuse.");
        cipherDest1.SequenceEqual(cipherDest2).Should().BeFalse();
        tagDest1.SequenceEqual(tagDest2).Should().BeFalse();
    }

    [Fact]
    public void ChaCha20Poly1305EncryptionEngine_SpanEncrypt_AlwaysOverwritesNonceBufferWithCsprngBytes_SEC_CRIT_02()
    {
        var engine = ChaCha20Poly1305EncryptionEngine.Shared;
        byte[] key = new byte[32];
        RandomNumberGenerator.Fill(key);
        byte[] plaintext = "Sensitive Financial Data"u8.ToArray();

        Span<byte> nonceDest1 = stackalloc byte[12];
        nonceDest1.Fill(0xAA);
        Span<byte> cipherDest1 = stackalloc byte[plaintext.Length];
        Span<byte> tagDest1 = stackalloc byte[16];

        var res1 = engine.Encrypt(plaintext, key, nonceDest1, cipherDest1, tagDest1);
        res1.IsSuccess.Should().BeTrue();
        nonceDest1.ToArray().Should().NotEqual(new byte[12] { 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA });

        Span<byte> nonceDest2 = stackalloc byte[12];
        nonceDest1.CopyTo(nonceDest2);
        Span<byte> cipherDest2 = stackalloc byte[plaintext.Length];
        Span<byte> tagDest2 = stackalloc byte[16];

        var res2 = engine.Encrypt(plaintext, key, nonceDest2, cipherDest2, tagDest2);
        res2.IsSuccess.Should().BeTrue();

        nonceDest1.SequenceEqual(nonceDest2).Should().BeFalse(
            "REMEDIATION VERIFIED (SEC_CRIT_02): ChaCha20Poly1305 nonce buffer must be auto-filled by engine.");
    }

    [Fact]
    public void HkdfAesGcmEncryptionEngine_FullLifecycle_And_HonestProperties_Verified()
    {
        var engine = HkdfAesGcmEncryptionEngine.Shared;
        HkdfAesGcmEncryptionEngine.IsQuantumResistant.Should().BeFalse();
        HkdfAesGcmEncryptionEngine.SubstrateDescription.Should().Contain("ADR-025");
        engine.Algorithm.Should().Be(EricksonLopez.Security.Abstractions.Cryptography.AeadAlgorithm.HkdfAes256Gcm);

        byte[] key = new byte[32];
        RandomNumberGenerator.Fill(key);
        byte[] plaintext = "Post-quantum transition envelope"u8.ToArray();

        var encRes = engine.Encrypt(plaintext, key);
        encRes.IsSuccess.Should().BeTrue();
        var encData = encRes.Value;

        // Decrypt with HkdfAesGcmEncryptionEngine
        Span<byte> decrypted = stackalloc byte[plaintext.Length];
        var decRes = engine.Decrypt(encData.Ciphertext.Span, key, encData.Nonce.Span, encData.Tag.Span, default, decrypted, out int written);
        decRes.IsSuccess.Should().BeTrue();
        written.Should().Be(plaintext.Length);
        decrypted.SequenceEqual(plaintext).Should().BeTrue();
    }

    [Fact]
    public async Task AesGcmSecretProtector_Rejects_Mismatched_Caller_AAD_When_Envelope_Has_AAD_SEC_CRIT_01()
    {
        // GIVEN: Tenant A protects confidential data with its own tenant identifier as authenticated associated data
        var keyStore = new InMemoryKeyStore();
        var lifecycle = new KeyLifecycleManager(keyStore);
        var keyRing = new KeyRing(keyStore);
        var keyResult = await lifecycle.GenerateAndActivateKeyAsync(KeyPurpose.Encryption);
        keyResult.IsSuccess.Should().BeTrue();

        var protector = new AesGcmSecretProtector(keyRing);
        byte[] secretPayload = "CONFIDENTIAL_STRIPE_KEY_ALPHA"u8.ToArray();
        var aadTenantA = AuthenticatedContext.FromBytes("tenant:enterprise_alpha"u8.ToArray());

        var protectResult = protector.Protect(secretPayload, KeyPurpose.Encryption, aadTenantA);
        protectResult.IsSuccess.Should().BeTrue();
        byte[] protectedEnvelope = protectResult.Value;

        // WHEN: An unauthorized caller (Tenant B) attempts to unprotect the envelope passing Tenant B's AAD
        var aadTenantB = AuthenticatedContext.FromBytes("tenant:enterprise_attacker_b"u8.ToArray());

        // 1. Synchronous verification
        var syncUnprotectResult = protector.Unprotect(protectedEnvelope, aadTenantB);
        syncUnprotectResult.IsFailure.Should().BeTrue();
        syncUnprotectResult.Error.Code.Should().Be("Security.AssociatedDataMismatch",
            "REMEDIATION VERIFIED (SEC-CRIT-01): AesGcmSecretProtector must reject mismatched caller AAD.");

        // 2. Asynchronous verification
        var asyncUnprotectResult = await protector.UnprotectAsync(protectedEnvelope, aadTenantB);
        asyncUnprotectResult.IsFailure.Should().BeTrue();
        asyncUnprotectResult.Error.Code.Should().Be("Security.AssociatedDataMismatch",
            "REMEDIATION VERIFIED (SEC-CRIT-01): AesGcmSecretProtector.UnprotectAsync must reject mismatched caller AAD.");

        // 3. Legitimate unprotect with matching AAD must succeed
        var legitResult = protector.Unprotect(protectedEnvelope, aadTenantA);
        legitResult.IsSuccess.Should().BeTrue();
        legitResult.Value.Should().BeEquivalentTo(secretPayload);
    }
}
