// Copyright © Erickson Lopez. MIT License.
// ReSharper disable once RedundantUsingDirective

namespace EricksonLopez.Security.Tests.Tokens;

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using EricksonLopez.Result;
using EricksonLopez.Security.Abstractions.Errors;
using EricksonLopez.Security.Abstractions.Primitives;
using EricksonLopez.Security.Abstractions.Tokens;
using EricksonLopez.Security.Tokens;
using Xunit;

public sealed class TokenSecurityTests
{
    private sealed class FakeCustomTokenHasher : ITokenHasher
    {
        public string HashToken(ReadOnlySpan<char> token) => "custom-hashed-token-val";

        public bool VerifyToken(ReadOnlySpan<char> token, string expectedHash) =>
            expectedHash == "custom-hashed-token-val";
    }

    // ==========================================
    // InMemoryApiKeyStore Tests
    // ==========================================

    [Fact]
    public async Task InMemoryApiKeyStore_Operations_WorkCorrectly()
    {
        var store = new InMemoryApiKeyStore();

        // Null key save
        var exNull = await Assert.ThrowsAsync<ArgumentNullException>(async () => await store.SaveAsync(null!));
        Assert.Equal("apiKey", exNull.ParamName);

        // Key not found
        var notFound = await store.GetByIdAsync(new ApiKeyId("ek_live_notfound"));
        Assert.True(notFound.IsFailure);
        Assert.Equal("Security.KeyNotFound", notFound.Error.Code);

        // Save key
        var keyId = new ApiKeyId("ek_live_abc123");
        var apiKey = new ApiKey(keyId, "owner-1", "Test Key", "ek_live_abc123_****", "hashed-secret", DateTimeOffset.UtcNow, null, null);
        var saveResult = await store.SaveAsync(apiKey);
        Assert.True(saveResult.IsSuccess);

        // Get key
        var getResult = await store.GetByIdAsync(keyId);
        Assert.True(getResult.IsSuccess);
        Assert.Equal(keyId, getResult.Value.Id);

        // Revoke unknown key
        var revokeUnknown = await store.RevokeAsync(new ApiKeyId("ek_live_unknown"));
        Assert.True(revokeUnknown.IsFailure);

        // Revoke existing key
        var revokeResult = await store.RevokeAsync(keyId);
        Assert.True(revokeResult.IsSuccess);

        var revokedGet = await store.GetByIdAsync(keyId);
        Assert.True(revokedGet.IsSuccess);
        Assert.True(revokedGet.Value.IsRevoked);
    }

    // ==========================================
    // OpaqueTokenGenerator Tests
    // ==========================================

    [Fact]
    public void OpaqueTokenGenerator_GenerateToken_ProducesValidTokens()
    {
        var generator = OpaqueTokenGenerator.Shared;

        var token = generator.GenerateToken(32);
        Assert.False(token.IsEmpty);
        Assert.True(token.Length > 0);

        var urlSafe = generator.GenerateUrlSafeToken(16);
        Assert.False(string.IsNullOrWhiteSpace(urlSafe));

        var hex = generator.GenerateHexToken(16);
        Assert.Equal(32, hex.Length);
        Assert.Matches("^[0-9a-f]{32}$", hex);
    }

    [Fact]
    public void OpaqueTokenGenerator_TryGenerateUrlSafeToken_WritesExpectedCharacters()
    {
        var generator = OpaqueTokenGenerator.Shared;
        Span<char> destination = stackalloc char[64];

        // 32 bytes entropy -> 43 characters Base64URL
        var success = generator.TryGenerateUrlSafeToken(destination, 32, out int charsWritten);
        Assert.True(success);
        Assert.Equal(43, charsWritten);
        Assert.Matches("^[A-Za-z0-9_-]{43}$", destination[..charsWritten].ToString());

        // Too small destination buffer
        Span<char> tiny = stackalloc char[10];
        var fail = generator.TryGenerateUrlSafeToken(tiny, 32, out int zeroWritten);
        Assert.False(fail);
        Assert.Equal(0, zeroWritten);

        // Invalid byteLength <= 0 throws
        var exInvalidByteLength = Assert.Throws<ArgumentOutOfRangeException>(() => generator.TryGenerateUrlSafeToken(new char[64], 0, out _));
        Assert.Equal("byteLength", exInvalidByteLength.ParamName);
        Assert.Contains("Byte length must be greater than zero.", exInvalidByteLength.Message);
    }

    [Fact]
    public void OpaqueTokenGenerator_GenerateNumericCode_ProducesExactDigitCount()
    {
        var generator = OpaqueTokenGenerator.Shared;

        var code1 = generator.GenerateNumericCode(1);
        Assert.Single(code1);
        Assert.True(char.IsDigit(code1[0]));

        var code6 = generator.GenerateNumericCode(6);
        Assert.Equal(6, code6.Length);
        Assert.True(int.TryParse(code6, out _));

        var code16 = generator.GenerateNumericCode(16);
        Assert.Equal(16, code16.Length);
        Assert.True(long.TryParse(code16, out _));

        var exZero = Assert.Throws<ArgumentOutOfRangeException>(() => generator.GenerateNumericCode(0));
        Assert.Equal("digits", exZero.ParamName);
        Assert.Contains("Digits must be between 1 and 16.", exZero.Message);

        var exNegative = Assert.Throws<ArgumentOutOfRangeException>(() => generator.GenerateNumericCode(-1));
        Assert.Equal("digits", exNegative.ParamName);
        Assert.Contains("Digits must be between 1 and 16.", exNegative.Message);

        var exTooLarge = Assert.Throws<ArgumentOutOfRangeException>(() => generator.GenerateNumericCode(17));
        Assert.Equal("digits", exTooLarge.ParamName);
        Assert.Contains("Digits must be between 1 and 16.", exTooLarge.Message);
    }

    // ==========================================
    // HmacSha256TokenHasher Tests
    // ==========================================

    [Fact]
    public void HmacSha256TokenHasher_Constructors_And_Hash_Verify()
    {
        var exEmpty = Assert.Throws<ArgumentException>(() => new HmacSha256TokenHasher(ReadOnlySpan<byte>.Empty));
        Assert.Equal("pepperKey", exEmpty.ParamName);
        Assert.Contains("Pepper key cannot be empty.", exEmpty.Message);

        byte[] pepper = [1, 2, 3, 4, 5, 6, 7, 8];
        var pepperedHasher = new HmacSha256TokenHasher(pepper);
        var unpepperedHasher = new HmacSha256TokenHasher();

        var token = "user-refresh-token-987654321";

        var pepperedHash = pepperedHasher.HashToken(token);
        var unpepperedHash = unpepperedHasher.HashToken(token);

        Assert.NotEqual(pepperedHash, unpepperedHash);
        Assert.True(pepperedHasher.VerifyToken(token, pepperedHash));
        Assert.True(unpepperedHasher.VerifyToken(token, unpepperedHash));
        Assert.False(pepperedHasher.VerifyToken("different-token", pepperedHash));
        Assert.False(unpepperedHasher.VerifyToken("different-token", unpepperedHash));

        // Empty token
        var exEmptyToken = Assert.Throws<ArgumentException>(() => unpepperedHasher.HashToken(""));
        Assert.Equal("token", exEmptyToken.ParamName);
        Assert.Contains("Token cannot be empty.", exEmptyToken.Message);

        // Verification edge cases
        Assert.False(unpepperedHasher.VerifyToken("", unpepperedHash));
        Assert.False(unpepperedHasher.VerifyToken(token, ""));
        Assert.False(unpepperedHasher.VerifyToken(token, "   "));
        Assert.False(unpepperedHasher.VerifyToken(token, null!));

        // Large token (> 256 bytes) to test ArrayPool renting
        var largeToken = new string('A', 500);
        var largeHash = unpepperedHasher.HashToken(largeToken);
        Assert.True(unpepperedHasher.VerifyToken(largeToken, largeHash));
    }

    [Fact]
    public void HmacSha256TokenHasher_TryHashToken_ComputesHashWithoutHeapAllocations()
    {
        // FINDING-NEW-07: Verify TryHashToken overload and zero allocation behavior
        var hasher = new HmacSha256TokenHasher();
        var token = "sensitive-api-token-value-12345";

        Span<char> destination = stackalloc char[64];
        var success = hasher.TryHashToken(token, destination, out int charsWritten);

        Assert.True(success);
        Assert.Equal(64, charsWritten);

        var expectedHash = Convert.ToHexString(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(token))).ToLowerInvariant();
        Assert.True(destination.SequenceEqual(expectedHash.AsSpan()));

        // Buffer boundaries: maxByteCount <= 256 vs > 256 (ArrayPool rent)
        var tokenBoundaryStack = new string('A', 85); // 85 * 3 = 255 bytes max <= 256
        Assert.True(hasher.TryHashToken(tokenBoundaryStack, destination, out _));
        var tokenBoundaryRent = new string('A', 86); // 86 * 3 = 258 bytes max > 256
        Assert.True(hasher.TryHashToken(tokenBoundaryRent, destination, out _));

        // Peppered TryHashToken matches HMACSHA256.HashData exactly
        byte[] pepper = [1, 2, 3, 4, 5, 6, 7, 8];
        using var pepperedHasher = new HmacSha256TokenHasher(pepper);
        var expectedHmac = Convert.ToHexString(HMACSHA256.HashData(pepper, System.Text.Encoding.UTF8.GetBytes(token))).ToLowerInvariant();
        Assert.True(pepperedHasher.TryHashToken(token, destination, out _));
        Assert.True(destination.SequenceEqual(expectedHmac.AsSpan()));

        // Buffer too small returns false
        Span<char> smallDest = stackalloc char[63];
        Assert.False(hasher.TryHashToken(token, smallDest, out int writtenSmall));
        Assert.Equal(0, writtenSmall);

        // Empty token returns false
        Assert.False(hasher.TryHashToken("", destination, out int writtenEmpty));
        Assert.Equal(0, writtenEmpty);
    }

    [Fact]
    public void HmacSha256TokenHasher_Dispose_ScrubsPepperKey_AndThrowsOnSubsequentUse()
    {
        byte[] pepper = [10, 20, 30, 40, 50, 60, 70, 80];
        var hasher = new HmacSha256TokenHasher(pepper);

        Assert.False(hasher.IsDisposed);
        var hash = hasher.HashToken("sample-token");
        Assert.NotNull(hash);

        hasher.Dispose();
        Assert.True(hasher.IsDisposed);

        // Multiple dispose calls are idempotent and safe
        hasher.Dispose();
        Assert.True(hasher.IsDisposed);

        // Subsequent operations throw ObjectDisposedException
        Assert.Throws<ObjectDisposedException>(() => hasher.HashToken("sample-token"));
        Assert.Throws<ObjectDisposedException>(() => hasher.VerifyToken("sample-token", hash));

        bool threwOnTryHash = false;
        try
        {
            Span<char> dest = stackalloc char[64];
            hasher.TryHashToken("sample-token", dest, out _);
        }
        catch (ObjectDisposedException)
        {
            threwOnTryHash = true;
        }

        Assert.True(threwOnTryHash);
    }

    // ==========================================
    // ApiKeyGenerator & Validator Tests
    // ==========================================

    [Fact]
    public void ApiKeyGenerator_ArgumentValidation_ThrowsExpected()
    {
        var generator = new ApiKeyGenerator(new HmacSha256TokenHasher());

        Assert.Throws<ArgumentException>(() => generator.GenerateApiKey("", "name"));
        Assert.Throws<ArgumentException>(() => generator.GenerateApiKey("   ", "name"));
        Assert.Throws<ArgumentNullException>(() => generator.GenerateApiKey(null!, "name"));

        Assert.Throws<ArgumentException>(() => generator.GenerateApiKey("owner", ""));
        Assert.Throws<ArgumentException>(() => generator.GenerateApiKey("owner", "   "));
        Assert.Throws<ArgumentNullException>(() => generator.GenerateApiKey("owner", null!));

        Assert.Throws<ArgumentException>(() => generator.GenerateApiKey("owner", "name", ""));
        Assert.Throws<ArgumentException>(() => generator.GenerateApiKey("owner", "name", "   "));
        Assert.Throws<ArgumentNullException>(() => generator.GenerateApiKey("owner", "name", null!));
    }

    [Fact]
    public void ApiKeyGenerator_GeneratesWithLifetimeAndCustomHasher()
    {
        var customHasher = new FakeCustomTokenHasher();
        var generator = new ApiKeyGenerator(customHasher);

        var issuanceNoExpiry = generator.GenerateApiKey("owner-1", "Test Key", "ek_live", lifetime: null);
        Assert.Null(issuanceNoExpiry.Key.ExpiresAtUtc);
        Assert.Equal($"{issuanceNoExpiry.Key.Id.Value}_****", issuanceNoExpiry.Key.DisplayPrefix);
        Assert.Equal("custom-hashed-token-val", issuanceNoExpiry.Key.HashedSecret);

        var issuanceWithExpiry = generator.GenerateApiKey("owner-1", "Test Key", "ek_live", lifetime: TimeSpan.FromDays(7));
        Assert.NotNull(issuanceWithExpiry.Key.ExpiresAtUtc);
    }

    [Fact]
    public async Task ValidateApiKeyAsync_InvalidPlaintextAndMissingKeys_ReturnsExpectedErrors()
    {
        var store = new InMemoryApiKeyStore();
        var generator = new ApiKeyGenerator(new HmacSha256TokenHasher());
        var validator = new ApiKeyValidator(store);

        var nullStoreEx = Assert.Throws<ArgumentNullException>(() => new ApiKeyValidator(null!));
        Assert.Equal("apiKeyStore", nullStoreEx.ParamName);

        // 1. Null / whitespace plaintext key
        var resNull = await validator.ValidateApiKeyAsync(null!);
        Assert.True(resNull.IsFailure);
        Assert.Contains("null or empty", resNull.Error.Description);

        var resEmpty = await validator.ValidateApiKeyAsync("   ");
        Assert.True(resEmpty.IsFailure);

        // 2. Malformed key without underscore or underscore at end / start
        var resNoUnderscore = await validator.ValidateApiKeyAsync("malformedkeywithoutseparator");
        Assert.True(resNoUnderscore.IsFailure);
        Assert.Contains("format is invalid", resNoUnderscore.Error.Description);

        var resLeadingUnderscore = await validator.ValidateApiKeyAsync("_secret");
        Assert.True(resLeadingUnderscore.IsFailure);
        Assert.Contains("format is invalid", resLeadingUnderscore.Error.Description);

        var resTrailingUnderscore = await validator.ValidateApiKeyAsync("ek_live_key_");
        Assert.True(resTrailingUnderscore.IsFailure);
        Assert.Contains("format is invalid", resTrailingUnderscore.Error.Description);

        // 3. Key not found in store (normalized to prevent account enumeration)
        var resNotFound = await validator.ValidateApiKeyAsync("ek_live_unknownid_somesecret");
        Assert.True(resNotFound.IsFailure);
        Assert.Equal("Invalid API key credentials.", resNotFound.Error.Description);

        // 4. Secret mismatch (normalized to prevent account enumeration)
        var issuance = generator.GenerateApiKey("tenant-1", "Test Key", "ek_live_custom__");
        await store.SaveAsync(issuance.Key);

        var wrongSecretKey = $"{issuance.Key.Id.Value}_wrongsecretpart12345";
        var resWrongSecret = await validator.ValidateApiKeyAsync(wrongSecretKey);
        Assert.True(resWrongSecret.IsFailure);
        Assert.Equal("Invalid API key credentials.", resWrongSecret.Error.Description);

        // 5. Expired key
        var expiredKey = issuance.Key with { ExpiresAtUtc = DateTimeOffset.UtcNow.AddMinutes(-5) };
        await store.SaveAsync(expiredKey);
        var resExpired = await validator.ValidateApiKeyAsync(issuance.PlaintextApiKey);
        Assert.True(resExpired.IsFailure);
        Assert.Equal("Security.TokenExpired", resExpired.Error.Code);

        // 6. Revoked key
        var revokedKey = issuance.Key with { RevokedAtUtc = DateTimeOffset.UtcNow.AddMinutes(-1), ExpiresAtUtc = null };
        await store.SaveAsync(revokedKey);
        var resRevoked = await validator.ValidateApiKeyAsync(issuance.PlaintextApiKey);
        Assert.True(resRevoked.IsFailure);
        Assert.Equal("Security.TokenRevoked", resRevoked.Error.Code);

        // 7. Custom hasher validation
        var customValidator = new ApiKeyValidator(store, new FakeCustomTokenHasher());
        var customIssuance = new ApiKeyGenerator(new FakeCustomTokenHasher()).GenerateApiKey("owner-2", "Key 2");
        await store.SaveAsync(customIssuance.Key);
        var resCustom = await customValidator.ValidateApiKeyAsync(customIssuance.PlaintextApiKey);
        Assert.True(resCustom.IsSuccess);
    }

    [Fact]
    public async Task ApiKeyGeneratorAndValidator_EndToEndFlow_ValidatesSuccessfully()
    {
        var store = new InMemoryApiKeyStore();
        var generator = new ApiKeyGenerator(new HmacSha256TokenHasher());
        var validator = new ApiKeyValidator(store);

        var scopes = new HashSet<string> { "orders:read", "orders:write" };

        var issuance = generator.GenerateApiKey(
            ownerId: "tenant-42",
            name: "Order Processing Service",
            prefix: "ek_live",
            lifetime: TimeSpan.FromDays(30),
            scopes: scopes);

        await store.SaveAsync(issuance.Key);

        var validationResult = await validator.ValidateApiKeyAsync(issuance.PlaintextApiKey);

        Assert.True(validationResult.IsSuccess);
        var key = validationResult.Value;
        Assert.Equal("tenant-42", key.OwnerId);
        Assert.True(key.HasScope("orders:read"));
        Assert.False(key.HasScope("admin"));

        await store.RevokeAsync(key.Id);
        var revokedValidation = await validator.ValidateApiKeyAsync(issuance.PlaintextApiKey);

        Assert.True(revokedValidation.IsFailure);
        Assert.Equal("Security.TokenRevoked", revokedValidation.Error.Code);
    }

    [Fact]
    public async Task ApiKeyGenerator_GenerateApiKeySecretBuffer_AllowsZeroizableHandling()
    {
        var store = new InMemoryApiKeyStore();
        var generator = new ApiKeyGenerator(new HmacSha256TokenHasher());
        var validator = new ApiKeyValidator(store);

        var (apiKeyEntity, secretBuffer) = generator.GenerateApiKeySecretBuffer(
            ownerId: "tenant-secret-mem",
            name: "Memory Safe Service",
            prefix: "ek_live");

        using (secretBuffer)
        {
            await store.SaveAsync(apiKeyEntity);
            string keyString = System.Text.Encoding.UTF8.GetString(secretBuffer.Span);
            var validationResult = await validator.ValidateApiKeyAsync(keyString);
            Assert.True(validationResult.IsSuccess);
        }

        Assert.True(secretBuffer.IsDisposed);
    }
}
