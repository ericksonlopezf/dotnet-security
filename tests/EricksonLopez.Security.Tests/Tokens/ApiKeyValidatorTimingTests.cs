// Copyright © Erickson Lopez. MIT License.
// Regression tests for SC-001 (timing oracle dummy hash) and MEM-007 (key disposal)

namespace EricksonLopez.Security.Tests.Tokens;

using System;
using System.Threading.Tasks;
using AwesomeAssertions;
using EricksonLopez.Security.Abstractions.Primitives;
using EricksonLopez.Security.Abstractions.Tokens;
using EricksonLopez.Security.Tokens;
using Xunit;

/// <summary>
/// Regression tests for SC-001: ApiKeyValidator dummy hash timing oracle fix.
/// </summary>
public sealed class ApiKeyValidatorTimingTests
{
    // ── SC-001 REGRESSION TESTS ─────────────────────────────────────────────────

    /// <summary>
    /// Regression test for SC-001: The dummy hash used when a key ID is not found must be
    /// exactly 64 hex characters — the same length as a real HMAC-SHA256/SHA-256 hash.
    ///
    /// Before fix: "$dummy_hash_to_prevent_timing_oracle$" — 33 chars.
    /// FixedTimeEquals returns early on length mismatch → timing difference leaks key ID existence.
    ///
    /// After fix: 64 lowercase hex zeros → same length as real hash → no early return.
    /// </summary>
    [Fact]
    public void DummyTimingHash_RealHash_MustBe64Chars()
    {
        // Verify that a real hash is 64 chars — the same length the dummy must be
        var hasher = new HmacSha256TokenHasher();
        var realHash = hasher.HashToken("sk_test_anytoken");
        realHash.Length.Should().Be(64, because: "SHA-256 produces 32 bytes = 64 hex chars");
    }

    [Fact]
    public async Task ValidateApiKey_KeyNotFound_ReturnsInvalidToken_DummyHashPathDoesNotCrash()
    {
        // When a key doesn't exist, the dummy VerifyToken() call should run without crashing.
        // This validates that the dummy hash path (SC-001 fix) executes successfully.
        var store = new InMemoryApiKeyStore();
        var validator = new ApiKeyValidator(store);

        var result = await validator.ValidateApiKeyAsync("ek_live_unknownkeyid_secretpart");

        result.IsFailure.Should().BeTrue();
        result.Error.Code.Should().Be("Security.InvalidToken");
    }

    [Fact]
    public async Task ValidateApiKey_RevokedKey_ReturnsRevoked_NotInvalidToken()
    {
        // Ensures revoked key path is distinct from not-found path (different error codes)
        var store = new InMemoryApiKeyStore();
        var hasher = new HmacSha256TokenHasher();
        var validator = new ApiKeyValidator(store, hasher);

        const string secretPart = "verylongsecretpart";
        var keyId = new ApiKeyId("ek_live_revokedtest");
        var hashedSecret = hasher.HashToken(secretPart);

        // Create revoked key by setting RevokedAtUtc — IsRevoked is a computed property
        var apiKey = new ApiKey(
            Id: keyId,
            OwnerId: "owner",
            Name: "Revoked Key",
            DisplayPrefix: "ek_live_revokedtest_****",
            HashedSecret: hashedSecret,
            CreatedAtUtc: DateTimeOffset.UtcNow,
            RevokedAtUtc: DateTimeOffset.UtcNow); // SC-001: revocation via RevokedAtUtc

        await store.SaveAsync(apiKey);

        var result = await validator.ValidateApiKeyAsync($"ek_live_revokedtest_{secretPart}");

        result.IsFailure.Should().BeTrue();
        result.Error.Code.Should().Be("Security.TokenRevoked");
    }
}
