// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Abstractions.Tests;

using System;
using EricksonLopez.Security.Abstractions.Errors;
using EricksonLopez.Security.Abstractions.Events;
using EricksonLopez.Security.Abstractions.Primitives;
using Xunit;

public sealed class ErrorAndEventTests
{
    // ==========================================
    // SecurityError Catalog Tests
    // ==========================================

    [Fact]
    public void SecurityError_InvalidCiphertext_ReturnsExpectedError()
    {
        var errDefault = SecurityError.InvalidCiphertext();
        Assert.Equal("Security.InvalidCiphertext", errDefault.Code);
        Assert.Equal("The provided ciphertext is invalid, corrupted, or has an unexpected format.", errDefault.Description);

        var errCustom = SecurityError.InvalidCiphertext("Truncated ciphertext buffer.");
        Assert.Equal("Security.InvalidCiphertext", errCustom.Code);
        Assert.Equal("Truncated ciphertext buffer.", errCustom.Description);
    }

    [Fact]
    public void SecurityError_AuthenticationTagMismatch_ReturnsExpectedError()
    {
        var errDefault = SecurityError.AuthenticationTagMismatch();
        Assert.Equal("Security.AuthenticationTagMismatch", errDefault.Code);
        Assert.Equal("Decryption failed: authentication tag verification failed (ciphertext or associated data was tampered with).", errDefault.Description);

        var errCustom = SecurityError.AuthenticationTagMismatch("AAD mismatch detected.");
        Assert.Equal("Security.AuthenticationTagMismatch", errCustom.Code);
        Assert.Equal("AAD mismatch detected.", errCustom.Description);
    }

    [Fact]
    public void SecurityError_InvalidKey_ReturnsExpectedError()
    {
        var errDefault = SecurityError.InvalidKey();
        Assert.Equal("Security.InvalidKey", errDefault.Code);
        Assert.Equal("The cryptographic key material is invalid or of an unsupported length.", errDefault.Description);

        var errCustom = SecurityError.InvalidKey("Key must be exactly 32 bytes.");
        Assert.Equal("Security.InvalidKey", errCustom.Code);
        Assert.Equal("Key must be exactly 32 bytes.", errCustom.Description);
    }

    [Fact]
    public void SecurityError_KeyNotFound_ReturnsExpectedError()
    {
        var errDefault = SecurityError.KeyNotFound("key-999");
        Assert.Equal("Security.KeyNotFound", errDefault.Code);
        Assert.Equal("The cryptographic key with identifier 'key-999' was not found.", errDefault.Description);

        var errCustom = SecurityError.KeyNotFound("key-999", "Custom store not found.");
        Assert.Equal("Security.KeyNotFound", errCustom.Code);
        Assert.Equal("Custom store not found.", errCustom.Description);
    }

    [Fact]
    public void SecurityError_KeyExpired_ReturnsExpectedError()
    {
        var errDefault = SecurityError.KeyExpired("key-123");
        Assert.Equal("Security.KeyExpired", errDefault.Code);
        Assert.Equal("The cryptographic key with identifier 'key-123' has expired.", errDefault.Description);

        var errCustom = SecurityError.KeyExpired("key-123", "Expired on 2026-01-01.");
        Assert.Equal("Security.KeyExpired", errCustom.Code);
        Assert.Equal("Expired on 2026-01-01.", errCustom.Description);
    }

    [Fact]
    public void SecurityError_KeyRevoked_ReturnsExpectedError()
    {
        var errDefault = SecurityError.KeyRevoked("key-456");
        Assert.Equal("Security.KeyRevoked", errDefault.Code);
        Assert.Equal("The cryptographic key with identifier 'key-456' has been revoked.", errDefault.Description);

        var errCustom = SecurityError.KeyRevoked("key-456", "Revoked by security administrator.");
        Assert.Equal("Security.KeyRevoked", errCustom.Code);
        Assert.Equal("Revoked by security administrator.", errCustom.Description);
    }

    [Fact]
    public void SecurityError_KeyPurposeMismatch_ReturnsExpectedError()
    {
        var err = SecurityError.KeyPurposeMismatch("Encryption", "Signing");
        Assert.Equal("Security.KeyPurposeMismatch", err.Code);
        Assert.Equal("Key purpose mismatch. Key is authorized for 'Signing', but operation requested 'Encryption'.", err.Description);
    }

    [Fact]
    public void SecurityError_InvalidToken_ReturnsExpectedError()
    {
        var errDefault = SecurityError.InvalidToken();
        Assert.Equal("Security.InvalidToken", errDefault.Code);
        Assert.Equal("The security token is invalid or malformed.", errDefault.Description);

        var errCustom = SecurityError.InvalidToken("Malformed header.");
        Assert.Equal("Security.InvalidToken", errCustom.Code);
        Assert.Equal("Malformed header.", errCustom.Description);
    }

    [Fact]
    public void SecurityError_TokenExpired_ReturnsExpectedError()
    {
        var errDefault = SecurityError.TokenExpired();
        Assert.Equal("Security.TokenExpired", errDefault.Code);
        Assert.Equal("The security token has expired.", errDefault.Description);

        var errCustom = SecurityError.TokenExpired("Expired 5 minutes ago.");
        Assert.Equal("Security.TokenExpired", errCustom.Code);
        Assert.Equal("Expired 5 minutes ago.", errCustom.Description);
    }

    [Fact]
    public void SecurityError_TokenRevoked_ReturnsExpectedError()
    {
        var errDefault = SecurityError.TokenRevoked();
        Assert.Equal("Security.TokenRevoked", errDefault.Code);
        Assert.Equal("The security token has been revoked.", errDefault.Description);

        var errCustom = SecurityError.TokenRevoked("Session was terminated.");
        Assert.Equal("Security.TokenRevoked", errCustom.Code);
        Assert.Equal("Session was terminated.", errCustom.Description);
    }

    [Fact]
    public void SecurityError_InvalidPassword_ReturnsExpectedError()
    {
        var errDefault = SecurityError.InvalidPassword();
        Assert.Equal("Security.InvalidPassword", errDefault.Code);
        Assert.Equal("Password verification failed.", errDefault.Description);

        var errCustom = SecurityError.InvalidPassword("Incorrect passphrase.");
        Assert.Equal("Security.InvalidPassword", errCustom.Code);
        Assert.Equal("Incorrect passphrase.", errCustom.Description);
    }

    [Fact]
    public void SecurityError_UnsupportedAlgorithm_ReturnsExpectedError()
    {
        var errDefault = SecurityError.UnsupportedAlgorithm("DES-CBC");
        Assert.Equal("Security.UnsupportedAlgorithm", errDefault.Code);
        Assert.Equal("The cryptographic algorithm 'DES-CBC' is not supported.", errDefault.Description);

        var errCustom = SecurityError.UnsupportedAlgorithm("DES-CBC", "Insecure legacy algorithm.");
        Assert.Equal("Security.UnsupportedAlgorithm", errCustom.Code);
        Assert.Equal("Insecure legacy algorithm.", errCustom.Description);
    }

    [Fact]
    public void SecurityError_SecurityPolicyViolation_ReturnsExpectedError()
    {
        var err = SecurityError.SecurityPolicyViolation("PasswordPolicy", "Must be at least 12 characters.");
        Assert.Equal("Security.PolicyViolation", err.Code);
        Assert.Equal("Security policy 'PasswordPolicy' violation: Must be at least 12 characters.", err.Description);
    }

    [Fact]
    public void SecurityError_SecretNotFound_ReturnsExpectedError()
    {
        var err = SecurityError.SecretNotFound("DatabasePassword");
        Assert.Equal("Security.SecretNotFound", err.Code);
        Assert.Equal("The secret 'DatabasePassword' was not found.", err.Description);
    }

    [Fact]
    public void SecurityError_EncryptionFailed_ReturnsExpectedError()
    {
        var err = SecurityError.EncryptionFailed("Hardware failure.");
        Assert.Equal("Security.EncryptionFailed", err.Code);
        Assert.Equal("Encryption operation failed: Hardware failure.", err.Description);
    }

    [Fact]
    public void SecurityError_DecryptionFailed_ReturnsExpectedError()
    {
        var err = SecurityError.DecryptionFailed("Corrupted padding.");
        Assert.Equal("Security.DecryptionFailed", err.Code);
        Assert.Equal("Decryption operation failed: Corrupted padding.", err.Description);
    }

    // ==========================================
    // Security Events Tests
    // ==========================================

    [Fact]
    public void KeyRotatedEvent_Create_SetsAllPropertiesCorrectly()
    {
        var keyId = KeyIdentifier.New();
        var prev = KeyVersion.Initial;
        var next = prev.Next();
        var before = DateTimeOffset.UtcNow;

        var evt = KeyRotatedEvent.Create(keyId, prev, next, KeyPurpose.Encryption, "tenant-1", "admin-user");

        Assert.NotEqual(Guid.Empty, evt.EventId);
        Assert.True(evt.TimestampUtc >= before);
        Assert.Equal(keyId, evt.KeyId);
        Assert.Equal(prev, evt.PreviousVersion);
        Assert.Equal(next, evt.NewVersion);
        Assert.Equal(KeyPurpose.Encryption, evt.Purpose);
        Assert.Equal("tenant-1", evt.TenantId);
        Assert.Equal("admin-user", evt.ActorId);
        Assert.Equal(SecurityEventSeverity.Informational, evt.Severity);
        Assert.Equal("Security.KeyRotated", evt.EventType);

        var evtDefault = KeyRotatedEvent.Create(keyId, prev, next, KeyPurpose.Encryption);
        Assert.Null(evtDefault.TenantId);
        Assert.Null(evtDefault.ActorId);
    }

    [Fact]
    public void KeyRevokedEvent_Create_SetsAllPropertiesCorrectly()
    {
        var keyId = KeyIdentifier.New();
        var version = KeyVersion.Initial;
        var before = DateTimeOffset.UtcNow;

        var evt = KeyRevokedEvent.Create(keyId, version, KeyPurpose.Signing, "Compromise detected", "tenant-2", "security-officer");

        Assert.NotEqual(Guid.Empty, evt.EventId);
        Assert.True(evt.TimestampUtc >= before);
        Assert.Equal(keyId, evt.KeyId);
        Assert.Equal(version, evt.Version);
        Assert.Equal(KeyPurpose.Signing, evt.Purpose);
        Assert.Equal("Compromise detected", evt.Reason);
        Assert.Equal("tenant-2", evt.TenantId);
        Assert.Equal("security-officer", evt.ActorId);
        Assert.Equal(SecurityEventSeverity.High, evt.Severity);
        Assert.Equal("Security.KeyRevoked", evt.EventType);

        var evtDefault = KeyRevokedEvent.Create(keyId, version, KeyPurpose.Signing, "Reason");
        Assert.Null(evtDefault.TenantId);
        Assert.Null(evtDefault.ActorId);
    }

    [Fact]
    public void ApiKeyCreatedEvent_Create_SetsAllPropertiesCorrectly()
    {
        var keyId = ApiKeyId.New();
        var before = DateTimeOffset.UtcNow;

        var evt = ApiKeyCreatedEvent.Create(keyId, "owner-42", "ek_live_***", "tenant-3", "app-client");

        Assert.NotEqual(Guid.Empty, evt.EventId);
        Assert.True(evt.TimestampUtc >= before);
        Assert.Equal(keyId, evt.KeyId);
        Assert.Equal("owner-42", evt.OwnerId);
        Assert.Equal("ek_live_***", evt.DisplayPrefix);
        Assert.Equal("tenant-3", evt.TenantId);
        Assert.Equal("app-client", evt.ActorId);
        Assert.Equal(SecurityEventSeverity.Informational, evt.Severity);
        Assert.Equal("Security.ApiKeyCreated", evt.EventType);

        var evtDefault = ApiKeyCreatedEvent.Create(keyId, "owner-42", "ek_live_***");
        Assert.Null(evtDefault.TenantId);
        Assert.Null(evtDefault.ActorId);
    }

    [Fact]
    public void ApiKeyRevokedEvent_Create_SetsAllPropertiesCorrectly()
    {
        var keyId = ApiKeyId.New();
        var before = DateTimeOffset.UtcNow;

        var evt = ApiKeyRevokedEvent.Create(keyId, "owner-42", "Leaked on GitHub", "tenant-3", "admin");

        Assert.NotEqual(Guid.Empty, evt.EventId);
        Assert.True(evt.TimestampUtc >= before);
        Assert.Equal(keyId, evt.KeyId);
        Assert.Equal("owner-42", evt.OwnerId);
        Assert.Equal("Leaked on GitHub", evt.Reason);
        Assert.Equal("tenant-3", evt.TenantId);
        Assert.Equal("admin", evt.ActorId);
        Assert.Equal(SecurityEventSeverity.Warning, evt.Severity);
        Assert.Equal("Security.ApiKeyRevoked", evt.EventType);

        var evtDefault = ApiKeyRevokedEvent.Create(keyId, "owner-42", "User request");
        Assert.Null(evtDefault.TenantId);
        Assert.Null(evtDefault.ActorId);
    }

    [Fact]
    public void SecretRotatedEvent_Create_SetsAllPropertiesCorrectly()
    {
        var before = DateTimeOffset.UtcNow;
        var evt = SecretRotatedEvent.Create("ApiKeySecret", "tenant-4", "vault-agent");

        Assert.NotEqual(Guid.Empty, evt.EventId);
        Assert.True(evt.TimestampUtc >= before);
        Assert.Equal("ApiKeySecret", evt.SecretName);
        Assert.Equal("tenant-4", evt.TenantId);
        Assert.Equal("vault-agent", evt.ActorId);
        Assert.Equal(SecurityEventSeverity.Informational, evt.Severity);
        Assert.Equal("Security.SecretRotated", evt.EventType);

        var evtDefault = SecretRotatedEvent.Create("ApiKeySecret");
        Assert.Null(evtDefault.TenantId);
        Assert.Null(evtDefault.ActorId);
    }

    [Fact]
    public void SecurityPolicyViolatedEvent_Create_SetsAllPropertiesCorrectly()
    {
        var before = DateTimeOffset.UtcNow;
        var evt = SecurityPolicyViolatedEvent.Create("PasswordPolicy", "Too short", "/api/auth/register", "tenant-5", "guest-user");

        Assert.NotEqual(Guid.Empty, evt.EventId);
        Assert.True(evt.TimestampUtc >= before);
        Assert.Equal("PasswordPolicy", evt.PolicyName);
        Assert.Equal("Too short", evt.ViolationDetails);
        Assert.Equal("/api/auth/register", evt.TargetResource);
        Assert.Equal("tenant-5", evt.TenantId);
        Assert.Equal("guest-user", evt.ActorId);
        Assert.Equal(SecurityEventSeverity.Warning, evt.Severity);
        Assert.Equal("Security.PolicyViolated", evt.EventType);

        var evtDefault = SecurityPolicyViolatedEvent.Create("PasswordPolicy", "Too short");
        Assert.Null(evtDefault.TargetResource);
        Assert.Null(evtDefault.TenantId);
        Assert.Null(evtDefault.ActorId);
    }

    [Fact]
    public void SecurityEventSeverity_EnumValues_MatchExpectedIntegers()
    {
        Assert.Equal(1, (int)SecurityEventSeverity.Informational);
        Assert.Equal(2, (int)SecurityEventSeverity.Warning);
        Assert.Equal(3, (int)SecurityEventSeverity.High);
        Assert.Equal(4, (int)SecurityEventSeverity.Critical);
    }

    [Fact]
    public void SecurityError_InvalidNonce_ReturnsExpectedError()
    {
        var errDefault = SecurityError.InvalidNonce();
        Assert.Equal("Security.InvalidNonce", errDefault.Code);
        Assert.Equal("The cryptographic nonce is invalid, of unsupported length, or reused.", errDefault.Description);

        var errCustom = SecurityError.InvalidNonce("Custom invalid nonce details.");
        Assert.Equal("Security.InvalidNonce", errCustom.Code);
        Assert.Equal("Custom invalid nonce details.", errCustom.Description);
    }

    [Fact]
    public void SecurityError_AuditFailed_ReturnsExpectedError()
    {
        var errDefault = SecurityError.AuditFailed();
        Assert.Equal("Security.AuditFailed", errDefault.Code);
        Assert.Equal("Publishing mandatory security audit event failed.", errDefault.Description);

        var errCustom = SecurityError.AuditFailed("Custom audit failure details.");
        Assert.Equal("Security.AuditFailed", errCustom.Code);
        Assert.Equal("Custom audit failure details.", errCustom.Description);
    }

    [Fact]
    public void SecurityError_AssociatedDataMismatch_ReturnsExpectedError()
    {
        var errDefault = SecurityError.AssociatedDataMismatch();
        Assert.Equal("Security.AssociatedDataMismatch", errDefault.Code);
        Assert.Equal("The authenticated associated data (AAD) provided does not match the authenticated context in the secret envelope.", errDefault.Description);

        var errCustom = SecurityError.AssociatedDataMismatch("Custom AAD mismatch details.");
        Assert.Equal("Security.AssociatedDataMismatch", errCustom.Code);
        Assert.Equal("Custom AAD mismatch details.", errCustom.Description);
    }

    [Fact]
    public void SecurityError_PayloadTooLarge_ReturnsExpectedError()
    {
        var errDefault = SecurityError.PayloadTooLarge();
        Assert.Equal("Security.PayloadTooLarge", errDefault.Code);
        Assert.Equal("The payload size exceeds the maximum permitted limit.", errDefault.Description);

        var errCustom = SecurityError.PayloadTooLarge("Custom payload too large details.");
        Assert.Equal("Security.PayloadTooLarge", errCustom.Code);
        Assert.Equal("Custom payload too large details.", errCustom.Description);
    }
}
