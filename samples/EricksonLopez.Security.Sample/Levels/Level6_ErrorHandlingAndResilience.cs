// Copyright © Erickson Lopez. MIT License.

using System;
using System.Text;
using System.Threading.Tasks;
using EricksonLopez.Security.Abstractions.Errors;
using EricksonLopez.Security.Abstractions.KeyManagement;
using EricksonLopez.Security.Abstractions.Primitives;
using EricksonLopez.Security.Abstractions.Secrets;
using EricksonLopez.Security.Privacy.Hibp.Abstractions;
using EricksonLopez.Security.Privacy.Hibp.DependencyInjection;
using EricksonLopez.Security.Privacy.Hibp.Models;
using EricksonLopez.Security.Randomness;
using Microsoft.Extensions.DependencyInjection;

namespace EricksonLopez.Security.Sample.Levels;

/// <summary>
/// Level 6: Functional Error Handling, SecurityError Catalog & Resilience.
/// Demonstrates explicit Result-pattern error handling, tamper detection via AEAD authentication tags,
/// emergency cryptographic key revocation, and constant-time comparison against timing side-channels.
/// </summary>
public static class Level6_ErrorHandlingAndResilience
{
    public static async Task RunAsync()
    {
        Console.WriteLine("\n================================================================================");
        Console.WriteLine("  LEVEL 6: FUNCTIONAL ERROR HANDLING & RESILIENCE");
        Console.WriteLine("================================================================================");

        var services = new ServiceCollection();
        services.AddEricksonLopezSecurity();
        using var provider = services.BuildServiceProvider();

        var keyLifecycle = provider.GetRequiredService<IKeyLifecycleManager>();
        var secretProtector = provider.GetRequiredService<ISecretProtector>();

        // -------------------------------------------------------------------------
        // 1. Tamper Detection & AEAD Tag Mismatch Failure
        // -------------------------------------------------------------------------
        Console.WriteLine("\n[1] Tamper Detection & Cryptographic Tag Mismatch Failure:");

        var activeKeyResult = await keyLifecycle.GenerateAndActivateKeyAsync(KeyPurpose.SecretProtection);
        var activeKey = activeKeyResult.Value;

        var originalData = Encoding.UTF8.GetBytes("FinancialTransfer: $1,000,000 to Account #998877");
        var envelope = (await secretProtector.ProtectAsync(originalData, KeyPurpose.SecretProtection)).Value;

        // Simulate Man-In-The-Middle bit flipping
        var tamperedEnvelope = (byte[])envelope.Clone();
        tamperedEnvelope[^1] ^= 0xFF; // Corrupt authentication tag byte

        var tamperResult = await secretProtector.UnprotectAsync(tamperedEnvelope);
        Console.WriteLine($"  -> Tampered Envelope Decryption Result: {(tamperResult.IsSuccess ? "PASSED (SECURITY FLAW!)" : "FAILED (Tamper Detected)")}");
        Console.WriteLine($"     Error Code: {tamperResult.Error.Code}");
        Console.WriteLine($"     Description: {tamperResult.Error.Description}");

        // -------------------------------------------------------------------------
        // 2. Emergency Key Revocation & Real-Time Cache Eviction (Kill-Switch)
        // -------------------------------------------------------------------------
        Console.WriteLine("\n[2] Emergency Cryptographic Key Revocation & Real-Time Cache Eviction:");

        var secretToRevoke = Encoding.UTF8.GetBytes("Critical Infrastructure Secret");
        var encryptedWithRevokableKey = (await secretProtector.ProtectAsync(secretToRevoke, KeyPurpose.SecretProtection)).Value;

        // Resolve IKeyRevocationNotifier and IKeyRing from DI
        var revocationNotifier = provider.GetRequiredService<IKeyRevocationNotifier>();
        var keyRing = provider.GetRequiredService<IKeyRing>();

        bool revocationSignalReceived = false;
        using var subscription = revocationNotifier.Subscribe((revokedId, revokedVer, revokedPurpose) =>
        {
            revocationSignalReceived = true;
            Console.WriteLine($"     [REVOCATION BROADCAST] KeyId={revokedId.Value}, Version={revokedVer.Value}, Purpose={revokedPurpose}");
        });

        // Emergency Incident: Revoke active key
        var revokeResult = await keyLifecycle.RevokeKeyAsync(
            activeKey.Metadata.KeyId,
            activeKey.Metadata.Version,
            "Compromise suspected in Security Incident #SEC-2026-0042");
        Console.WriteLine($"  -> Revocation Status: {(revokeResult.IsSuccess ? "REVOKED" : "FAILED")}");
        Console.WriteLine($"  -> Real-Time Notifier Signal Received: {revocationSignalReceived}");

        // Attempting to decrypt with revoked key must fail immediately
        var decryptRevokedResult = await secretProtector.UnprotectAsync(encryptedWithRevokableKey);
        Console.WriteLine($"  -> Decrypt Attempt with Revoked Key: {(decryptRevokedResult.IsSuccess ? "SUCCESS" : "REJECTED (Access Terminated)")}");
        Console.WriteLine($"     Error Code: {decryptRevokedResult.Error.Code}");
        Console.WriteLine($"     Description: {decryptRevokedResult.Error.Description}");

        // Exercise explicit IKeyRing cache invalidation methods
        keyRing.InvalidateKey(activeKey.Metadata.KeyId, activeKey.Metadata.Version);
        keyRing.InvalidateActiveKey(KeyPurpose.SecretProtection);
        keyRing.InvalidateAll();
        Console.WriteLine("  -> IKeyRing Invalidation: InvalidateKey(), InvalidateActiveKey(), InvalidateAll() executed.");

        // -------------------------------------------------------------------------
        // 3. Constant-Time Comparer against Timing Side-Channels
        // -------------------------------------------------------------------------
        Console.WriteLine("\n[3] Constant-Time Comparison against Side-Channel Timing Attacks:");

        var secretSignatureExpected = new byte[32];
        var secretSignatureReceived = new byte[32];
        CryptographicRandom.Shared.Fill(secretSignatureExpected);
        Buffer.BlockCopy(secretSignatureExpected, 0, secretSignatureReceived, 0, 32);

        var isFixedTimeMatch = ConstantTimeComparer.Shared.FixedTimeEquals(secretSignatureExpected, secretSignatureReceived);
        Console.WriteLine($"  -> Constant-Time Byte Comparison (Expected == Received): {isFixedTimeMatch}");

        secretSignatureReceived[0] ^= 0x01;
        var isFixedTimeMismatch = ConstantTimeComparer.Shared.FixedTimeEquals(secretSignatureExpected, secretSignatureReceived);
        Console.WriteLine($"  -> Constant-Time Byte Comparison (Tampered mismatch): {isFixedTimeMismatch}");

        // -------------------------------------------------------------------------
        // 4. SecurityError Catalog — Structured Error Construction
        // -------------------------------------------------------------------------
        Console.WriteLine("\n[4] SecurityError Catalog — Strongly-Typed Error Factories:");

        var errInvalidCiphertext = SecurityError.InvalidCiphertext("Envelope header magic bytes mismatch (expected 0xECSEC01).");
        Console.WriteLine($"  -> {errInvalidCiphertext.Code}: {errInvalidCiphertext.Description}");

        var errTagMismatch = SecurityError.AuthenticationTagMismatch();
        Console.WriteLine($"  -> {errTagMismatch.Code}: {errTagMismatch.Description}");

        var errKeyNotFound = SecurityError.KeyNotFound("key_abc123");
        Console.WriteLine($"  -> {errKeyNotFound.Code}: {errKeyNotFound.Description}");

        var errKeyRevoked = SecurityError.KeyRevoked("key_abc123", "Compromised during Security Incident #SEC-2026-0042.");
        Console.WriteLine($"  -> {errKeyRevoked.Code}: {errKeyRevoked.Description}");

        var errKeyExpired = SecurityError.KeyExpired("key_abc123");
        Console.WriteLine($"  -> {errKeyExpired.Code}: {errKeyExpired.Description}");

        var errPurposeMismatch = SecurityError.KeyPurposeMismatch("Signing", "SecretProtection");
        Console.WriteLine($"  -> {errPurposeMismatch.Code}: {errPurposeMismatch.Description}");

        var errInvalidToken = SecurityError.InvalidToken("Token length mismatch — expected 43 Base64Url chars.");
        Console.WriteLine($"  -> {errInvalidToken.Code}: {errInvalidToken.Description}");

        var errTokenExpired = SecurityError.TokenExpired();
        Console.WriteLine($"  -> {errTokenExpired.Code}: {errTokenExpired.Description}");

        var errTokenRevoked = SecurityError.TokenRevoked();
        Console.WriteLine($"  -> {errTokenRevoked.Code}: {errTokenRevoked.Description}");

        var errPolicyViolation = SecurityError.SecurityPolicyViolation("PasswordPolicy", "Password must be at least 14 characters.");
        Console.WriteLine($"  -> {errPolicyViolation.Code}: {errPolicyViolation.Description}");

        var errSecretNotFound = SecurityError.SecretNotFound("Database:ConnectionString");
        Console.WriteLine($"  -> {errSecretNotFound.Code}: {errSecretNotFound.Description}");

        var errUnsupportedAlgo = SecurityError.UnsupportedAlgorithm("RC4", "RC4 is prohibited by security policy.");
        Console.WriteLine($"  -> {errUnsupportedAlgo.Code}: {errUnsupportedAlgo.Description}");

        // -------------------------------------------------------------------------
        // 5. Have I Been Pwned (HIBP) k-Anonymity — Privacy-Preserving Breach Check
        // -------------------------------------------------------------------------
        Console.WriteLine("\n[5] Have I Been Pwned — k-Anonymity Service Registration & API Contracts:");

        // Registering the HIBP service — AddHaveIBeenPwned() extension method
        var hibpServices = new ServiceCollection();
        hibpServices.AddHaveIBeenPwned(opts =>
        {
            opts.UserAgent = "EricksonLopez-Security-Showcase/1.0";
            opts.MaxAllowedBreachCount = 0; // Zero tolerance: any breach fails validation
        });

        Console.WriteLine("  -> AddHaveIBeenPwned() registered: IHaveIBeenPwnedClient (HttpClient), IPasswordPwnedValidator (scoped)");
        Console.WriteLine("  -> IHaveIBeenPwnedClient.CheckPasswordAsync(password) : Task<Result<PwnedPasswordCheckResult>>");
        Console.WriteLine("  -> IHaveIBeenPwnedClient.GetRangeAsync(hashPrefix)     : Task<Result<IReadOnlyList<PwnedPasswordEntry>>>");
        Console.WriteLine("  -> IPasswordPwnedValidator.ValidateNotPwnedAsync(pwd)  : Task<Result>");
        Console.WriteLine("  Note: Actual HTTP calls require a running HttpClient against api.pwnedpasswords.com.");
        Console.WriteLine("        In production, use AddHaveIBeenPwned() + inject IPasswordPwnedValidator into your registration pipeline.");

        // PwnedPasswordCheckResult — result shape for a CheckPasswordAsync() call
        var cleanResult = new PwnedPasswordCheckResult(hashPrefix: "5BAA6", breachCount: 0);
        Console.WriteLine($"  -> PwnedPasswordCheckResult (clean password): IsPwned={cleanResult.IsPwned}, BreachCount={cleanResult.BreachCount}, HashPrefix={cleanResult.HashPrefix}");

        var pwnedResult = new PwnedPasswordCheckResult(hashPrefix: "5BAA6", breachCount: 9874387);
        Console.WriteLine($"  -> PwnedPasswordCheckResult ('password' hash): IsPwned={pwnedResult.IsPwned}, BreachCount={pwnedResult.BreachCount:N0}");

        Console.WriteLine("--------------------------------------------------------------------------------");
    }
}
