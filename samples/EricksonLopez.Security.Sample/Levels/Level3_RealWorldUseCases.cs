// Copyright © Erickson Lopez. MIT License.

using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using EricksonLopez.Security.Abstractions.KeyManagement;
using EricksonLopez.Security.Abstractions.Primitives;
using EricksonLopez.Security.Abstractions.Secrets;
using EricksonLopez.Security.Abstractions.Tokens;
using EricksonLopez.Security.Memory;
using EricksonLopez.Security.Mfa;
using EricksonLopez.Security.Tokens;
using Microsoft.Extensions.DependencyInjection;

namespace EricksonLopez.Security.Sample.Levels;

/// <summary>
/// Level 3: Real-World Use Cases & Enterprise Scenarios.
/// Demonstrates end-to-end cryptographic key rotation with historical decryption,
/// scoped API key issuance with constant-time store validation, and RFC 6238 TOTP MFA.
/// </summary>
public static class Level3_RealWorldUseCases
{
    public static async Task RunAsync()
    {
        Console.WriteLine("\n================================================================================");
        Console.WriteLine("  LEVEL 3: REAL-WORLD PRODUCTION USE CASES & SCENARIOS");
        Console.WriteLine("================================================================================");

        var services = new ServiceCollection();
        services.AddEricksonLopezSecurity();
        services.AddSecurityMfa();
        using var provider = services.BuildServiceProvider();

        var keyLifecycle = provider.GetRequiredService<IKeyLifecycleManager>();
        var secretProtector = provider.GetRequiredService<ISecretProtector>();
        var apiKeyGenerator = provider.GetRequiredService<IApiKeyGenerator>();
        var totpService = provider.GetRequiredService<ITotpService>();

        // -------------------------------------------------------------------------
        // SCENARIO 1: Key Lifecycle Management & Historical Data Decryption
        // -------------------------------------------------------------------------
        Console.WriteLine("\n[1] SCENARIO 1: Cryptographic Key Rotation & Historical Record Decryption");

        // Step 1: Generate Key v1
        var v1Result = await keyLifecycle.GenerateAndActivateKeyAsync(KeyPurpose.SecretProtection);
        var keyV1 = v1Result.Value;
        Console.WriteLine($"  -> Step 1: Active Key v1 Generated: {keyV1.Metadata.KeyId} (v{keyV1.Metadata.Version})");

        // Step 2: Encrypt Customer Record using Active Key (v1)
        var customerPii = Encoding.UTF8.GetBytes("TaxId=999-88-7777; HealthRecordId=HR-2026-90812");
        var encryptedWithV1 = (await secretProtector.ProtectAsync(customerPii, KeyPurpose.SecretProtection)).Value;
        Console.WriteLine($"  -> Step 2: Customer PII Encrypted with Key v1 (Envelope Size: {encryptedWithV1.Length} bytes)");

        // Step 3: Rotate Cryptographic Key Ring -> Key v2 becomes Active, Key v1 becomes Retired
        var v2Result = await keyLifecycle.RotateKeyAsync(KeyPurpose.SecretProtection);
        var keyV2 = v2Result.Value;
        Console.WriteLine($"  -> Step 3: Key Ring Rotated! New Active Key: {keyV2.Metadata.KeyId} (v{keyV2.Metadata.Version})");

        // Step 4: Transparent Historical Decryption (System finds Retired Key v1 in Ring automatically)
        var historicalDecrypted = await secretProtector.UnprotectAsync(encryptedWithV1);
        Console.WriteLine($"  -> Step 4: Historical Payload Decrypted via Retired Key v1: '{Encoding.UTF8.GetString(historicalDecrypted.Value)}'");

        // Step 5: New Data Encrypted with Key v2
        var newCustomerPii = Encoding.UTF8.GetBytes("TaxId=111-22-3333; HealthRecordId=HR-2026-99999");
        var encryptedWithV2 = (await secretProtector.ProtectAsync(newCustomerPii, KeyPurpose.SecretProtection)).Value;
        Console.WriteLine($"  -> Step 5: New Customer PII Encrypted with Key v2 (Envelope Size: {encryptedWithV2.Length} bytes)");

        // -------------------------------------------------------------------------
        // SCENARIO 1b: Synchronous ISecretProtector & ProtectedSecret Container
        // -------------------------------------------------------------------------
        Console.WriteLine("\n[1b] SCENARIO 1b: Synchronous Protect/Unprotect & ProtectedSecret Memory Container");

        // Synchronous protect (no async overhead when Key Ring is pre-warmed)
        var syncSecret = Encoding.UTF8.GetBytes("SyncPayload: BankRoutingNumber=091000019");
        var syncProtectResult = secretProtector.Protect(syncSecret, KeyPurpose.SecretProtection);
        var syncProtectedBytes = syncProtectResult.Value;
        Console.WriteLine($"  -> Synchronous Protect: {syncSecret.Length}b plaintext => {syncProtectedBytes.Length}b envelope");

        var syncUnprotectResult = secretProtector.Unprotect(syncProtectedBytes);
        Console.WriteLine($"  -> Synchronous Unprotect: '{Encoding.UTF8.GetString(syncUnprotectResult.Value)}'");

        // ProtectedSecret — holds an encrypted envelope in-memory with key metadata for deferred decryption
        var keyV2Active = v2Result.Value;
        var piiPayload = Encoding.UTF8.GetBytes("SSN=123-45-6789; CreditScore=780");
        var piiEnvelope = (await secretProtector.ProtectAsync(piiPayload, KeyPurpose.SecretProtection)).Value;
        var protectedSecret = new ProtectedSecret(keyV2Active.Metadata.KeyId, keyV2Active.Metadata.Version, piiEnvelope);
        Console.WriteLine($"  -> ProtectedSecret.ToString() (redacted): {protectedSecret}");
        Console.WriteLine($"  -> ProtectedSecret.KeyId: {protectedSecret.KeyId} | Version: {protectedSecret.KeyVersion}");
        var unprotectedViaHolder = await protectedSecret.UnprotectAsync(secretProtector);
        Console.WriteLine($"  -> Deferred UnprotectAsync via ProtectedSecret: '{Encoding.UTF8.GetString(unprotectedViaHolder.Value)}'");

        // -------------------------------------------------------------------------
        // SCENARIO 2: Scoped API Key Issuance, Hashing & Verification
        // -------------------------------------------------------------------------
        Console.WriteLine("\n[2] SCENARIO 2: High-Entropy Scoped API Keys Issuance & In-Memory Store Validation");

        var apiKeyStore = new InMemoryApiKeyStore();
        var apiKeyValidator = new ApiKeyValidator(apiKeyStore);

        // Issue new key
        var issuance = apiKeyGenerator.GenerateApiKey(
            ownerId: "tenant_fintech_enterprise_42",
            name: "Core Banking Integration Connector",
            prefix: "ek_live",
            lifetime: TimeSpan.FromDays(90),
            scopes: new HashSet<string> { "payments:process", "accounts:read", "transfers:execute" });

        // Save key entity in store (Only hashed secret is stored!)
        await apiKeyStore.SaveAsync(issuance.Key);

        Console.WriteLine($"  -> API Key ID: {issuance.Key.Id.Value}");
        Console.WriteLine($"  -> Display Masked Prefix: {issuance.Key.DisplayPrefix}");
        Console.WriteLine($"  -> Stored Hashed Secret (SHA-256): {issuance.Key.HashedSecret[..16]}... (Redacted)");
        Console.WriteLine($"  -> Single-Use Plaintext Key Returned: {issuance.PlaintextApiKey}");

        // Validate Presented Plaintext Key
        var authResult = await apiKeyValidator.ValidateApiKeyAsync(issuance.PlaintextApiKey);
        Console.WriteLine($"  -> Validating Plaintext Key: {(authResult.IsSuccess ? "AUTHORIZED" : "UNAUTHORIZED")}");
        if (authResult.IsSuccess)
        {
            Console.WriteLine($"     Owner: {authResult.Value.OwnerId}, Scopes: [{string.Join(", ", authResult.Value.Scopes ?? new HashSet<string>())}]");
        }

        // Validate Tampered Key
        var tamperedKey = issuance.PlaintextApiKey + "_invalid";
        var tamperedAuthResult = await apiKeyValidator.ValidateApiKeyAsync(tamperedKey);
        Console.WriteLine($"  -> Validating Tampered Key: {(tamperedAuthResult.IsSuccess ? "AUTHORIZED" : "REJECTED")} (Reason: {tamperedAuthResult.Error.Description})");

        // -------------------------------------------------------------------------
        // SCENARIO 3: Multi-Factor Authentication (RFC 6238 TOTP & Recovery Codes)
        // -------------------------------------------------------------------------
        Console.WriteLine("\n[3] SCENARIO 3: Multi-Factor Authentication (RFC 6238 TOTP & Emergency Recovery Codes)");

        // 3a. GenerateSecretKey() — standalone key generation (no setup info needed)
        var standaloneKey = totpService.GenerateSecretKey(byteLength: 32); // 256-bit key
        Console.WriteLine($"  -> GenerateSecretKey(32 bytes): {standaloneKey} (Base32, {standaloneKey.Length} chars)");

        // 3b. GenerateSetupInfo() — standard 20-byte / 160-bit TOTP enrollment
        var setupInfo = totpService.GenerateSetupInfo(
            issuer: "EricksonLopez Platform",
            accountName: "security.officer@enterprise.com");

        Console.WriteLine($"  -> Base32 Secret Key: {setupInfo.SecretKey}");
        Console.WriteLine($"  -> FormattedSecretKey (chunked): {setupInfo.FormattedSecretKey}");
        Console.WriteLine($"  -> Authenticator URI: {setupInfo.AuthenticatorUri}");

        // 3c. GenerateSetupInfo() with existing key (for re-enrollment without key regeneration)
        var reEnrollInfo = totpService.GenerateSetupInfo(
            issuer: "EricksonLopez Platform",
            accountName: "security.officer@enterprise.com",
            secretKey: setupInfo.SecretKey); // Pass existing key
        Console.WriteLine($"  -> Re-Enrollment (same key): keys match = {reEnrollInfo.SecretKey == setupInfo.SecretKey}");

        // 3d. TotpOptions — all configurable parameters
        var customTotpOptions = new TotpOptions
        {
            Digits = 8,                               // 8-digit code instead of default 6
            PeriodSeconds = 60,                       // 60-second window instead of default 30
            Algorithm = TotpHashAlgorithm.Sha256,     // HMAC-SHA256 instead of default Sha1
            AllowedDriftSteps = 2                     // ±2 time-steps tolerance
        };
        Console.WriteLine($"  -> TotpOptions: Digits={customTotpOptions.Digits}, Period={customTotpOptions.PeriodSeconds}s, Algorithm={customTotpOptions.Algorithm}, DriftSteps={customTotpOptions.AllowedDriftSteps}");

        // 3e. TotpHashAlgorithm — all enum values
        Console.WriteLine($"  -> TotpHashAlgorithm.Sha1={TotpHashAlgorithm.Sha1}, Sha256={TotpHashAlgorithm.Sha256}, Sha512={TotpHashAlgorithm.Sha512}");

        // 3f. GenerateSetupInfo() with custom options (SHA-256, 8 digits)
        var customSetupInfo = totpService.GenerateSetupInfo(
            issuer: "EricksonLopez Platform",
            accountName: "security.officer@enterprise.com",
            options: customTotpOptions);
        Console.WriteLine($"  -> Custom 8-digit URI: {customSetupInfo.AuthenticatorUri}");

        // Compute active 6-digit code for current time (default options)
        var currentCode = totpService.ComputeCode(setupInfo.SecretKey, DateTimeOffset.UtcNow);
        Console.WriteLine($"  -> Generated TOTP Code (default 6-digit): {currentCode}");

        // Compute 8-digit code with custom options
        var customCode = totpService.ComputeCode(customSetupInfo.SecretKey, DateTimeOffset.UtcNow, customTotpOptions);
        Console.WriteLine($"  -> Generated TOTP Code (custom 8-digit SHA-256): {customCode}");

        var isTotpValid = totpService.VerifyCode(setupInfo.SecretKey, currentCode);
        Console.WriteLine($"  -> Verified TOTP Code: {(isTotpValid ? "VALID (Access Granted)" : "INVALID")}");

        // VerifyCode with explicit timestamp and custom options
        var isCustomValid = totpService.VerifyCode(customSetupInfo.SecretKey, customCode, DateTimeOffset.UtcNow, customTotpOptions);
        Console.WriteLine($"  -> Verified Custom 8-digit Code: {(isCustomValid ? "VALID" : "INVALID")}");

        // Emergency Recovery Backup Codes (AUTH-010: Hashed Storage & Constant-Time Verification)
        IRecoveryCodeGenerator recoveryGenerator = new RecoveryCodeGenerator();
        var backupCodes = recoveryGenerator.GenerateCodes(count: 3, codeLength: 10);
        Console.WriteLine("  -> Emergency Single-Use Recovery Codes (IRecoveryCodeGenerator):");

        var firstCode = backupCodes[0];
        var storedHash = RecoveryCodeGenerator.HashCode(firstCode);
        Console.WriteLine($"     • Plaintext Code: {firstCode}");
        Console.WriteLine($"     • Stored Hash (SHA-256): {storedHash[..16]}... (Store hash in DB, never plaintext)");

        // Constant-time verification against timing oracle attacks
        var isCodeValid = RecoveryCodeGenerator.VerifyCode(firstCode, storedHash);
        var isTamperedValid = RecoveryCodeGenerator.VerifyCode("WRON-CODE-99", storedHash);
        Console.WriteLine($"     • VerifyCode (correct): {isCodeValid}");
        Console.WriteLine($"     • VerifyCode (tampered): {isTamperedValid}");

        // 3g. Multi-Node Distributed TOTP Replay Prevention (DelegateTotpReplayStore)
        Console.WriteLine("\n  -> Distributed TOTP Replay Protection across Multi-Node Clusters (DelegateTotpReplayStore):");
        var clusterSharedReplayMap = new System.Collections.Concurrent.ConcurrentDictionary<string, DateTimeOffset>();
        var distributedStore = new DelegateTotpReplayStore(
            (key, exp, ct) => ValueTask.FromResult(clusterSharedReplayMap.TryAdd(key, exp)),
            (key, exp) => clusterSharedReplayMap.TryAdd(key, exp));

        var clusterTotpServiceNodeA = new TotpService(TimeProvider.System, distributedStore);
        var clusterTotpServiceNodeB = new TotpService(TimeProvider.System, distributedStore);
        var replayProtectedOptions = new TotpOptions { PreventReplay = true };

        var tokenToReplay = clusterTotpServiceNodeA.ComputeCode(setupInfo.SecretKey, DateTimeOffset.UtcNow, replayProtectedOptions);

        // First presentation on Node A succeeds
        var nodeAVerified = await clusterTotpServiceNodeA.VerifyCodeAsync(setupInfo.SecretKey, tokenToReplay, DateTimeOffset.UtcNow, replayProtectedOptions);
        Console.WriteLine($"     • Node A Verification (1st presentation): {(nodeAVerified ? "ACCEPTED (Valid Token)" : "REJECTED")}");

        // Attacker attempts to replay the identical token within the valid window on Node B:
        var nodeBReplay = await clusterTotpServiceNodeB.VerifyCodeAsync(setupInfo.SecretKey, tokenToReplay, DateTimeOffset.UtcNow, replayProtectedOptions);
        Console.WriteLine($"     • Node B Verification (Replay Attack blocked): {(nodeBReplay ? "ACCEPTED (VULNERABILITY!)" : "REJECTED (Replay Mitigated)")}");

        Console.WriteLine("--------------------------------------------------------------------------------");
    }
}
