// Copyright © Erickson Lopez. MIT License.

using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using EricksonLopez.Result;
using Result = global::EricksonLopez.Result.Result;
using EricksonLopez.Security.Abstractions.KeyManagement;
using EricksonLopez.Security.Abstractions.Passwords;
using EricksonLopez.Security.Abstractions.Primitives;
using EricksonLopez.Security.Abstractions.Secrets;
using EricksonLopez.Security.Abstractions.Tokens;
using EricksonLopez.Security.AspNetCore.Identity;
using EricksonLopez.Security.KeyManagement;
using EricksonLopez.Security.Passwords;
using EricksonLopez.Security.Secrets;
using EricksonLopez.Security.Testing.Fakes;
using EricksonLopez.Security.Testing.Http;
using EricksonLopez.Security.Testing.Logging;
using EricksonLopez.Security.Tokens;
using EricksonLopez.Security.ZeroTrust;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace EricksonLopez.Security.Sample.Levels;

/// <summary>
/// Level 8: Customization, Extensibility & Component Replacement.
/// Demonstrates how to create custom implementations of core contracts (such as a custom
/// audited IKeyStore decorator) and build custom ABAC domain rules.
/// </summary>
public static class Level8_CustomizationAndExtensibility
{
    public static async Task RunAsync()
    {
        Console.WriteLine("\n================================================================================");
        Console.WriteLine("  LEVEL 8: CUSTOMIZATION, EXTENSIBILITY & COMPONENT REPLACEMENT");
        Console.WriteLine("================================================================================");

        // -------------------------------------------------------------------------
        // 1. Custom Auditing Key Store Decorator
        // -------------------------------------------------------------------------
        Console.WriteLine("\n[1] Registering Custom Audited IKeyStore Decorator:");

        var services = new ServiceCollection();
        services.AddEricksonLopezSecurity();

        // Replace default IKeyStore with custom audited implementation
        services.AddSingleton<IKeyStore>(sp => new CustomAuditedKeyStore(new InMemoryKeyStore()));

        using var provider = services.BuildServiceProvider();
        var keyLifecycle = provider.GetRequiredService<IKeyLifecycleManager>();

        Console.WriteLine("  -> Generating Key through Custom Audited Key Store:");
        var keyGenResult = await keyLifecycle.GenerateAndActivateKeyAsync(KeyPurpose.SecretProtection);
        Console.WriteLine($"  -> Key Generated Successfully: {keyGenResult.Value.Metadata.KeyId}");

        // -------------------------------------------------------------------------
        // 2. Custom Domain ABAC Rule & Policy Definition
        // -------------------------------------------------------------------------
        Console.WriteLine("\n[2] Designing Custom ABAC Dynamic Access Rules:");

        // Custom Rule: Allow financial wire transfers only if user has CFO role, MFA is verified, and amount < $1,000,000
        var wireTransferRule = AbacRule.PermitIf(
            ruleId: "RULE_FINANCIAL_WIRE_TRANSFER",
            condition: ctx =>
            {
                var role = ctx.Get<string>(AbacAttributeCategory.Subject, "Role");
                var mfa = ctx.Get<bool>(AbacAttributeCategory.Subject, "MfaVerified");
                var amount = ctx.Get<decimal>(AbacAttributeCategory.Resource, "TransferAmount");

                return role == "CFO" && mfa && amount < 1000000m;
            },
            description: "Permits wire transfers under $1M for MFA-verified CFO users.");

        var customPolicy = new AbacPolicy(
            policyId: "POLICY_FINANCIAL_OPERATIONS",
            rules: new[] { wireTransferRule },
            combiningAlgorithm: AbacCombiningAlgorithm.DenyOverrides,
            description: "Enterprise Financial Operations Policy");

        var policyEngine = new AbacPolicyEngine();

        // Test Context: Valid CFO transfer
        var validContext = new AbacContext()
            .WithSubject("Role", "CFO")
            .WithSubject("MfaVerified", true)
            .WithResource("TransferAmount", 250000m)
            .WithAction("TransferFunds");

        var validDecision = policyEngine.Evaluate(validContext, new[] { customPolicy });
        Console.WriteLine($"  -> Valid CFO Transfer ($250k): {validDecision.Status} (Permitted: {validDecision.IsPermitted})");

        // Test Context: Non-MFA transfer
        var invalidContext = new AbacContext()
            .WithSubject("Role", "CFO")
            .WithSubject("MfaVerified", false)
            .WithResource("TransferAmount", 250000m)
            .WithAction("TransferFunds");

        var invalidDecision = policyEngine.Evaluate(invalidContext, new[] { customPolicy });
        Console.WriteLine($"  -> Non-MFA CFO Transfer: {invalidDecision.Status} (Permitted: {invalidDecision.IsPermitted}, Reason: {invalidDecision.Reason})");

        // AbacDecisionStatus enum — all values
        Console.WriteLine($"  -> AbacDecisionStatus enum: Permit={AbacDecisionStatus.Permit}, Deny={AbacDecisionStatus.Deny}, NotApplicable={AbacDecisionStatus.NotApplicable}, Indeterminate={AbacDecisionStatus.Indeterminate}");

        // AbacEffect enum — all values
        Console.WriteLine($"  -> AbacEffect enum: Permit={AbacEffect.Permit}, Deny={AbacEffect.Deny}");

        // IAbacPolicyEngine — programming against the interface (not the concrete class)
        IAbacPolicyEngine engineAsInterface = new AbacPolicyEngine();
        var interfaceDecision = engineAsInterface.Evaluate(validContext, new[] { customPolicy });
        Console.WriteLine($"  -> IAbacPolicyEngine.Evaluate() via interface: {interfaceDecision.Status} (Permitted: {interfaceDecision.IsPermitted})");

        // Demonstrate remaining customization APIs (password hashers, secret stores, API key store)
        await DemonstratePasswordHasherCustomization();

        // -------------------------------------------------------------------------
        // 8. ASP.NET Core Identity Bridge — IdentityPasswordHasherBridge<TUser>
        // -------------------------------------------------------------------------
        Console.WriteLine("\n[8] ASP.NET Core Identity Bridge — IdentityPasswordHasherBridge<TUser>:");

        // Direct instantiation (for testing or manual scenarios)
        var compositeHasherForBridge = new CompositePasswordHasher();
        var identityBridge = new IdentityPasswordHasherBridge<object>(compositeHasherForBridge);

        var bridgeTestPwd = "IdentityBridgeTest$Pwd!2026";
        var bridgeHash = identityBridge.HashPassword(new object(), bridgeTestPwd);
        Console.WriteLine($"  -> IdentityPasswordHasherBridge<TUser>.HashPassword(): {bridgeHash[..20]}...");

        var bridgeVerifyResult = identityBridge.VerifyHashedPassword(new object(), bridgeHash, bridgeTestPwd);
        Console.WriteLine($"  -> VerifyHashedPassword() (correct): {bridgeVerifyResult}");

        var bridgeWrongResult = identityBridge.VerifyHashedPassword(new object(), bridgeHash, "wrong_password");
        Console.WriteLine($"  -> VerifyHashedPassword() (wrong): {bridgeWrongResult}");

        Console.WriteLine("  DI registration in ASP.NET Core app:");
        Console.WriteLine("    services.AddEricksonLopezIdentityPasswordHasher<ApplicationUser>()");
        Console.WriteLine("    Replaces ASP.NET Core Identity's default IPasswordHasher<TUser> with EricksonLopez bridge.");

        // Pbkdf2PasswordHasher.Default — explicit static default instance access
        Console.WriteLine("\n[8b] Pbkdf2PasswordHasher.Default — Explicit Static Instance:");
        var pbkdf2Default = Pbkdf2PasswordHasher.Default;
        Console.WriteLine($"  -> Pbkdf2PasswordHasher.Default.Algorithm: {pbkdf2Default.Algorithm}");
        var pbkdf2Hash = pbkdf2Default.HashPassword(bridgeTestPwd.AsSpan());
        Console.WriteLine($"  -> HashPassword() format prefix: {pbkdf2Hash.Split('$')[0]}${pbkdf2Hash.Split('$')[1]}");
        Console.WriteLine($"  -> NeedsRehash() (current default params): {pbkdf2Default.NeedsRehash(pbkdf2Hash)}");

        // Testing Utilities showcase
        await DemonstrateTestingUtilitiesAsync();

        Console.WriteLine("--------------------------------------------------------------------------------");
    }

    private static async Task DemonstratePasswordHasherCustomization()
    {
        // -------------------------------------------------------------------------
        // 3. CompositePasswordHasher — Multi-Algorithm Dispatch & Auto-Rehash
        // -------------------------------------------------------------------------
        Console.WriteLine("\n[3] CompositePasswordHasher — Transparent Multi-Algorithm Hash Upgrade:");
        // Default: Pbkdf2 as primary, with support for additional legacy hashers
        var compositeHasher = new CompositePasswordHasher(
            primaryHasher: Pbkdf2PasswordHasher.Default,
            additionalHashers: [Argon2idPasswordHasher.Default, LegacyPbkdf2PasswordHasher.Default]);
        Console.WriteLine($"  -> CompositePasswordHasher.Algorithm (primary): {compositeHasher.Algorithm}");

        var testPassword = "UserPassword!Ultra$Secure#2026";
        var hash = compositeHasher.HashPassword(testPassword.AsSpan());
        Console.WriteLine($"  -> CompositePasswordHasher.HashPassword() primary format: {hash.Split('$')[0]}${hash.Split('$')[1]}");

        // Verify against primary algorithm
        var verifyResult = compositeHasher.VerifyPassword(testPassword.AsSpan(), hash);
        Console.WriteLine($"  -> CompositePasswordHasher.VerifyPassword(): {verifyResult}");

        // When legacy hash is presented, SuccessRehashNeeded is returned to trigger upgrade
        var legacyArgonHash = Argon2idPasswordHasher.Default.HashPassword(testPassword.AsSpan());
        var rehashResult = compositeHasher.VerifyPassword(testPassword.AsSpan(), legacyArgonHash);
        Console.WriteLine($"  -> Verify legacy hash with primary Pbkdf2: {rehashResult} (Signals rehash on next login)");

        // -------------------------------------------------------------------------
        // 4. Argon2idPasswordHasher & LegacyPbkdf2PasswordHasher — Format Demonstrations
        // -------------------------------------------------------------------------
        Console.WriteLine("\n[4] Specialized Password Hashers (Argon2id & LegacyPbkdf2):");

        // Argon2idPasswordHasher ($argon2id$ format)
        var customArgon2 = new Argon2idPasswordHasher(
            memorySizeKb: 65536,
            iterations: 3,
            parallelism: 4);
        var argon2McfHash = customArgon2.HashPassword(testPassword.AsSpan());
        Console.WriteLine($"  -> Argon2idPasswordHasher.Algorithm: {customArgon2.Algorithm}");
        Console.WriteLine($"  -> Hash starts with $argon2id$: {argon2McfHash.StartsWith("$argon2id$", StringComparison.Ordinal)}");
        Console.WriteLine($"  -> NeedsRehash (matching params): {customArgon2.NeedsRehash(argon2McfHash)}");

        // LegacyPbkdf2PasswordHasher ($legacy-pbkdf2$ format)
        var customLegacy = new LegacyPbkdf2PasswordHasher(
            memorySizeKb: 32768,
            iterations: 2,
            parallelism: 4);
        var legacyHash = customLegacy.HashPassword(testPassword.AsSpan());
        Console.WriteLine($"  -> LegacyPbkdf2PasswordHasher.Algorithm: {customLegacy.Algorithm}");
        Console.WriteLine($"  -> Hash starts with $legacy-pbkdf2$: {legacyHash.StartsWith("$legacy-pbkdf2$", StringComparison.Ordinal)}");
        Console.WriteLine($"  -> NeedsRehash (matching params): {customLegacy.NeedsRehash(legacyHash)}");
        Console.WriteLine($"  -> NeedsRehash (older default hash): {customLegacy.NeedsRehash(LegacyPbkdf2PasswordHasher.Default.HashPassword(testPassword.AsSpan()))}");

        // -------------------------------------------------------------------------
        // 5. EnvironmentSecretStore — In-Process Secret Resolution
        // -------------------------------------------------------------------------
        Console.WriteLine("\n[5] EnvironmentSecretStore — Environment Variable Secret Backend:");

        var envStore = new EnvironmentSecretStore(prefix: "APP_");
        Environment.SetEnvironmentVariable("APP_DATABASE_CONNECTION_STRING", "Host=localhost;Database=mydb");

        var resolvedSecret = await envStore.GetSecretAsync("Database:Connection:String");
        Console.WriteLine($"  -> GetSecretAsync (env: 'APP_DATABASE_CONNECTION_STRING'): {resolvedSecret.IsSuccess}");
        Console.WriteLine($"  -> Resolved Redacted<string>.ToString(): {resolvedSecret.Value}"); // [REDACTED]
        Console.WriteLine($"  -> Resolved Redacted<string>.HasValue: {resolvedSecret.Value.HasValue}");

        var missingSecret = await envStore.GetSecretAsync("NonExistent:Key");
        Console.WriteLine($"  -> GetSecretAsync (missing key): IsSuccess={missingSecret.IsSuccess}, Error={missingSecret.Error.Code}");

        var writeResult = await envStore.SetSecretAsync("Feature:Flag:Beta", "true");
        Console.WriteLine($"  -> SetSecretAsync: {writeResult.IsSuccess}");

        // -------------------------------------------------------------------------
        // 6. CompositeSecretResolver — Multi-Scheme URI Secret Resolution
        // -------------------------------------------------------------------------
        Console.WriteLine("\n[6] CompositeSecretResolver — Multi-Scheme Secret URI Resolution:");
        Console.WriteLine("  Supported schemes: raw:VALUE | env:VAR_NAME | store:SECRET_NAME");

        var resolver = new CompositeSecretResolver(envStore);

        // raw: scheme — inline plaintext value (for dev/testing only)
        var rawResult = await resolver.ResolveAsync("raw:InlineConfigValue123");
        Console.WriteLine($"  -> Resolve 'raw:InlineConfigValue123': {rawResult.IsSuccess} — Redacted: {rawResult.Value}");
        Console.WriteLine($"  -> Raw UnsafeValue: {rawResult.Value.UnsafeValue}");

        // env: scheme — read from environment variable
        var envResult = await resolver.ResolveAsync("env:Database:Connection:String");
        Console.WriteLine($"  -> Resolve 'env:Database:Connection:String': {envResult.IsSuccess}");

        // store: scheme — read from registered store
        var storeResult = await resolver.ResolveAsync("store:NonExistent");
        Console.WriteLine($"  -> Resolve 'store:NonExistent': IsSuccess={storeResult.IsSuccess} (expected false)");

        // -------------------------------------------------------------------------
        // 7. InMemoryApiKeyStore & ApiKey — API Key Lifecycle
        // -------------------------------------------------------------------------
        Console.WriteLine("\n[7] InMemoryApiKeyStore & ApiKey — API Key Entity Lifecycle:");

        var apiKeyStore = new InMemoryApiKeyStore();
        var keyId = ApiKeyId.New();
        var apiKey = new ApiKey(
            Id: keyId,
            OwnerId: "user_enterprise_001",
            Name: "Integration API Key — Production",
            DisplayPrefix: "ek_live_9f8a...",
            HashedSecret: "sha256:fakehashvalue",
            CreatedAtUtc: DateTimeOffset.UtcNow,
            ExpiresAtUtc: DateTimeOffset.UtcNow.AddDays(90),
            Scopes: new HashSet<string> { "read:data", "write:data", "admin:keys" });

        Console.WriteLine($"  -> ApiKey.Id: {apiKey.Id}");
        Console.WriteLine($"  -> ApiKey.IsActive(): {apiKey.IsActive()}");
        Console.WriteLine($"  -> ApiKey.IsRevoked: {apiKey.IsRevoked}");
        Console.WriteLine($"  -> ApiKey.HasScope('admin:keys'): {apiKey.HasScope("admin:keys")}");
        Console.WriteLine($"  -> ApiKey.HasScope('delete:all'): {apiKey.HasScope("delete:all")}");

        var saveResult = await apiKeyStore.SaveAsync(apiKey);
        Console.WriteLine($"  -> InMemoryApiKeyStore.SaveAsync(): {saveResult.IsSuccess}");

        var retrieved = await apiKeyStore.GetByIdAsync(keyId);
        Console.WriteLine($"  -> InMemoryApiKeyStore.GetByIdAsync(): {retrieved.IsSuccess}, OwnerId={retrieved.Value.OwnerId}");

        var revokeResult = await apiKeyStore.RevokeAsync(keyId);
        Console.WriteLine($"  -> InMemoryApiKeyStore.RevokeAsync(): {revokeResult.IsSuccess}");

        var afterRevoke = await apiKeyStore.GetByIdAsync(keyId);
        Console.WriteLine($"  -> ApiKey.IsRevoked (after revoke): {afterRevoke.Value.IsRevoked}");
        Console.WriteLine($"  -> ApiKey.IsActive() (after revoke): {afterRevoke.Value.IsActive()}");
    }

    private static async Task RunExtensionsAsync()
    {
        await DemonstratePasswordHasherCustomization();
    }

    private static async Task DemonstrateTestingUtilitiesAsync()
    {
        // =========================================================================
        // [T1] FakePasswordHasher — Deterministic, Zero-Cost Test Double for IPasswordHasher
        // =========================================================================
        Console.WriteLine("\n[T1] EricksonLopez.Security.Testing — Test Doubles & Assertions:");
        Console.WriteLine("\n[T1a] FakePasswordHasher — Deterministic Zero-Cost IPasswordHasher Test Double:");

        var fakeHasher = new FakePasswordHasher();  // no KDF cost in tests
        var fakeHash = fakeHasher.HashPassword("TestPassword123!".AsSpan());
        Console.WriteLine($"  -> FakePasswordHasher.Algorithm: {fakeHasher.Algorithm}");
        Console.WriteLine($"  -> HashPassword(): {fakeHash[..20]}...");

        var fakeVerifyOk = fakeHasher.VerifyPassword("TestPassword123!".AsSpan(), fakeHash);
        var fakeVerifyFail = fakeHasher.VerifyPassword("WrongPassword".AsSpan(), fakeHash);
        Console.WriteLine($"  -> VerifyPassword (correct): {fakeVerifyOk}");
        Console.WriteLine($"  -> VerifyPassword (wrong):   {fakeVerifyFail}");

        // SimulateNeedsRehash — flag to test upgrade path in production code
        fakeHasher.SimulateNeedsRehash = true;
        Console.WriteLine($"  -> NeedsRehash (SimulateNeedsRehash=true): {fakeHasher.NeedsRehash(fakeHash)}");
        fakeHasher.SimulateNeedsRehash = false;
        Console.WriteLine($"  -> NeedsRehash (SimulateNeedsRehash=false): {fakeHasher.NeedsRehash(fakeHash)}");

        // =========================================================================
        // [T2] FakeSecretProtector — XOR-Masking In-Memory ISecretProtector
        // =========================================================================
        Console.WriteLine("\n[T2] FakeSecretProtector — XOR-Masking In-Memory ISecretProtector Test Double:");

        var fakeProtector = new FakeSecretProtector();
        var plaintext = System.Text.Encoding.UTF8.GetBytes("SensitiveTestData");

        // Protect and unprotect round-trip
        var fakeProtected = await fakeProtector.ProtectAsync(plaintext);
        Console.WriteLine($"  -> FakeSecretProtector.ProtectAsync(): {fakeProtected.Value.Length} bytes (XOR-masked)");

        var fakeUnprotected = await fakeProtector.UnprotectAsync(fakeProtected.Value);
        Console.WriteLine($"  -> FakeSecretProtector.UnprotectAsync(): {(fakeUnprotected.IsSuccess ? "SUCCESS" : "FAILED")}");
        Console.WriteLine($"  -> Round-trip data integrity: {System.Text.Encoding.UTF8.GetString(fakeUnprotected.Value) == "SensitiveTestData"}");

        // InjectedError — simulated failure to test error-handling paths
        fakeProtector.InjectedError = EricksonLopez.Security.Abstractions.Errors.SecurityError.InvalidCiphertext("Simulated test failure");
        var injectedFailure = await fakeProtector.ProtectAsync(plaintext);
        Console.WriteLine($"  -> FakeSecretProtector (InjectedError): IsSuccess={injectedFailure.IsSuccess}, Code={injectedFailure.Error.Code}");
        fakeProtector.InjectedError = null;  // clear injection

        // =========================================================================
        // [T3] FakeKeyStore — In-Memory IKeyStore with Failure Injection
        // =========================================================================
        Console.WriteLine("\n[T3] FakeKeyStore — In-Memory IKeyStore Test Double with Error Injection:");

        var fakeKeyStore = new FakeKeyStore();
        var testKeyBytes = new byte[32];
        System.Security.Cryptography.RandomNumberGenerator.Fill(testKeyBytes);
        using var testKey = EricksonLopez.Security.Memory.SecretBuffer.FromSpan(testKeyBytes);
        var testKeyMeta = new KeyMetadata(
            KeyId: KeyIdentifier.New(),
            Version: KeyVersion.Initial,
            Purpose: KeyPurpose.SecretProtection,
            Status: KeyStatus.Active,
            AlgorithmId: "AES-256-GCM",
            CreatedAtUtc: DateTimeOffset.UtcNow);
        var testCryptoKey = new CryptographicKey(testKeyMeta, testKey);

        var saveResult = await fakeKeyStore.SaveKeyAsync(testCryptoKey);
        Console.WriteLine($"  -> FakeKeyStore.SaveKeyAsync(): {saveResult.IsSuccess}");

        var getResult = await fakeKeyStore.GetKeyAsync(testKeyMeta.KeyId, testKeyMeta.Version);
        Console.WriteLine($"  -> FakeKeyStore.GetKeyAsync(): {getResult.IsSuccess}, Purpose={getResult.Value.Metadata.Purpose}");

        var listResult = await fakeKeyStore.ListMetadataAsync();
        Console.WriteLine($"  -> FakeKeyStore.ListMetadataAsync(): {listResult.Value.Count} key(s) stored");

        var updateResult = await fakeKeyStore.UpdateStatusAsync(testKeyMeta.KeyId, testKeyMeta.Version, KeyStatus.Retired);
        Console.WriteLine($"  -> FakeKeyStore.UpdateStatusAsync(Retired): {updateResult.IsSuccess}");

        // InjectedError — simulated storage failure
        fakeKeyStore.InjectedError = EricksonLopez.Security.Abstractions.Errors.SecurityError.KeyNotFound("test-key", "Store failure");
        var injectedGetFail = await fakeKeyStore.GetKeyAsync(testKeyMeta.KeyId, testKeyMeta.Version);
        Console.WriteLine($"  -> FakeKeyStore (InjectedError): IsSuccess={injectedGetFail.IsSuccess}, Code={injectedGetFail.Error.Code}");
        fakeKeyStore.InjectedError = null;  // clear injection

        // =========================================================================
        // [T4] DeterministicRandomNumberGenerator — Seeded CSPRNG for Reproducible Tests
        // =========================================================================
        Console.WriteLine("\n[T4] DeterministicRandomNumberGenerator — Seeded Deterministic RNG:");

        var deterministicRng = new DeterministicRandomNumberGenerator(seed: 42);
        var rngBuffer1 = new byte[16];
        deterministicRng.Fill(rngBuffer1);
        var rngBuffer2 = new byte[16];
        var deterministicRng2 = new DeterministicRandomNumberGenerator(seed: 42); // same seed
        deterministicRng2.Fill(rngBuffer2);

        Console.WriteLine($"  -> DeterministicRNG.Fill(16 bytes): {Convert.ToHexString(rngBuffer1)}");
        Console.WriteLine($"  -> Same-seed reproducibility: {rngBuffer1.AsSpan().SequenceEqual(rngBuffer2)}");
        Console.WriteLine($"  -> GetInt32(0, 100): {deterministicRng.GetInt32(0, 100)}");

        // =========================================================================
        // [T5] TestHttpMessageHandler — Configurable HTTP Test Double
        // =========================================================================
        Console.WriteLine("\n[T5] TestHttpMessageHandler — Configurable HTTP Mock for SSRF & HIBP Testing:");

        // Scenario: simulate a HIBP k-anonymity response returning breach count = 5
        var mockHibpHandler = new TestHttpMessageHandler(
            responseContent: "1234567890:5\r\nABCDEF0123:12\r\n",  // k-anonymity suffix response
            statusCode: HttpStatusCode.OK,
            mediaType: "text/plain");
        using var mockHttpClient = new HttpClient(mockHibpHandler);
        var hibpResponse = await mockHttpClient.GetAsync("https://api.pwnedpasswords.com/range/ABC12");
        Console.WriteLine($"  -> TestHttpMessageHandler response: StatusCode={hibpResponse.StatusCode}");
        Console.WriteLine($"  -> LastRequest URL: {mockHibpHandler.LastRequest?.RequestUri}");
        Console.WriteLine($"  -> RequestCount: {mockHibpHandler.RequestCount}");
        var hibpBody = await hibpResponse.Content.ReadAsStringAsync();
        Console.WriteLine($"  -> Response body lines: {hibpBody.Split("\r\n", StringSplitOptions.RemoveEmptyEntries).Length}");

        // Scenario: simulate network error (exception-throwing constructor)
        // (demonstrated conceptually — use: new TestHttpMessageHandler(new HttpRequestException("Network unavailable")))

        // =========================================================================
        // [T6] FakeLogger<T> & FakeLogRecord — Structured Log Capture Test Double
        // =========================================================================
        Console.WriteLine("\n[T6] FakeLogger<T> & FakeLogRecord — Structured Log Assertions:");

        var fakeLogger = new FakeLogger<FakeKeyStore>(minLevel: LogLevel.Debug);
        fakeLogger.LogInformation("Test: Key rotation completed for KeyId={KeyId}", "key_abc123");
        fakeLogger.LogWarning("Test: Key approaching expiration in {Days} days", 7);
        fakeLogger.LogError("Test: Decryption failed — authentication tag mismatch");

        // FakeLogger.Entries property (IReadOnlyList<FakeLogRecord>)
        var logEntries = fakeLogger.Entries;
        Console.WriteLine($"  -> FakeLogger.Count: {fakeLogger.Count}");
        Console.WriteLine($"  -> FakeLogger.Entries.Count: {logEntries.Count}");
        foreach (var entry in logEntries)
        {
            Console.WriteLine($"  -> FakeLogRecord: Level={entry.LogLevel}, Message='{entry.Message}'");
        }

        // FakeLogger.HasMessage() — assertion helper
        Console.WriteLine($"  -> FakeLogger.HasMessage('rotation'): {fakeLogger.HasMessage("rotation")}");
        Console.WriteLine($"  -> FakeLogger.HasMessage('NotPresent'): {fakeLogger.HasMessage("NotPresent")}");

        // FakeLogger.Messages — string-only snapshot for simple assertions
        var messages = fakeLogger.Messages;
        Console.WriteLine($"  -> FakeLogger.Messages count: {messages.Count}");

        // FakeLogRecord structure verification
        var infoEntry = logEntries[0];
        Console.WriteLine($"  -> FakeLogRecord.LogLevel: {infoEntry.LogLevel} (positional record field)");
        Console.WriteLine($"  -> FakeLogRecord.EventId:  {infoEntry.EventId}");
        Console.WriteLine($"  -> FakeLogRecord.Exception (no exception): {infoEntry.Exception?.GetType().Name ?? "null"}");
    }

    /// <summary>
    /// Custom sample IKeyStore implementation that logs cryptographic operations for compliance auditing.
    /// </summary>
    private sealed class CustomAuditedKeyStore : IKeyStore
    {
        private readonly IKeyStore _inner;

        public CustomAuditedKeyStore(IKeyStore inner)
        {
            _inner = inner;
        }

        public async ValueTask<global::EricksonLopez.Result.Result> SaveKeyAsync(CryptographicKey key, CancellationToken cancellationToken = default)
        {
            Console.WriteLine($"     [AUDIT LOG] Persisting key {key.Metadata.KeyId} (v{key.Metadata.Version}, Purpose: {key.Metadata.Purpose}) to secure store.");
            return await _inner.SaveKeyAsync(key, cancellationToken);
        }

        public async ValueTask<Result<CryptographicKey>> GetKeyAsync(KeyIdentifier keyId, KeyVersion version, CancellationToken cancellationToken = default)
        {
            Console.WriteLine($"     [AUDIT LOG] Reading key {keyId} (v{version}) from secure store.");
            return await _inner.GetKeyAsync(keyId, version, cancellationToken);
        }

        public ValueTask<Result<IReadOnlyList<KeyMetadata>>> ListMetadataAsync(KeyPurpose? purpose = null, CancellationToken cancellationToken = default)
        {
            Console.WriteLine($"     [AUDIT LOG] Listing key metadata (Filter: {purpose?.ToString() ?? "All"}).");
            return _inner.ListMetadataAsync(purpose, cancellationToken);
        }

        public ValueTask<global::EricksonLopez.Result.Result> UpdateStatusAsync(KeyIdentifier keyId, KeyVersion version, KeyStatus newStatus, CancellationToken cancellationToken = default)
        {
            Console.WriteLine($"     [AUDIT LOG] Updating status for key {keyId} (v{version}) to '{newStatus}'.");
            return _inner.UpdateStatusAsync(keyId, version, newStatus, cancellationToken);
        }
    }
}
