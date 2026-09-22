// Copyright © Erickson Lopez. MIT License.

using System;
using System.Text;
using System.Threading.Tasks;
using EricksonLopez.Security.Abstractions.Cryptography;
using EricksonLopez.Security.Abstractions.Errors;
using EricksonLopez.Security.Abstractions.Events;
using EricksonLopez.Security.Abstractions.KeyManagement;
using EricksonLopez.Security.Abstractions.Passwords;
using EricksonLopez.Security.Abstractions.Policies;
using EricksonLopez.Security.Abstractions.Primitives;
using EricksonLopez.Security.Abstractions.Secrets;
using EricksonLopez.Security.Abstractions.Tokens;
using EricksonLopez.Security.Cryptography;
using EricksonLopez.Security.Memory;
using EricksonLopez.Security.Randomness;
using EricksonLopez.Security.Tokens;
using Microsoft.Extensions.DependencyInjection;

namespace EricksonLopez.Security.Sample.Levels;

/// <summary>
/// Level 2: Comprehensive Configuration, Policies & Memory-Safe Primitives.
/// Demonstrates explicit cryptographic engine selection, security policy tuning,
/// binary envelope serialization, and zero-allocation memory-scrubbed secret buffers.
/// </summary>
public static class Level2_FullConfiguration
{
    public static void Run() => RunAsync().GetAwaiter().GetResult();

    public static async Task RunAsync()
    {
        Console.WriteLine("\n================================================================================");
        Console.WriteLine("  LEVEL 2: COMPREHENSIVE CONFIGURATION, POLICIES & MEMORY SAFETY");
        Console.WriteLine("================================================================================");

        // 1. Enterprise Security Policies Definition
        Console.WriteLine("\n[1] Fine-Tuning Enterprise Security Policies:");

        var customPasswordPolicy = new PasswordPolicy(
            MinimumLength: 14,
            MaximumLength: 128,
            RequireDigit: true,
            RequireUppercase: true,
            RequireLowercase: true,
            RequireNonAlphanumeric: true,
            MaxConsecutiveRepeatedChars: 3);

        var passwordEvaluationValid = customPasswordPolicy.Validate("SecureEnterprise#2026!Key");
        var passwordEvaluationWeak = customPasswordPolicy.Validate("short1!");

        Console.WriteLine($"  -> Policy Validation ('SecureEnterprise#2026!Key'): {(passwordEvaluationValid.IsSuccess ? "PASSED" : "FAILED")}");
        Console.WriteLine($"  -> Policy Validation ('short1!'): {(passwordEvaluationWeak.IsSuccess ? "PASSED" : "FAILED")} (Error: {passwordEvaluationWeak.Error.Description})");

        var rotationPolicy = new KeyRotationPolicy(
            RotationInterval: TimeSpan.FromDays(30),
            RetirementGracePeriod: TimeSpan.FromDays(90));

        var apiKeyPolicy = new ApiKeyPolicy(
            SecretByteLength: 32,
            MaxLifetime: TimeSpan.FromDays(90));

        Console.WriteLine($"  -> Key Rotation Policy: Interval={rotationPolicy.RotationInterval.TotalDays}d, GracePeriod={rotationPolicy.RetirementGracePeriod.TotalDays}d");
        Console.WriteLine($"  -> ApiKey Policy: SecretEntropy={apiKeyPolicy.SecretByteLength * 8} bits, MaxLifetime={apiKeyPolicy.MaxLifetime?.TotalDays}d");

        // TokenPolicy — validates OpaqueToken entropy and lifetime compliance
        var tokenPolicy = new TokenPolicy(MinimumByteLength: 32, MaxLifetime: TimeSpan.FromDays(15));
        var longToken = new OpaqueToken(new string('z', 44));  // 44 chars >= 32 minimum
        var shortToken = new OpaqueToken("short12345678901"); // 16 chars < 32 minimum
        var tokenValidPass = tokenPolicy.Validate(longToken);
        var tokenValidFail = tokenPolicy.Validate(shortToken);
        Console.WriteLine($"  -> TokenPolicy.Default: MinBytes={TokenPolicy.Default.MinimumByteLength}, MaxLifetime={TokenPolicy.Default.MaxLifetime?.TotalDays}d");
        Console.WriteLine($"  -> TokenPolicy Validate (44-char token): {(tokenValidPass.IsSuccess ? "PASSED" : "FAILED")}");
        Console.WriteLine($"  -> TokenPolicy Validate (short token): {(tokenValidFail.IsSuccess ? "PASSED" : "FAILED")} (Error: {tokenValidFail.Error.Description})");

        // Enumerations — Security domain model vocabulary
        Console.WriteLine("\n[1b] Enumerations — Security Domain Vocabulary:");

        // KeyPurpose — purpose-bound key authorization
        Console.WriteLine($"  -> KeyPurpose values: {string.Join(", ", Enum.GetNames<KeyPurpose>())}");
        Console.WriteLine($"  -> KeyPurpose.SecretProtection = {(int)KeyPurpose.SecretProtection}");
        Console.WriteLine($"  -> KeyPurpose.Signing = {(int)KeyPurpose.Signing}");

        // KeyStatus — key lifecycle states
        Console.WriteLine($"  -> KeyStatus values: {string.Join(", ", Enum.GetNames<KeyStatus>())}");

        // PasswordHashAlgorithm — supported adaptive KDF algorithms
        Console.WriteLine($"  -> PasswordHashAlgorithm values: {string.Join(", ", Enum.GetNames<PasswordHashAlgorithm>())}");

        // AeadAlgorithm — supported authenticated encryption schemes
        Console.WriteLine($"  -> AeadAlgorithm values: {string.Join(", ", Enum.GetNames<AeadAlgorithm>())}");

        // Strongly-typed Cryptographic Primitive Value Objects
        Console.WriteLine("\n[1c] Cryptographic Value Objects — Nonce, Salt, SecurityStamp, PasswordHash:");

        // KeyIdentifier — all factory methods
        var prefixedKeyId = KeyIdentifier.Prefixed("key_sec");
        Console.WriteLine($"  -> KeyIdentifier.Prefixed('key_sec'): {prefixedKeyId.Value}");
        bool keyIdCreated = KeyIdentifier.TryCreate("existing-key-id-abc123", out var parsedKeyId);
        Console.WriteLine($"  -> KeyIdentifier.TryCreate(): {keyIdCreated} — Value='{parsedKeyId}'");
        Console.WriteLine($"  -> KeyIdentifier comparisons: (New() == New()) = {KeyIdentifier.New() == KeyIdentifier.New()}");

        // Nonce — strongly-typed IV container
        var nonceBytes = new byte[Nonce.AesGcmStandardLength]; // 12 bytes
        CryptographicRandom.Shared.Fill(nonceBytes);
        var nonce = new Nonce(nonceBytes);
        Console.WriteLine($"  -> Nonce(byte[]): Length={nonce.Length} bytes, AesGcmStandardLength={Nonce.AesGcmStandardLength}");
        Console.WriteLine($"  -> Nonce.ToString(): {nonce}");

        var nonceFromSpan = new Nonce(nonce.Span); // Copy via ReadOnlySpan<byte>
        Console.WriteLine($"  -> Nonce equality (original == copy): {nonce == nonceFromSpan}");

        // Salt — strongly-typed salt container
        var saltBytes = new byte[Salt.DefaultLength]; // 16 bytes
        CryptographicRandom.Shared.Fill(saltBytes);
        var salt = new Salt(saltBytes);
        Console.WriteLine($"  -> Salt(byte[]): Length={salt.Length} bytes, DefaultLength={Salt.DefaultLength}");
        Console.WriteLine($"  -> Salt.ToString(): {salt}");

        // SecurityStamp — session and cache invalidation token
        var stamp1 = SecurityStamp.New();
        var stamp2 = SecurityStamp.New();
        Console.WriteLine($"  -> SecurityStamp.New(): {stamp1} (unique per call)");
        Console.WriteLine($"  -> SecurityStamp equality (different stamps): {stamp1 == stamp2}");
        bool created = SecurityStamp.TryCreate("existing-stamp-abc123", out var parsedStamp);
        Console.WriteLine($"  -> SecurityStamp.TryCreate(): {created} — Value='{parsedStamp}'");

        // PasswordHash — redacted strongly-typed hash container
        var hashString = "$pbkdf2-sha512$i=210000$fakeSaltBase64$fakeHashBase64ExampleOnly";
        var passwordHash = new PasswordHash(hashString);
        Console.WriteLine($"  -> PasswordHash.ToString() (redacted): {passwordHash}");
        Console.WriteLine($"  -> PasswordHash.Value (authorized read): {((string)passwordHash)[..20]}... (implicit string cast)");

        // 2. Direct Cryptographic Engine Selection (AES-256-GCM & ChaCha20-Poly1305)
        Console.WriteLine("\n[2] Direct AEAD Engine Selection (AES-256-GCM vs. ChaCha20-Poly1305):");

        var rawKey = new byte[32];
        CryptographicRandom.Shared.Fill(rawKey);
        var rawPlaintext = Encoding.UTF8.GetBytes("Payload requiring AEAD authenticated encryption.");
        var aad = Encoding.UTF8.GetBytes("TenantId=org_acme_corp_01");

        // AES-256-GCM
        var aesEngine = AesGcmEncryptionEngine.Shared;
        var aesResult = aesEngine.Encrypt(rawPlaintext, rawKey, aad);
        var aesEncrypted = aesResult.Value;
        Console.WriteLine($"  -> [AES-256-GCM] Algorithm: {aesEngine.Algorithm}, Ciphertext: {aesEncrypted.Ciphertext.Length}b, Tag: {aesEncrypted.Tag.Length}b, Nonce: {aesEncrypted.Nonce.Length}b");

        // ChaCha20-Poly1305
        var chachaEngine = ChaCha20Poly1305EncryptionEngine.Shared;
        var chachaResult = chachaEngine.Encrypt(rawPlaintext, rawKey, aad);
        var chachaEncrypted = chachaResult.Value;
        Console.WriteLine($"  -> [ChaCha20-Poly1305] Algorithm: {chachaEngine.Algorithm}, Ciphertext: {chachaEncrypted.Ciphertext.Length}b, Tag: {chachaEncrypted.Tag.Length}b, Nonce: {chachaEncrypted.Nonce.Length}b");

        // 3. Binary Security Envelope Serialization
        Console.WriteLine("\n[3] Binary Envelope Serialization (Interoperable Wire Format):");
        var serializer = BinarySecurityEnvelopeSerializer.Shared;
        var envelope = new SecurityEnvelope(
            FormatVersion: SecurityEnvelope.CurrentFormatVersion,
            Algorithm: AeadAlgorithm.Aes256Gcm,
            KeyId: KeyIdentifier.New(),
            KeyVersion: KeyVersion.Initial,
            Nonce: aesEncrypted.Nonce,
            Tag: aesEncrypted.Tag,
            Ciphertext: aesEncrypted.Ciphertext,
            AssociatedData: aad);

        var serializedEnvelope = serializer.Serialize(envelope);
        Console.WriteLine($"  -> Serialized Envelope Size: {serializedEnvelope.Length} bytes");

        // TrySerialize — zero-allocation stack-backed Span<byte> overload
        var spanBuffer = new byte[serializedEnvelope.Length + 64]; // pre-sized buffer
        bool trySerializeOk = serializer.TrySerialize(envelope, spanBuffer, out int bytesWrittenToSpan);
        Console.WriteLine($"  -> TrySerialize(Span<byte>) => Success={trySerializeOk}, BytesWritten={bytesWrittenToSpan} (matches Serialize: {bytesWrittenToSpan == serializedEnvelope.Length})");

        var deserializedResult = serializer.Deserialize(serializedEnvelope);
        var restoredEnvelope = deserializedResult.Value;
        Console.WriteLine($"  -> Deserialized Header: KeyId={restoredEnvelope.KeyId}, Version={restoredEnvelope.KeyVersion}, Algorithm={restoredEnvelope.Algorithm}");
        Console.WriteLine($"  -> Envelope.CiphertextLength: {restoredEnvelope.CiphertextLength} bytes | HasAssociatedData: {restoredEnvelope.HasAssociatedData}");

        // 4. Memory-Safe Scrubbing Buffer & Timing-Safe Comparisons
        Console.WriteLine("\n[4] Memory-Safe SecretBuffer (ArrayPool-backed & ZeroMemory on Dispose):");
        using (var secretBuffer = SecretBuffer.CreateRandom(32))
        {
            Console.WriteLine($"  -> Allocated SecretBuffer: Length={secretBuffer.Length}, String Repr='{secretBuffer}'");
            Console.WriteLine($"  -> Constant-Time Equality: {secretBuffer.FixedTimeEquals(secretBuffer.Span)}");
        } // At closing brace, CryptographicOperations.ZeroMemory() is guaranteed to execute and wipe the memory before returning to pool!
        Console.WriteLine("  -> SecretBuffer memory wiped and returned cleanly to ArrayPool<byte>.Shared.");

        // SecretBuffer.FromUtf8() — zero-intermediate-string factory from char span
        // Avoids creating a managed GC-allocated string from UI input (prevents string interning leaks)
        Console.WriteLine("\n[4a] SecretBuffer.FromUtf8() — Zero-Intermediate-String Password Capture:");
        ReadOnlySpan<char> passwordInput = "UserEnteredPassword$Ultra#Secure2026".AsSpan();
        using (var utf8Buffer = SecretBuffer.FromUtf8(passwordInput))
        {
            Console.WriteLine($"  -> SecretBuffer.FromUtf8() allocated: {utf8Buffer.Length} bytes (UTF-8 encoded, no managed string)");
            Console.WriteLine($"  -> SecretBuffer.IsDisposed (before Dispose): {utf8Buffer.IsDisposed}");
            Console.WriteLine($"  -> SecretBuffer.ToString() (redacted): {utf8Buffer}");
        }
        Console.WriteLine("  -> SecretBuffer.FromUtf8() disposed: UTF-8 bytes zeroed in ArrayPool slot — no string reference survives.");

        // AuthenticatedContext — strongly-typed AEAD Associated Authenticated Data (AAD)
        // Used to bind encrypted envelopes cryptographically to specific tenants or business contexts
        Console.WriteLine("\n[4b-ext] AuthenticatedContext — Strongly-Typed AEAD Binding Context:");

        // ForTenant() — factory that encodes 'tenant:<tenantId>' as UTF-8 AAD bytes
        var tenantCtx = AuthenticatedContext.ForTenant("tenant_fintech_enterprise_42");
        Console.WriteLine($"  -> AuthenticatedContext.ForTenant(): IsEmpty={tenantCtx.IsEmpty}, Span.Length={tenantCtx.Span.Length} bytes");

        // FromBytes() — factory accepting raw byte context for custom bindings
        var rawCtxBytes = Encoding.UTF8.GetBytes("RequestId=req-7f3a-9b12;Region=us-east-1");
        var rawCtx = AuthenticatedContext.FromBytes(rawCtxBytes);
        Console.WriteLine($"  -> AuthenticatedContext.FromBytes(): IsEmpty={rawCtx.IsEmpty}, Span.Length={rawCtx.Span.Length} bytes");

        // Empty — default (no AAD)
        var emptyCtx = AuthenticatedContext.Empty;
        Console.WriteLine($"  -> AuthenticatedContext.Empty: IsEmpty={emptyCtx.IsEmpty}");

        // Constant-time equality (via CryptographicOperations.FixedTimeEquals internally)
        var tenantCtx2 = AuthenticatedContext.ForTenant("tenant_fintech_enterprise_42");
        Console.WriteLine($"  -> Equality (same tenant): {tenantCtx == tenantCtx2}");
        Console.WriteLine($"  -> Inequality (different contexts): {tenantCtx != rawCtx}");

        // TimingSafeString
        var safeSecretA = new TimingSafeString("api_secret_token_12345");
        var safeSecretB = new TimingSafeString("api_secret_token_12345");
        var safeSecretC = new TimingSafeString("api_secret_token_99999");
        Console.WriteLine($"  -> TimingSafeString Equality (A == B): {safeSecretA.Equals(safeSecretB)}");
        Console.WriteLine($"  -> TimingSafeString Equality (A == C): {safeSecretA.Equals(safeSecretC)}");

        // Fingerprint — SHA-256 cryptographic fingerprint value object
        Console.WriteLine("\n[4b] Fingerprint — SHA-256 Content Integrity Fingerprints:");
        var fpFromString = Fingerprint.FromUtf8String("EricksonLopez.Security:v2026.1.0");
        var fpFromBytes = Fingerprint.FromBytes(rawPlaintext);
        var fpFromHex = new Fingerprint("3A7B9C2F1E4D8A0B5C6E7F2D9A1B3C4E5F6A7B8C9D0E1F2A3B4C5D6E7F8A9B0C");
        Console.WriteLine($"  -> Fingerprint.FromUtf8String(): {fpFromString.HexValue[..16]}... (SHA-256)");
        Console.WriteLine($"  -> Fingerprint.FromBytes(plaintext): {fpFromBytes.HexValue[..16]}...");
        Console.WriteLine($"  -> Fingerprint.FromHex (custom): {fpFromHex.HexValue[..16]}...");
        Console.WriteLine($"  -> Fingerprint Comparison (equal): {fpFromString.CompareTo(fpFromString) == 0}");

        // Secret<T> — typed secret wrapper with auto-redaction and memory scrubbing
        Console.WriteLine("\n[4c] Secret<T> — Typed Secret Container with Auto-Redaction:");
        using (var secretString = new Secret<string>("DatabasePassword!Ultra$Secret#2026"))
        {
            Console.WriteLine($"  -> Secret<string>.ToString() (safe for logs): {secretString}");
            Console.WriteLine($"  -> Secret<string>.Value (authorized access only): {secretString.Value[..8]}... (redacted for display)");
            Console.WriteLine($"  -> Secret<string>.Length: {secretString.Length}");
        } // IDisposable: value is cleared from memory on Dispose
        Console.WriteLine("  -> Secret<string> disposed: memory cleared.");

        using (var secretBytes = new Secret<byte[]>(new byte[] { 0x00, 0x01, 0x02, 0x03 }))
        {
            Console.WriteLine($"  -> Secret<byte[]>.IsDisposed (before): {secretBytes.IsDisposed}");
        }

        // Redacted<T> — implicit wrapper preventing sensitive data leakage in logs/traces
        Console.WriteLine("\n[4d] Redacted<T> — Log-Safe Sensitive Data Wrapper:");
        Redacted<string> redactedConnectionString = "Server=prod-sql-01.internal;Password=ultra$ecret!2026";
        Console.WriteLine($"  -> Redacted<string>.ToString() (safe for logs): {redactedConnectionString}");
        Console.WriteLine($"  -> Redacted<string>.HasValue: {redactedConnectionString.HasValue}");
        Console.WriteLine($"  -> Redacted<string>.UnsafeValue (authorized boundary only): {redactedConnectionString.UnsafeValue![..12]}... (truncated)");

        Redacted<string> redactedEmpty = default;
        Console.WriteLine($"  -> Redacted<string> default HasValue: {redactedEmpty.HasValue}");
        Console.WriteLine($"  -> Redacted<string> equality (same value): {(redactedConnectionString == new Redacted<string>(redactedConnectionString.UnsafeValue))}");

        // 5. HKDF-Enhanced AEAD & Post-Quantum Compatibility Slot (ADR-025)
        Console.WriteLine("\n[5] HKDF-Enhanced AEAD & Post-Quantum Compatibility Slot (ADR-025):");
        var hkdfEngine = HkdfAesGcmEncryptionEngine.Shared;
        Console.WriteLine($"  -> Canonical Engine: {nameof(HkdfAesGcmEncryptionEngine)}");
        Console.WriteLine($"  -> Algorithm: {hkdfEngine.Algorithm} (Value: {(byte)hkdfEngine.Algorithm})");
        Console.WriteLine($"  -> Substrate: {HkdfAesGcmEncryptionEngine.SubstrateDescription}");
        Console.WriteLine($"  -> Quantum Resistant: {HkdfAesGcmEncryptionEngine.IsQuantumResistant} (Forward roadmap slot reserved for ML-KEM-768)");
        Console.WriteLine($"  -> Key Size: {hkdfEngine.KeySizeBytes * 8} bits | Nonce Size: {hkdfEngine.NonceSizeBytes * 8} bits | Tag Size: {hkdfEngine.TagSizeBytes * 8} bits");

        var pqPlaintext = Encoding.UTF8.GetBytes("Ephemeral-key-isolated secret payload per operation (ADR-025).");
        var pqEncryptResult = hkdfEngine.Encrypt(pqPlaintext, rawKey, aad);
        var pqEncrypted = pqEncryptResult.Value;
        Console.WriteLine($"  -> [HKDF-AES-GCM] Ciphertext: {pqEncrypted.Ciphertext.Length}b, Tag: {pqEncrypted.Tag.Length}b, Nonce: {pqEncrypted.Nonce.Length}b");

        var pqDecryptDestination = new byte[pqPlaintext.Length];
        var pqDecryptResult = hkdfEngine.Decrypt(pqEncrypted.Ciphertext.Span, rawKey, pqEncrypted.Nonce.Span, pqEncrypted.Tag.Span, aad,
            pqDecryptDestination, out var pqBytesWritten);
        Console.WriteLine($"  -> [HKDF-AES-GCM] Decryption: {(pqDecryptResult.IsSuccess ? "SUCCESS" : "FAILED")} ({pqBytesWritten} bytes recovered)");


        Console.WriteLine("--------------------------------------------------------------------------------");

        // =========================================================================
        // [11] ISecurityPolicy<T> — Base Contract Reference & Dual-PBKDF2 Note
        // =========================================================================
        Console.WriteLine("\n[11] ISecurityPolicy<T> — Direct Polymorphic Policy Reference:");
        // PasswordPolicy, TokenPolicy, ApiKeyPolicy all implement ISecurityPolicy<T>.
        ISecurityPolicy<OpaqueToken> tokenPolicyAsBase = new TokenPolicy(MinimumByteLength: 16);
        ISecurityPolicy<string> pwdPolicyAsBase = new PasswordPolicy(
            MinimumLength: 12, MaximumLength: 128,
            RequireDigit: true, RequireUppercase: false,
            RequireLowercase: false, RequireNonAlphanumeric: false,
            MaxConsecutiveRepeatedChars: 5);
        var baseResultToken = tokenPolicyAsBase.Validate(new OpaqueToken(new string('a', 20)));
        var baseResultPwd = pwdPolicyAsBase.Validate("strongPassword1");
        Console.WriteLine($"  -> ISecurityPolicy<OpaqueToken>.Validate() (20-char): {(baseResultToken.IsSuccess ? "PASSED" : "FAILED")}");
        Console.WriteLine($"  -> ISecurityPolicy<string>.Validate() ('strongPassword1'): {(baseResultPwd.IsSuccess ? "PASSED" : "FAILED")}");

        // =========================================================================
        // [12] Missing SecurityError Factories — Complete Error Catalog
        // =========================================================================
        Console.WriteLine("\n[12] SecurityError Complete Factory Catalog (remaining entries):");
        var errInvalidKey = SecurityError.InvalidKey("Key material is 15 bytes, but AES-256-GCM requires exactly 32 bytes.");
        Console.WriteLine($"  -> {errInvalidKey.Code}: {errInvalidKey.Description}");

        var errEncFailed = SecurityError.EncryptionFailed("AES-GCM internal fault: nonce reuse detected.");
        Console.WriteLine($"  -> {errEncFailed.Code}: {errEncFailed.Description}");

        var errDecFailed = SecurityError.DecryptionFailed("Authentication tag mismatch during ChaCha20-Poly1305 decryption.");
        Console.WriteLine($"  -> {errDecFailed.Code}: {errDecFailed.Description}");

        var errInvalidPwd = SecurityError.InvalidPassword("Provided password does not meet complexity requirements.");
        Console.WriteLine($"  -> {errInvalidPwd.Code}: {errInvalidPwd.Description}");

        var errInvalidNonce = SecurityError.InvalidNonce("Cryptographic nonce length mismatch or reused nonce detected.");
        Console.WriteLine($"  -> {errInvalidNonce.Code}: {errInvalidNonce.Description}");

        var errBufferTooSmall = SecurityError.BufferTooSmall("Destination span is smaller than required output size.");
        Console.WriteLine($"  -> {errBufferTooSmall.Code}: {errBufferTooSmall.Description}");

        // =========================================================================
        // [13] AddEricksonLopezCryptographyCore() — Tier-1 Cryptography DI Package
        // =========================================================================
        Console.WriteLine("\n[13] EricksonLopez.Security.Cryptography — Tier-1 Package Notes:");
        Console.WriteLine("  The EricksonLopez.Security.Cryptography package provides standalone tier-1 primitives:");
        Console.WriteLine("  -> AddEricksonLopezCryptographyCore(): Registers ICryptographicRandomNumberGenerator,");
        Console.WriteLine("     IConstantTimeComparer, IAuthenticatedEncryptionEngine, and IPasswordHasher (PBKDF2.V1$ format).");
        Console.WriteLine("  IMPORTANT: EricksonLopez.Security.Cryptography.Passwords.Pbkdf2PasswordHasher uses format:");
        Console.WriteLine("    'PBKDF2.V1$<iterations>$<salt>$<hash>' with 600,000 iterations (OWASP recommended).");
        Console.WriteLine("  EricksonLopez.Security.Passwords.Pbkdf2PasswordHasher uses format:");
        Console.WriteLine("    '$pbkdf2-sha512$i=210000$s=<salt>$<hash>' with 210,000 iterations.");
        Console.WriteLine("  These are INCOMPATIBLE — do not mix them in the same verification path (see ADR-023).");

        // Demonstrate CSPRNG, ConstantTimeComparer, TimingSafeString, SecretBuffer advanced, and DI extension methods
        DemonstrateCsprngAndConstantTime();
        await DemonstrateAadAndKeyLifecycleAsync();
    }

    private static void DemonstrateCsprngAndConstantTime()
    {
        // =========================================================================
        // [6] CryptographicRandom — Full CSPRNG API (ICryptographicRandomNumberGenerator)
        // =========================================================================
        Console.WriteLine("\n[6] CryptographicRandom — Full CSPRNG API:");
        var csprng = CryptographicRandom.Shared;

        // Fill — direct Span<byte> fill (zero allocation)
        Span<byte> fillTarget = stackalloc byte[16];
        csprng.Fill(fillTarget);
        Console.WriteLine($"  -> Fill(Span<byte>[16]): {Convert.ToHexString(fillTarget)}");

        // GetInt32 — bounded random integer (no modulo bias)
        int randomInt = csprng.GetInt32(1, 101);  // [1, 100] inclusive
        Console.WriteLine($"  -> GetInt32(1, 101): {randomInt} (range: 1..100)");

        // GetBytes — allocates new byte[]
        byte[] randomBytes = csprng.GetBytes(32);
        Console.WriteLine($"  -> GetBytes(32): {Convert.ToHexString(randomBytes)[..16]}... (hex, 32 bytes)");

        // GetUrlSafeString — Base64Url encoded random string
        string urlSafe = csprng.GetUrlSafeString(32);
        Console.WriteLine($"  -> GetUrlSafeString(32): {urlSafe[..16]}... (Base64Url, no +/=)");

        // GetHexString — lowercase hex encoded random string
        string hexStr = csprng.GetHexString(16);
        Console.WriteLine($"  -> GetHexString(16): {hexStr} (32 hex chars)");

        // =========================================================================
        // [7] ConstantTimeComparer & IConstantTimeComparer — Timing Attack Resistance
        // =========================================================================
        Console.WriteLine("\n[7] ConstantTimeComparer — Side-Channel Resistant Comparison:");
        var comparer = ConstantTimeComparer.Shared;

        // FixedTimeEquals(ReadOnlySpan<byte>, ReadOnlySpan<byte>)
        byte[] secret1 = [0x01, 0x02, 0x03, 0x04];
        byte[] secret2 = [0x01, 0x02, 0x03, 0x04];
        byte[] secret3 = [0x01, 0x02, 0x03, 0x05];
        Console.WriteLine($"  -> FixedTimeEquals(byte, byte) equal:     {comparer.FixedTimeEquals(secret1, secret2)}");
        Console.WriteLine($"  -> FixedTimeEquals(byte, byte) different:  {comparer.FixedTimeEquals(secret1, secret3)}");

        // FixedTimeEquals(ReadOnlySpan<char>, ReadOnlySpan<char>)
        string token1 = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
        string token2 = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
        string token3 = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9"; // different
        Console.WriteLine($"  -> FixedTimeEquals(char, char) equal:     {comparer.FixedTimeEquals(token1.AsSpan(), token2.AsSpan())}");
        Console.WriteLine($"  -> FixedTimeEquals(char, char) different:  {comparer.FixedTimeEquals(token1.AsSpan(), token3.AsSpan())}");

        // Static Equals(string, string) — null-safe constant-time string comparison
        Console.WriteLine($"  -> ConstantTimeComparer.Equals(string, string): {ConstantTimeComparer.Equals(token1, token2)}");
        Console.WriteLine($"  -> ConstantTimeComparer.Equals(null, null): {ConstantTimeComparer.Equals(null, null)}");
        Console.WriteLine($"  -> ConstantTimeComparer.Equals(null, string): {ConstantTimeComparer.Equals(null, token1)}");

        // =========================================================================
        // [8] TimingSafeString — Credential Wrapper with Constant-Time Equality
        // =========================================================================
        Console.WriteLine("\n[8] TimingSafeString — Timing-Attack-Resistant String Wrapper:");

        TimingSafeString safeToken1 = "sensitive-api-key-abc123-xyz789";  // implicit conversion
        TimingSafeString safeToken2 = "sensitive-api-key-abc123-xyz789";
        TimingSafeString safeToken3 = "different-api-key-000000-000000";

        Console.WriteLine($"  -> TimingSafeString.Length: {safeToken1.Length}");
        Console.WriteLine($"  -> TimingSafeString.IsEmpty: {safeToken1.IsEmpty}");
        Console.WriteLine($"  -> TimingSafeString.ToString() (redacted): {safeToken1}");
        Console.WriteLine($"  -> TimingSafeString == same value:     {safeToken1 == safeToken2}  (constant time)");
        Console.WriteLine($"  -> TimingSafeString == different:      {safeToken1 == safeToken3} (constant time)");
        Console.WriteLine($"  -> TimingSafeString.AsSpan().Length:   {safeToken1.AsSpan().Length}");

        // =========================================================================
        // [9] SecretBuffer Advanced — FromSpan, GetWritableSpan, FixedTimeEquals
        // =========================================================================
        Console.WriteLine("\n[9] SecretBuffer Advanced — FromSpan, GetWritableSpan, FixedTimeEquals:");

        // SecretBuffer.FromSpan — copies from an existing byte span
        byte[] existingKeyMaterial = csprng.GetBytes(32);
        using var fromSpanBuffer = SecretBuffer.FromSpan(existingKeyMaterial);
        Console.WriteLine($"  -> SecretBuffer.FromSpan(byte[32]): Length={fromSpanBuffer.Length}, IsDisposed={fromSpanBuffer.IsDisposed}");
        Console.WriteLine($"  -> SecretBuffer.ToString() (redacted): {fromSpanBuffer}");

        // GetWritableSpan — exposes writable Span<byte> for initialization only
        using var writableBuffer = new SecretBuffer(32);
        var writable = writableBuffer.GetWritableSpan();
        CryptographicRandom.Shared.Fill(writable);  // populate with random bytes
        Console.WriteLine($"  -> SecretBuffer.GetWritableSpan(): {writable.Length} bytes writable (first byte: 0x{writable[0]:X2})");

        // FixedTimeEquals — constant-time comparison of two secret buffers
        byte[] referenceKey = [.. fromSpanBuffer.Span]; // copy for comparison
        Console.WriteLine($"  -> SecretBuffer.FixedTimeEquals (same content): {fromSpanBuffer.FixedTimeEquals(fromSpanBuffer.Span)}");
        Console.WriteLine($"  -> SecretBuffer.FixedTimeEquals (different):    {fromSpanBuffer.FixedTimeEquals(writableBuffer.Span)}");

        // =========================================================================
        // [10] Granular DI Extension Methods — Selective Service Registration
        // =========================================================================
        Console.WriteLine("\n[10] Granular DI Extension Methods — Selective Service Registration:");
        Console.WriteLine("  Available extension methods on IServiceCollection:");
        Console.WriteLine("  -> AddSecurityCore()       — CSPRNG, ConstantTimeComparer, AES-256-GCM, BinarySerializer");
        Console.WriteLine("  -> AddKeyManagement()      — IKeyStore (InMemory), KeyRing, IKeyLifecycleManager");
        Console.WriteLine("  -> AddPasswordSecurity()   — Pbkdf2PasswordHasher, Argon2idPasswordHasher, CompositePasswordHasher, ISimplePasswordHasher");
        Console.WriteLine("  -> AddTokenSecurity()      — InMemoryApiKeyStore, OpaqueTokenGenerator, HmacSha256TokenHasher, ApiKeyGenerator, ApiKeyValidator");
        Console.WriteLine("  -> AddSecretProtection()   — AesGcmSecretProtector, EnvironmentSecretStore, CompositeSecretResolver");
        Console.WriteLine("  -> AddEricksonLopezSecurity() — Calls all of the above (batteries-included one-liner)");

        // Demonstrate selective/granular registration: only passwords + tokens (no key lifecycle)
        var selectiveServices = new Microsoft.Extensions.DependencyInjection.ServiceCollection();
        selectiveServices.AddPasswordSecurity(iterations: 150_000); // custom iteration count
        selectiveServices.AddTokenSecurity();
        using var selectiveProvider = selectiveServices.BuildServiceProvider();

        var hasher = selectiveProvider.GetRequiredService<IPasswordHasher>();
        var tokenGen = selectiveProvider.GetRequiredService<ITokenGenerator>();
        Console.WriteLine($"  -> Selective AddPasswordSecurity: Algorithm={hasher.Algorithm}");
        Console.WriteLine($"  -> Selective AddTokenSecurity: Token generated={tokenGen.GenerateHexToken(16).Length} hex chars");

        // =========================================================================
        // [14] ISimplePasswordHasher — String-Based Password Hashing Contract
        // =========================================================================
        Console.WriteLine("\n[14] ISimplePasswordHasher — Simplified String-Based Password Hashing:");
        // ISimplePasswordHasher provides string-oriented API (no ReadOnlySpan<char> required)
        // CompositePasswordHasher implements both IPasswordHasher and ISimplePasswordHasher
        var simpleHasher = selectiveProvider.GetRequiredService<ISimplePasswordHasher>();

        const string simpleTestPwd = "SimpleApiPassword!#2026";
        var simpleHash = simpleHasher.Hash(simpleTestPwd);           // string Hash(string password)
        Console.WriteLine($"  -> ISimplePasswordHasher.Hash(): {simpleHash[..20]}...");

        var simpleVerifyOk = simpleHasher.Verify(simpleTestPwd, simpleHash);      // bool Verify(string, string)
        var simpleVerifyFail = simpleHasher.Verify("wrongPwd!", simpleHash);
        Console.WriteLine($"  -> ISimplePasswordHasher.Verify (correct): {simpleVerifyOk}");
        Console.WriteLine($"  -> ISimplePasswordHasher.Verify (wrong):   {simpleVerifyFail}");

        var simpleNeedsRehash = simpleHasher.NeedsRehash(simpleHash);  // bool NeedsRehash(string)
        Console.WriteLine($"  -> ISimplePasswordHasher.NeedsRehash (current params): {simpleNeedsRehash}");

        // =========================================================================
        // [15] OpaqueTokenGenerator.Shared — Static Singleton Access
        // =========================================================================
        Console.WriteLine("\n[15] OpaqueTokenGenerator.Shared — Static Singleton Access (No DI Required):");
        // OpaqueTokenGenerator.Shared provides the same API as ITokenGenerator but accessible
        // without dependency injection — useful in static utility contexts or tests.
        var opaqueTokenShared = OpaqueTokenGenerator.Shared.GenerateToken(32);
        Console.WriteLine($"  -> OpaqueTokenGenerator.Shared.GenerateToken(32): Type={opaqueTokenShared.GetType().Name}");
        Console.WriteLine($"  -> OpaqueTokenGenerator.Shared.GenerateUrlSafeToken(16): {OpaqueTokenGenerator.Shared.GenerateUrlSafeToken(16).Length} chars");
        Console.WriteLine($"  -> OpaqueTokenGenerator.Shared.GenerateHexToken(16): {OpaqueTokenGenerator.Shared.GenerateHexToken(16).Length} hex chars");
        Console.WriteLine($"  -> OpaqueTokenGenerator.Shared.GenerateNumericCode(8): {OpaqueTokenGenerator.Shared.GenerateNumericCode(8)}");

        // =========================================================================
        // [16] SecurityEventSeverity — All Enum Values
        // =========================================================================
        Console.WriteLine("\n[16] SecurityEventSeverity — Security Domain Audit Event Severity Taxonomy:");
        Console.WriteLine($"  -> SecurityEventSeverity.Informational = {SecurityEventSeverity.Informational}");
        Console.WriteLine($"  -> SecurityEventSeverity.Warning       = {SecurityEventSeverity.Warning}");
        Console.WriteLine($"  -> SecurityEventSeverity.Critical      = {SecurityEventSeverity.Critical}");
        Console.WriteLine($"  -> All values: {string.Join(", ", Enum.GetNames<SecurityEventSeverity>())}");

        // =========================================================================
        // [17] KeyPurpose.Encryption — All Enum Values Explicitly
        // =========================================================================
        Console.WriteLine("\n[17] KeyPurpose — All Purpose-Bound Key Authorization Values:");
        foreach (var purposeName in Enum.GetNames<KeyPurpose>())
        {
            var purposeVal = Enum.Parse<KeyPurpose>(purposeName);
            Console.WriteLine($"  -> KeyPurpose.{purposeName} = {(int)purposeVal}");
        }
    }

    private static async Task DemonstrateAadAndKeyLifecycleAsync()
    {
        // =========================================================================
        // [18] ISecretProtector — AAD (Associated Data) Overloads
        // =========================================================================
        Console.WriteLine("\n[18] ISecretProtector — Associated Data (AAD) Binding for Context Authentication:");

        var aadServices = new ServiceCollection();
        aadServices.AddEricksonLopezSecurity();
        using var aadProvider = aadServices.BuildServiceProvider();

        var aadKeyLifecycle = aadProvider.GetRequiredService<IKeyLifecycleManager>();
        var aadSecretProtector = aadProvider.GetRequiredService<ISecretProtector>();

        // Seed key ring
        await aadKeyLifecycle.GenerateAndActivateKeyAsync(KeyPurpose.SecretProtection);

        var sensitivePayload = Encoding.UTF8.GetBytes("UserPII: SSN=987-65-4321");
        // AAD: bound to tenant and user ID — decryption will fail if AAD changes
        var associatedData = Encoding.UTF8.GetBytes("TenantId=acme_corp;UserId=usr_cfo_001");

        // Async ProtectAsync with AAD
        var expectedAssociatedData = AuthenticatedContext.FromBytes(Encoding.UTF8.GetBytes("TenantId=acme_corp;UserId=usr_cfo_001"));
        var protectedWithAad = await aadSecretProtector.ProtectAsync(
            secret: sensitivePayload,
            purpose: KeyPurpose.SecretProtection,
            expectedAssociatedData: expectedAssociatedData);
        Console.WriteLine($"  -> ProtectAsync (with AAD): {protectedWithAad.Value.Length} bytes (authenticated against TenantId+UserId)");

        // Async UnprotectAsync with matching AAD (succeeds)
        var decryptedMatchAad = await aadSecretProtector.UnprotectAsync(
            protectedData: protectedWithAad.Value,
            expectedAssociatedData: expectedAssociatedData);
        Console.WriteLine($"  -> UnprotectAsync (matching AAD): {(decryptedMatchAad.IsSuccess ? "SUCCESS" : "FAILED")}");

        // Async UnprotectAsync with wrong AAD (AEAD tag mismatch — EXPECTED failure)
        var wrongAad = AuthenticatedContext.FromBytes(Encoding.UTF8.GetBytes("TenantId=evil_corp;UserId=attacker"));
        var decryptedWrongAad = await aadSecretProtector.UnprotectAsync(
            protectedData: protectedWithAad.Value,
            expectedAssociatedData: wrongAad);
        Console.WriteLine($"  -> UnprotectAsync (wrong AAD — AAD tamper): {(decryptedWrongAad.IsSuccess ? "NOTE: AAD not enforced at UnprotectAsync layer" : "REJECTED (Tamper Detected)")} — {(decryptedWrongAad.IsSuccess ? "implementation-dependent" : $"Code: {decryptedWrongAad.Error.Code}")}");

        // Synchronous Protect/Unprotect with AAD
        var syncWithAad = aadSecretProtector.Protect(
            secret: sensitivePayload,
            purpose: KeyPurpose.SecretProtection,
            expectedAssociatedData: expectedAssociatedData);
        Console.WriteLine($"  -> Protect (sync, AAD): {syncWithAad.Value.Length} bytes");

        var syncUnprotectAad = aadSecretProtector.Unprotect(
            protectedData: syncWithAad.Value,
            expectedAssociatedData: expectedAssociatedData);
        Console.WriteLine($"  -> Unprotect (sync, AAD): {(syncUnprotectAad.IsSuccess ? "SUCCESS" : "FAILED")}");

        // =========================================================================
        // [19] IKeyLifecycleManager — Explicit AlgorithmId + ValidityPeriod Overloads
        // =========================================================================
        Console.WriteLine("\n[19] IKeyLifecycleManager — Explicit AlgorithmId + ValidityPeriod Overloads:");
        var timedKey = await aadKeyLifecycle.GenerateAndActivateKeyAsync(
            purpose: KeyPurpose.Signing,
            algorithmId: "ECDSA-P256",        // explicit algorithm label
            validityPeriod: TimeSpan.FromDays(30));
        Console.WriteLine($"  -> GenerateAndActivateKeyAsync (Signing, ECDSA-P256, 30d): {timedKey.Value.Metadata.KeyId}");
        Console.WriteLine($"  -> Algorithm: {timedKey.Value.Metadata.AlgorithmId} | Expires: {timedKey.Value.Metadata.ExpiresAtUtc?.ToString("yyyy-MM-dd") ?? "never"}");

        var rotatedTimedKey = await aadKeyLifecycle.RotateKeyAsync(
            purpose: KeyPurpose.Signing,
            validityPeriod: TimeSpan.FromDays(30));
        Console.WriteLine($"  -> RotateKeyAsync (Signing, 30d validity): NewVersion={rotatedTimedKey.Value.Metadata.Version}");

        Console.WriteLine("--------------------------------------------------------------------------------");
    }
}
