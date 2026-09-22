// Copyright © Erickson Lopez. MIT License.

using System;
using System.Text;
using System.Threading.Tasks;
using EricksonLopez.Security.Abstractions.KeyManagement;
using EricksonLopez.Security.Abstractions.Passwords;
using EricksonLopez.Security.Abstractions.Primitives;
using EricksonLopez.Security.Abstractions.Secrets;
using EricksonLopez.Security.Abstractions.Tokens;
using Microsoft.Extensions.DependencyInjection;

namespace EricksonLopez.Security.Sample.Levels;

/// <summary>
/// Level 1: Quick Start & Minimum Functional Setup.
/// Demonstrates the fastest path to integrating cryptographic protection,
/// password hashing, and token generation in a .NET application.
/// </summary>
public static class Level1_QuickStart
{
    public static async Task RunAsync()
    {
        Console.WriteLine("\n================================================================================");
        Console.WriteLine("  LEVEL 1: QUICK START — MINIMUM FUNCTIONAL CONFIGURATION");
        Console.WriteLine("================================================================================");

        // 1. Minimum Dependency Injection Setup
        var services = new ServiceCollection();
        services.AddEricksonLopezSecurity();
        using var provider = services.BuildServiceProvider();

        // 2. Resolve Core Security Services
        var keyLifecycle = provider.GetRequiredService<IKeyLifecycleManager>();
        var secretProtector = provider.GetRequiredService<ISecretProtector>();
        var passwordHasher = provider.GetRequiredService<IPasswordHasher>();
        var tokenGenerator = provider.GetRequiredService<ITokenGenerator>();

        Console.WriteLine("\n[1] Initializing Cryptographic Key Ring:");
        var activeKeyResult = await keyLifecycle.GenerateAndActivateKeyAsync(KeyPurpose.SecretProtection);
        var activeKey = activeKeyResult.Value;
        Console.WriteLine($"  -> Active Key: {activeKey.Metadata.KeyId} (v{activeKey.Metadata.Version}, Purpose: {activeKey.Metadata.Purpose})");

        Console.WriteLine("\n[2] Encrypting & Decrypting Sensitive Data (Authenticated Envelope):");
        var secretPayload = Encoding.UTF8.GetBytes("ApiKey=sk_live_999888777666;CardNumber=4532-0150-1234-5678");
        var envelopeResult = await secretProtector.ProtectAsync(secretPayload, KeyPurpose.SecretProtection);
        var envelopeBytes = envelopeResult.Value;
        Console.WriteLine($"  -> Plaintext length: {secretPayload.Length} bytes");
        Console.WriteLine($"  -> Encrypted envelope length: {envelopeBytes.Length} bytes (Includes header, IV, ciphertext & GCM tag)");

        var decryptedResult = await secretProtector.UnprotectAsync(envelopeBytes);
        var decryptedText = Encoding.UTF8.GetString(decryptedResult.Value);
        Console.WriteLine($"  -> Successfully Decrypted: {decryptedText}");

        Console.WriteLine("\n[3] Password Hashing with Memory-Hard Algorithm (Argon2id/PBKDF2):");
        const string rawPassword = "CorrectHorseBatteryStaple!2026#";
        var passwordHash = passwordHasher.HashPassword(rawPassword.AsSpan());
        Console.WriteLine($"  -> Formatted Modular Hash: {passwordHash}");

        var verificationResult = passwordHasher.VerifyPassword(rawPassword.AsSpan(), passwordHash);
        Console.WriteLine($"  -> Password Verification: {verificationResult} (Success={verificationResult == PasswordVerificationResult.Success})");

        Console.WriteLine("\n[4] Cryptographic Token & OTP Generation:");
        // GenerateToken() returns OpaqueToken (auto-redacted in ToString for log safety).
        // Use .Value to access the underlying string, or use GenerateHexToken/GenerateUrlSafeToken for raw strings.
        var opaqueToken = tokenGenerator.GenerateToken(32);
        var hexToken = tokenGenerator.GenerateHexToken(32);
        var urlSafeToken = tokenGenerator.GenerateUrlSafeToken(32);
        var numericOtp = tokenGenerator.GenerateNumericCode(6);
        Console.WriteLine($"  -> OpaqueToken (log-safe ToString): {opaqueToken}");
        Console.WriteLine($"  -> OpaqueToken.Value (authorized access): {opaqueToken.Value[..8]}... (truncated for display)");
        Console.WriteLine($"  -> Hex Token (64 chars): {hexToken}");
        Console.WriteLine($"  -> URL-Safe Token (Base64Url): {urlSafeToken}");
        Console.WriteLine($"  -> Numeric 6-Digit OTP: {numericOtp}");

        Console.WriteLine("\n[5] Password Hasher Algorithm & Rehash Detection:");
        Console.WriteLine($"  -> Active Password Algorithm: {passwordHasher.Algorithm}");
        var hashForRehashCheck = passwordHasher.HashPassword(rawPassword.AsSpan());
        var needsRehash = passwordHasher.NeedsRehash(hashForRehashCheck);
        Console.WriteLine($"  -> Current Hash NeedsRehash: {needsRehash} (false = current parameters are up-to-date)");

        Console.WriteLine("--------------------------------------------------------------------------------");
    }
}
