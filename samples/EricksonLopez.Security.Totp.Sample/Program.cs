// Copyright © Erickson Lopez. MIT License.
// Sample: TOTP Multi-Factor Authentication + Recovery Codes
//
// This sample demonstrates the full MFA enrollment and verification lifecycle:
//   1. Generate a TOTP secret key.
//   2. Display the otpauth:// URI (scan with Google Authenticator, Authy, 1Password).
//   3. Verify a TOTP code entered by the user (with ±1 step tolerance).
//   4. Generate emergency recovery codes (hashed for storage).
//   5. Redeem a recovery code (single-use).
//
// To run:
//   cd samples/EricksonLopez.Security.Totp.Sample
//   dotnet run

using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using EricksonLopez.Security;
using EricksonLopez.Security.Mfa;
using Microsoft.Extensions.DependencyInjection;

Console.WriteLine("╔══════════════════════════════════════════════════════════╗");
Console.WriteLine("║  EricksonLopez.Security — TOTP + Recovery Codes Sample  ║");
Console.WriteLine("╚══════════════════════════════════════════════════════════╝");
Console.WriteLine();

// ─── Setup DI ─────────────────────────────────────────────────────────────────

var services = new ServiceCollection();
services.AddEricksonLopezSecurity();
services.AddSecurityMfa();
using var sp = services.BuildServiceProvider();

var totpService = sp.GetRequiredService<ITotpService>();

// ─── Step 1: TOTP Enrollment ──────────────────────────────────────────────────

Console.WriteLine("── STEP 1: TOTP ENROLLMENT ─────────────────────────────────");
Console.WriteLine();

// Simulate a user enrolling MFA
const string userEmail = "alice@example.com";
const string appName = "EricksonLopez.Security Demo";

// Generate a setup for the user (one-time — store secretKey encrypted in DB)
var setup = totpService.GenerateSetupInfo(
    issuer: appName,
    accountName: userEmail);

Console.WriteLine($"  User:        {userEmail}");
Console.WriteLine($"  Secret Key:  {setup.SecretKey}  ← Encrypt and store in DB");
Console.WriteLine($"  OTP URI:     {setup.AuthenticatorUri}");
Console.WriteLine();
Console.WriteLine("  ┌─────────────────────────────────────────────────────┐");
Console.WriteLine($"  │ Scan with authenticator app or open this URI:       │");
Console.WriteLine($"  │ {setup.AuthenticatorUri[..Math.Min(50, setup.AuthenticatorUri.Length)]}... │");
Console.WriteLine("  └─────────────────────────────────────────────────────┘");
Console.WriteLine();

// ─── Step 2: Verify TOTP Code ─────────────────────────────────────────────────

Console.WriteLine("── STEP 2: TOTP VERIFICATION ───────────────────────────────");
Console.WriteLine();

// Simulate computing the code for 'now' (in a real app the user enters this)
var now = DateTimeOffset.UtcNow;
var expectedCode = totpService.ComputeCode(setup.SecretKey, now);

Console.WriteLine($"  Current TOTP code (auto-computed for demo): {expectedCode}");
Console.WriteLine($"  Valid window: {now:HH:mm:ss} UTC ± 30 seconds");
Console.WriteLine();

// Verify the code (as the server would do when user submits the form)
var isValid = totpService.VerifyCode(setup.SecretKey, expectedCode, now);
Console.WriteLine($"  Verification result: {(isValid ? "✅ VALID" : "❌ INVALID")}");
Console.WriteLine();

// Demonstrate invalid code rejection
var wrongCode = expectedCode == "000000" ? "111111" : "000000";
var isWrongValid = totpService.VerifyCode(setup.SecretKey, wrongCode, now);
Console.WriteLine($"  Wrong code '{wrongCode}' result: {(isWrongValid ? "✅ (unexpected)" : "❌ REJECTED (expected)")}");
Console.WriteLine();

// ─── Step 3: Generate Recovery Codes ──────────────────────────────────────────

Console.WriteLine("── STEP 3: RECOVERY CODE GENERATION ───────────────────────");
Console.WriteLine();

// Generate 10 single-use recovery codes
string[] recoveryCodes = new RecoveryCodeGenerator().GenerateCodes(count: 10, codeLength: 10);

Console.WriteLine("  Generated recovery codes (show to user ONCE — hash and store in DB):");
Console.WriteLine();
for (var i = 0; i < recoveryCodes.Length; i++)
{
    Console.WriteLine($"    {i + 1,2}. {recoveryCodes[i]}");
}
Console.WriteLine();

// ─── Step 4: Hash Recovery Codes for Storage ──────────────────────────────────

Console.WriteLine("── STEP 4: STORING HASHED RECOVERY CODES ──────────────────");
Console.WriteLine();
Console.WriteLine("  In production: store the SHA-256 hash of each code, not the plaintext.");
Console.WriteLine("  Never store plaintext recovery codes in your database.");
Console.WriteLine();

// Simulate hashing recovery codes for storage (use bcrypt or Argon2 in production)
var hashedCodes = new Dictionary<string, bool>(); // hash → isUsed
foreach (var code in recoveryCodes)
{
    var hash = ComputeRecoveryCodeHash(code);
    hashedCodes[hash] = false;
    Console.WriteLine($"    Stored: {hash[..16]}... (isUsed: false)");
}
Console.WriteLine();

// ─── Step 5: Redeem a Recovery Code ───────────────────────────────────────────

Console.WriteLine("── STEP 5: RECOVERY CODE REDEMPTION ───────────────────────");
Console.WriteLine();

// Simulate user submitting the 3rd recovery code
var attemptedCode = recoveryCodes[2];
Console.WriteLine($"  User attempts recovery with code: {attemptedCode}");

var attemptHash = ComputeRecoveryCodeHash(attemptedCode);
if (hashedCodes.TryGetValue(attemptHash, out var isUsed))
{
    if (!isUsed)
    {
        hashedCodes[attemptHash] = true; // Mark as used (single-use)
        Console.WriteLine("  ✅ Recovery code ACCEPTED — code marked as used (cannot be reused).");
    }
    else
    {
        Console.WriteLine("  ❌ Recovery code ALREADY USED — rejected.");
    }
}
else
{
    Console.WriteLine("  ❌ Recovery code NOT FOUND — rejected.");
}
Console.WriteLine();

// Demonstrate that the same code is rejected on second attempt
Console.WriteLine($"  Attempting to reuse the same code: {attemptedCode}");
if (hashedCodes.TryGetValue(attemptHash, out var isUsed2) && isUsed2)
{
    Console.WriteLine("  ❌ Recovery code ALREADY USED — replay attack prevented.");
}
Console.WriteLine();

Console.WriteLine("╔══════════════════════════════════════════════════════════╗");
Console.WriteLine("║  Sample Completed Successfully!                          ║");
Console.WriteLine("╚══════════════════════════════════════════════════════════╝");

// Helper: compute a deterministic hash for a recovery code
// In production: use Argon2id or PBKDF2 for recovery codes (not SHA-256)
static string ComputeRecoveryCodeHash(string code)
{
    var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(code.Replace("-", "")));
    return Convert.ToHexString(bytes).ToLowerInvariant();
}
