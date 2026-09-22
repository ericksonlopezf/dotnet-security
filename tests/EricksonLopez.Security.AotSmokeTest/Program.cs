// Copyright © Erickson Lopez. MIT License.

using System;
using System.Text;
using EricksonLopez.Security.Abstractions.Cryptography;
using EricksonLopez.Security.Abstractions.KeyManagement;
using EricksonLopez.Security.Abstractions.Passwords;
using EricksonLopez.Security.Abstractions.Primitives;
using EricksonLopez.Security.Abstractions.Secrets;
using EricksonLopez.Security.Abstractions.Tokens;
using EricksonLopez.Security.Cryptography;
using EricksonLopez.Security.KeyManagement;
using EricksonLopez.Security.Passwords;
using EricksonLopez.Security.Secrets;
using EricksonLopez.Security.Tokens;
using Microsoft.Extensions.DependencyInjection;

Console.WriteLine("=== EricksonLopez.Security Native AOT Smoke Test ===");

// 1. Dependency Injection Verification
var services = new ServiceCollection();
services.AddEricksonLopezSecurity();
using var serviceProvider = services.BuildServiceProvider();

// 2. Key Management & Lifecycle Test
var lifecycle = serviceProvider.GetRequiredService<IKeyLifecycleManager>();
var keyRing = serviceProvider.GetRequiredService<IKeyRing>();

var keyResult = await lifecycle.GenerateAndActivateKeyAsync(KeyPurpose.Encryption);
if (keyResult.IsFailure)
{
    Console.Error.WriteLine($"[FAIL] Key generation failed: {keyResult.Error.Description}");
    return 1;
}
Console.WriteLine($"[PASS] Generated active key: {keyResult.Value.Metadata.KeyId}:{keyResult.Value.Metadata.Version}");

// 3. AEAD AES-GCM Encryption Engine Test
var engine = serviceProvider.GetRequiredService<IAuthenticatedEncryptionEngine>();
var plaintext = Encoding.UTF8.GetBytes("Native AOT Confidential Data Payload");
var aad = Encoding.UTF8.GetBytes("tenant-aot-1");

var encryptResult = engine.Encrypt(plaintext, keyResult.Value.GetKeyBytes(), aad);
if (encryptResult.IsFailure)
{
    Console.Error.WriteLine($"[FAIL] AES-GCM encryption failed: {encryptResult.Error.Description}");
    return 1;
}

var encrypted = encryptResult.Value;
var decryptedBuffer = new byte[plaintext.Length];
var decryptResult = engine.Decrypt(
    ciphertext: encrypted.Ciphertext.Span,
    key: keyResult.Value.GetKeyBytes(),
    nonce: encrypted.Nonce.Span,
    tag: encrypted.Tag.Span,
    associatedData: aad,
    plaintextDestination: decryptedBuffer,
    out int written);

if (decryptResult.IsFailure || written != plaintext.Length || !decryptedBuffer.AsSpan().SequenceEqual(plaintext))
{
    Console.Error.WriteLine("[FAIL] AES-GCM decryption failed or data mismatch.");
    return 1;
}
Console.WriteLine("[PASS] AES-GCM AEAD encryption & decryption verified.");

// 4. Secret Protector & Binary Envelope Serialization Test
var protector = serviceProvider.GetRequiredService<ISecretProtector>();
var aadContext = AuthenticatedContext.FromBytes(aad);
var protectResult = await protector.ProtectAsync(plaintext, KeyPurpose.Encryption, aadContext);
if (protectResult.IsFailure)
{
    Console.Error.WriteLine($"[FAIL] Secret protection failed: {protectResult.Error.Description}");
    return 1;
}

var unprotectResult = await protector.UnprotectAsync(protectResult.Value, aadContext);
if (unprotectResult.IsFailure || !unprotectResult.Value.AsSpan().SequenceEqual(plaintext))
{
    Console.Error.WriteLine("[FAIL] Secret unprotection failed.");
    return 1;
}
Console.WriteLine("[PASS] Secret protection & binary envelope serialization verified.");

// 5. Password Hashing Test
var passwordHasher = serviceProvider.GetRequiredService<IPasswordHasher>();
var password = "CorrectHorseBatteryStaple!2026";
var hashedPassword = passwordHasher.HashPassword(password);
var verification = passwordHasher.VerifyPassword(password, hashedPassword);
if (verification != PasswordVerificationResult.Success)
{
    Console.Error.WriteLine("[FAIL] Password verification failed.");
    return 1;
}
Console.WriteLine("[PASS] PBKDF2 Password hashing & verification verified.");

// 6. Token Generation & Hashing Test
var tokenGenerator = serviceProvider.GetRequiredService<ITokenGenerator>();
var tokenHasher = serviceProvider.GetRequiredService<ITokenHasher>();
var token = tokenGenerator.GenerateUrlSafeToken(32);
var tokenHash = tokenHasher.HashToken(token);
if (!tokenHasher.VerifyToken(token, tokenHash))
{
    Console.Error.WriteLine("[FAIL] Token hashing verification failed.");
    return 1;
}
Console.WriteLine("[PASS] Token generation and hashing verified.");

Console.WriteLine("=== ALL AOT SMOKE TESTS PASSED SUCCESSFULLY ===");
return 0;
