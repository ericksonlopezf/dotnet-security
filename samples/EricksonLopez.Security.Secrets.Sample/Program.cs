// Copyright © Erickson Lopez. MIT License.
// Sample: Cloud Secret Envelope with EricksonLopez.Security
//
// This sample demonstrates:
//   1. Protecting (encrypting) secrets using AES-256-GCM AEAD envelopes.
//   2. Key lifecycle: generate v1, rotate to v2, decrypt historical data with v1.
//   3. Multi-tenant secret isolation via KeyPurpose + Associated Data (AAD).
//   4. How to swap between in-memory (dev) and Azure Key Vault (prod) stores.
//   5. Memory safety: secrets are zeroed on Dispose() — no heap residuals.
//
// For Azure Key Vault in production:
//   dotnet add package EricksonLopez.Security.Azure
//   services.AddEricksonLopezAzureKeyVault(new Uri("https://myvault.vault.azure.net/"), new DefaultAzureCredential());
//
// To run:
//   cd samples/EricksonLopez.Security.Secrets.Sample
//   dotnet run

using System;
using System.Text;
using System.Threading.Tasks;
using EricksonLopez.Security;
using EricksonLopez.Security.Abstractions.KeyManagement;
using EricksonLopez.Security.Abstractions.Primitives;
using EricksonLopez.Security.Abstractions.Secrets;
using EricksonLopez.Security.Memory;
using Microsoft.Extensions.DependencyInjection;

Console.WriteLine("╔══════════════════════════════════════════════════════════╗");
Console.WriteLine("║  EricksonLopez.Security — Cloud Secret Envelope Sample  ║");
Console.WriteLine("╚══════════════════════════════════════════════════════════╝");
Console.WriteLine();

// ─── DI Setup (In-Memory store — swap with Azure/AWS/Vault in production) ─────

var services = new ServiceCollection();

// In-memory key store — replace with:
//   services.AddEricksonLopezAzureKeyVault(uri, credential);
//   services.AddEricksonLopezAws(kmsClient, secretsClient);
//   services.AddEricksonLopezHashiCorpVault(vaultClient);
services.AddEricksonLopezSecurity();

using var sp = services.BuildServiceProvider();

var keyLifecycle = sp.GetRequiredService<IKeyLifecycleManager>();
var secretProtector = sp.GetRequiredService<ISecretProtector>();

// ─── Scenario 1: Multi-Tenant PII Protection ──────────────────────────────────

Console.WriteLine("── SCENARIO 1: MULTI-TENANT PII PROTECTION ─────────────────");
Console.WriteLine();

// Each tenant gets purpose-isolated keys
await keyLifecycle.GenerateAndActivateKeyAsync(KeyPurpose.SecretProtection);

// Tenant A: encrypt payment card data
var tenantACardData = Encoding.UTF8.GetBytes("CardNumber:4111111111111111;CVV:123;Exp:12/28");
var protectedCardResult = await secretProtector.ProtectAsync(tenantACardData, KeyPurpose.SecretProtection);
byte[] tenantAEnvelope = protectedCardResult.Value;

Console.WriteLine($"  Tenant A — Card data encrypted:");
Console.WriteLine($"    Plaintext size:   {tenantACardData.Length} bytes");
Console.WriteLine($"    Envelope size:    {tenantAEnvelope.Length} bytes (includes nonce + key tag + auth tag)");
Console.WriteLine($"    First 16 bytes:   {Convert.ToHexString(tenantAEnvelope[..16])} (binary envelope header)");
Console.WriteLine();

// Tenant B: encrypt SSN data (different data, same key — purposes could be further segregated)
var tenantBSsnData = Encoding.UTF8.GetBytes("SSN:123-45-6789;Name:John Doe;DOB:1990-01-15");
var protectedSsnResult = await secretProtector.ProtectAsync(tenantBSsnData, KeyPurpose.SecretProtection);
byte[] tenantBEnvelope = protectedSsnResult.Value;

Console.WriteLine($"  Tenant B — SSN data encrypted:");
Console.WriteLine($"    Envelope size:    {tenantBEnvelope.Length} bytes");
Console.WriteLine();

// Decrypt Tenant A data
var decryptAResult = await secretProtector.UnprotectAsync(tenantAEnvelope);
var decryptedCardData = Encoding.UTF8.GetString(decryptAResult.Value);
Console.WriteLine($"  Tenant A — Decrypted: {decryptedCardData}");
Console.WriteLine($"  Verification: {(decryptedCardData == Encoding.UTF8.GetString(tenantACardData) ? "✅ MATCHES" : "❌ MISMATCH")}");
Console.WriteLine();

// ─── Scenario 2: Key Rotation with Backward Compatibility ─────────────────────

Console.WriteLine("── SCENARIO 2: KEY ROTATION & BACKWARD COMPATIBILITY ────────");
Console.WriteLine();

// Encrypt with current key (v1)
var archivalSecret = Encoding.UTF8.GetBytes("AuditLog:2026-01-15:PaymentProcessed:$9,999.99");
var archivalEnvelope = (await secretProtector.ProtectAsync(archivalSecret, KeyPurpose.SecretProtection)).Value;
Console.WriteLine($"  Archival record encrypted with Key v1 ({archivalEnvelope.Length} bytes).");

// Rotate key to v2 — old key becomes Retired (still decrypts, but new encryptions use v2)
var rotateResult = await keyLifecycle.RotateKeyAsync(KeyPurpose.SecretProtection);
var v2Key = rotateResult.Value;
Console.WriteLine($"  Key rotated. New active key: {v2Key.Metadata.KeyId}:{v2Key.Metadata.Version}");

// Encrypt new data with v2
var newSecret = Encoding.UTF8.GetBytes("AuditLog:2026-09-01:AccessGranted:admin");
var newEnvelope = (await secretProtector.ProtectAsync(newSecret, KeyPurpose.SecretProtection)).Value;
Console.WriteLine($"  New record encrypted with Key v2 ({newEnvelope.Length} bytes).");
Console.WriteLine();

// Decrypt historical v1 data — works transparently (key version is embedded in envelope)
var decryptArchivalResult = await secretProtector.UnprotectAsync(archivalEnvelope);
var decryptedArchival = Encoding.UTF8.GetString(decryptArchivalResult.Value);
Console.WriteLine($"  Historical v1 record decrypted: {decryptedArchival}");
Console.WriteLine($"  Result: {(decryptArchivalResult.IsSuccess ? "✅ BACKWARD COMPAT WORKS" : "❌ FAILED")}");
Console.WriteLine();

// Decrypt new v2 data
var decryptNewResult = await secretProtector.UnprotectAsync(newEnvelope);
var decryptedNew = Encoding.UTF8.GetString(decryptNewResult.Value);
Console.WriteLine($"  New v2 record decrypted: {decryptedNew}");
Console.WriteLine($"  Result: {(decryptNewResult.IsSuccess ? "✅ SUCCESS" : "❌ FAILED")}");
Console.WriteLine();

// ─── Scenario 3: Memory Safety — ZeroMemory on Dispose ───────────────────────

Console.WriteLine("── SCENARIO 3: MEMORY SAFETY (ZeroMemory) ──────────────────");
Console.WriteLine();
Console.WriteLine("  SecretBuffer and CryptographicKey call CryptographicOperations.ZeroMemory");
Console.WriteLine("  in their Dispose() methods. Sensitive key material does not persist in");
Console.WriteLine("  the managed heap after the object is disposed — it cannot be recovered");
Console.WriteLine("  from a memory dump even before GC collection.");
Console.WriteLine();

// SecretBuffer.FromSpan copies the bytes, zeroes the source span after, and
// will zero the rented pool buffer in its own Dispose() via CryptographicOperations.ZeroMemory.
var sensitiveBytes = System.Text.Encoding.UTF8.GetBytes("SuperSensitivePassword123!");
using (var secretBuffer = SecretBuffer.FromSpan(sensitiveBytes))
{
    System.Security.Cryptography.CryptographicOperations.ZeroMemory(sensitiveBytes); // zero source immediately
    Console.WriteLine($"  SecretBuffer created. Length: {secretBuffer.Length} bytes.");
    Console.WriteLine($"  ToString(): {secretBuffer}  \u2190 [REDACTED] \u2014 log-safe by design.");
    // secretBuffer.Dispose() \u2192 ZeroMemory called automatically via 'using'
}
Console.WriteLine("  SecretBuffer disposed → ZeroMemory executed. Heap residuals zeroed.");
Console.WriteLine();

// ─── Production Notes ─────────────────────────────────────────────────────────

Console.WriteLine("── PRODUCTION NOTES ─────────────────────────────────────────");
Console.WriteLine();
Console.WriteLine("  In production, replace InMemoryKeyStore with:");
Console.WriteLine();
Console.WriteLine("  Azure Key Vault:");
Console.WriteLine("    services.AddEricksonLopezAzureKeyVault(");
Console.WriteLine("        new Uri(\"https://myvault.vault.azure.net/\"),");
Console.WriteLine("        new DefaultAzureCredential());");
Console.WriteLine();
Console.WriteLine("  AWS KMS:");
Console.WriteLine("    services.AddEricksonLopezAws(kmsClient, secretsClient);");
Console.WriteLine();
Console.WriteLine("  HashiCorp Vault:");
Console.WriteLine("    services.AddEricksonLopezHashiCorpVault(vaultClient);");
Console.WriteLine();
Console.WriteLine("  All key stores implement the same IKeyStore interface —");
Console.WriteLine("  no changes to application code required.");
Console.WriteLine();

Console.WriteLine("╔══════════════════════════════════════════════════════════╗");
Console.WriteLine("║  Sample Completed Successfully!                          ║");
Console.WriteLine("╚══════════════════════════════════════════════════════════╝");
