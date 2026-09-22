# Level 01: Authenticated Encryption & Binary Security Envelopes

## 1. AEAD Encryption Engine (AES-256-GCM)

`EricksonLopez.Security` enforces authenticated encryption via `IAuthenticatedEncryptionEngine`. Every encryption operation produces a ciphertext accompanied by a cryptographic authentication tag:

```csharp
using System.Text;
using EricksonLopez.Security.Abstractions.Cryptography;
using EricksonLopez.Security.Cryptography;

// 1. Initialize engine
IAuthenticatedEncryptionEngine engine = new AesGcmEncryptionEngine();

// 2. Prepare 256-bit key, plaintext, and associated data (AAD)
byte[] key = new byte[32];
System.Security.Cryptography.RandomNumberGenerator.Fill(key);

byte[] plaintext = Encoding.UTF8.GetBytes("Confidential Patient Record");
byte[] associatedData = Encoding.UTF8.GetBytes("tenant-42:hospital-system");

// 3. Encrypt payload
var encryptResult = engine.Encrypt(plaintext, key, associatedData);

if (encryptResult.IsSuccess)
{
    EncryptedData encrypted = encryptResult.Value;
    Console.WriteLine($"Nonce: {Convert.ToHexString(encrypted.Nonce.Span)}");
    Console.WriteLine($"Tag: {Convert.ToHexString(encrypted.Tag.Span)}");
}
```

---

## 2. Decryption & Tag Verification

During decryption, any bit-flip in ciphertext or alteration of associated data triggers an instantaneous tag mismatch failure without throwing unhandled exceptions:

```csharp
var decryptedBuffer = new byte[plaintext.Length];

var decryptResult = engine.Decrypt(
    ciphertext: encrypted.Ciphertext.Span,
    key: key,
    nonce: encrypted.Nonce.Span,
    tag: encrypted.Tag.Span,
    associatedData: associatedData,
    plaintextDestination: decryptedBuffer,
    out int bytesWritten);

if (decryptResult.IsSuccess)
{
    string decryptedText = Encoding.UTF8.GetString(decryptedBuffer.AsSpan(0, bytesWritten));
    Console.WriteLine($"Decrypted: {decryptedText}");
}
else
{
    Console.Error.WriteLine($"Decryption rejected: {decryptResult.Error.Description}");
}
```

---

## 3. High-Level Secret Protector & Binary Envelope

For application-level persistence, `ISecretProtector` serializes data into a self-describing binary envelope containing the key ID, version, algorithm identifier, nonce, tag, and ciphertext:

```csharp
using EricksonLopez.Security.Abstractions.Cryptography;
using EricksonLopez.Security.Abstractions.Secrets;

ISecretProtector protector = serviceProvider.GetRequiredService<ISecretProtector>();

// Protect data with typed tenant context binding (AuthenticatedContext is a strongly-typed AAD struct)
var tenantCtx = AuthenticatedContext.ForTenant("tenant-42");
var protectedBytes = await protector.ProtectAsync(
    secret: plaintext,
    purpose: KeyPurpose.SecretProtection,
    expectedAssociatedData: tenantCtx);

if (protectedBytes.IsFailure)
{
    Console.Error.WriteLine($"Protection failed: {protectedBytes.Error.Description}");
    return;
}

// Unprotect data — same tenant context required for authentication tag verification
var unprotectResult = await protector.UnprotectAsync(
    protectedData: protectedBytes.Value,
    expectedAssociatedData: tenantCtx);

if (unprotectResult.IsSuccess)
{
    Console.WriteLine($"Decrypted: {System.Text.Encoding.UTF8.GetString(unprotectResult.Value)}");
}
else
{
    Console.Error.WriteLine($"Decryption failed: {unprotectResult.Error.Description}");
}
```
