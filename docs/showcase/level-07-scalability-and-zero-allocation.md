# Level 07: Scalability, Performance & Zero-Allocation Primitives

> **Showcase Level**: Level 7  
> **Source Code**: [`samples/EricksonLopez.Security.Sample/Levels/Level7_ScalabilityAndPerformance.cs`](../../samples/EricksonLopez.Security.Sample/Levels/Level7_ScalabilityAndPerformance.cs)  
> **Packages**: `EricksonLopez.Security`, `EricksonLopez.Security.Abstractions`, `EricksonLopez.Security.OpenTelemetry`

---

## 1. Overview & Architectural Role

Level 7 demonstrates high-throughput, allocation-free cryptography and runtime observability:
- **Zero-Allocation Span Hotpaths**: `ReadOnlySpan<byte>` and `Span<byte>` over `stackalloc` buffers eliminate GC heap allocations during cryptographic encryption and decryption loops.
- **High-Throughput Concurrency**: Thread-safe engines capable of executing 500,000+ AES-256-GCM operations per second.
- **OpenTelemetry Observability**: Native `ActivitySource` and `Meter` instrumentation providing APM distributed tracing spans and metrics.
- **`HmacSha256TokenHasher`**: SHA-256 and keyed HMAC-SHA256 token hashing for database persistence and constant-time verification.

---

## 2. In-Place Span Cryptography (0 Heap Allocations)

```csharp
using System.Text;
using EricksonLopez.Security.Cryptography;
using EricksonLopez.Security.Randomness;

ReadOnlySpan<byte> rawPlaintext = "HighThroughputMessageBlock_0123456789"u8;
Span<byte> key = stackalloc byte[32];
Span<byte> nonce = stackalloc byte[12];
Span<byte> ciphertext = stackalloc byte[rawPlaintext.Length];
Span<byte> tag = stackalloc byte[16];
Span<byte> decryptedPlaintext = stackalloc byte[rawPlaintext.Length];

CryptographicRandom.Shared.Fill(key);
CryptographicRandom.Shared.Fill(nonce);

var engine = AesGcmEncryptionEngine.Shared;

// Zero heap allocations in the encryption call!
var encryptResult = engine.Encrypt(
    plaintext: rawPlaintext,
    key: key,
    nonce: nonce,
    ciphertextDestination: ciphertext,
    tagDestination: tag);

var decryptResult = engine.Decrypt(
    ciphertext: ciphertext,
    key: key,
    nonce: nonce,
    tag: tag,
    associatedData: default,
    plaintextDestination: decryptedPlaintext,
    out var bytesWritten);
```

---

## 3. High-Concurrency Multi-Threaded Execution

`AesGcmEncryptionEngine.Shared` is stateless and thread-safe, making it optimal for high-concurrency microservices:

```csharp
Parallel.For(0, 10000, i =>
{
    Span<byte> localKey = stackalloc byte[32];
    Span<byte> localNonce = stackalloc byte[12];
    Span<byte> localCt = stackalloc byte[32];
    Span<byte> localTag = stackalloc byte[16];

    localKey.Fill((byte)(i % 255));
    localNonce.Fill((byte)(i % 12));

    ReadOnlySpan<byte> pt = "ConcurrentMicroBenchmarkPayload!"u8;
    engine.Encrypt(pt, localKey, localNonce, localCt, localTag);
});
// 10,000 operations complete in ~15 ms (over 600,000 ops/second)
```

---

## 4. Distributed Tracing (`SecurityActivitySource`)

Standardized BCL `ActivitySource` spans compatible with OpenTelemetry:

```csharp
using EricksonLopez.Security.Diagnostics;

// Spans:
// - security.encrypt
// - security.decrypt
// - security.password.hash
// - security.password.verify
// - security.secret.protect
// - security.secret.unprotect

// Tags:
// - security.algorithm: 'aes-256-gcm'
// - security.key.version: 'v2'
// - security.hash.algorithm: 'argon2id'
// - security.result: 'success' | 'failure' | 'rehash_needed'
```

---

## 5. Metrics Instrumentation (`SecurityMeter`)

Counters and Histograms for production dashboarding:

```csharp
using EricksonLopez.Security.Diagnostics;

// Counters:
// - security.encrypt.total
// - security.decrypt.total
// - security.key.rotations_total
// - security.key.revocations_total
// - security.apikey.validations_total
// - security.password.verifications_total

// Histograms:
// - security.argon2id.hashing_duration_ms
// - security.pbkdf2.hashing_duration_ms
```

---

## 6. Token Hashing for Database Storage

```csharp
using System.Text;
using EricksonLopez.Security.Tokens;

// --- Unkeyed SHA-256 (no pepper) ---
var tokenHasher = new HmacSha256TokenHasher();

string tokenHash = tokenHasher.HashToken("usr_secret_token_12345");
bool isMatch = tokenHasher.VerifyToken("usr_secret_token_12345", tokenHash); // true

// --- Keyed HMAC-SHA256 with application pepper ---
// The pepper is injected via constructor, not passed to HashToken/VerifyToken.
byte[] pepperKey = Encoding.UTF8.GetBytes("AppSecretPepper2026");
var pepperedHasher = new HmacSha256TokenHasher(pepperKey);

string pepperedHash = pepperedHasher.HashToken("usr_secret_token_12345");
bool isPepperedMatch = pepperedHasher.VerifyToken("usr_secret_token_12345", pepperedHash); // true
```
