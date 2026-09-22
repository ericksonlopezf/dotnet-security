# Migration Guide: Microsoft.AspNetCore.DataProtection → EricksonLopez.Security

> **Audience**: .NET backend developers and architects who currently use
> `Microsoft.AspNetCore.DataProtection` and are evaluating or adopting
> `EricksonLopez.Security` Core.
>
> **Goal**: Migrate from DataProtection to EL.Security with zero downtime, in a weekend.

---

## Why Migrate?

| Concern | Microsoft.AspNetCore.DataProtection | EricksonLopez.Security |
|---|---|---|
| **Encryption mode** | AES-256-CBC + HMAC-SHA256 (composition of two primitives; historically vulnerable to padding oracle if misimplemented) | AES-256-GCM (NIST SP 800-38D) — single-pass authenticated encryption. Padding oracles are structurally impossible. |
| **Native AOT** | ❌ Uses reflection (`DataProtectionExtensions`, XML serialization of key ring) | ✅ Zero reflection in core. `IsAotCompatible = true`. |
| **Key revocation** | ❌ Keys rotate automatically but cannot be immediately revoked | ✅ `KeyLifecycleManager` supports `Active → Retired → Revoked → Destroyed` state machine with immediate revocation. |
| **Memory safety** | ❌ Protected data stays in managed heap until GC. No `ZeroMemory` on dispose. | ✅ `SecretBuffer.Dispose()` calls `CryptographicOperations.ZeroMemory` immediately. |
| **Error handling** | ❌ Throws `CryptographicException` on failure. Exceptions = control flow. | ✅ Returns `Result<T>`. No exceptions for expected security failures. |
| **Post-Quantum** | ❌ Not planned | ✅ `HkdfAesGcmEncryptionEngine` (HKDF-SHA512 + AES-256-GCM in v1.x; ML-KEM-768 on v2.x roadmap per [ADR-025](./adr/adr-025-hkdf-enhanced-encryption-engine-pqc-roadmap.md)). |
| **Log safety** | ❌ Byte arrays printed as-is in debug mode | ✅ `Redacted<T>` wraps sensitive values. `ToString()` returns `[REDACTED]`. |

---

## API Equivalence Table

| DataProtection | EricksonLopez.Security | Notes |
|---|---|---|
| `IDataProtector.Protect(byte[])` | `ISecretProtector.ProtectAsync(byte[], KeyPurpose)` | EL.Security returns `Task<Result<byte[]>>` |
| `IDataProtector.Unprotect(byte[])` | `ISecretProtector.UnprotectAsync(byte[])` | Auto-resolves key version from envelope header |
| `IDataProtectionProvider.CreateProtector(purpose)` | `IKeyRing.GetActiveKeyAsync(KeyPurpose)` | Purpose segregation via `KeyPurpose` enum |
| `services.AddDataProtection()` | `services.AddEricksonLopezSecurity()` | — |
| `KeyManagementOptions.NewKeyLifetime` | `KeyRotationPolicy.RotationInterval` | — |
| `PersistKeysToFileSystem(dir)` | Custom `IKeyStore` → `FileSystemKeyStore` | Or use `EricksonLopez.Security.Azure` / `Aws` |
| `ProtectKeysWithAzureKeyVault(...)` | `services.AddAzureKeyVaultSecurity(...)` | Configures Azure Key Vault key and secret stores |

---

## Step-by-Step Migration

### Step 1 — Install Packages

```bash
# Remove DataProtection (only if you are ready for full cutover)
# Keep it installed during parallel run period
dotnet add package EricksonLopez.Security
dotnet add package EricksonLopez.Security.AspNetCore
```

### Step 2 — Configure DI

**Before (DataProtection):**

```csharp
builder.Services.AddDataProtection()
    .PersistKeysToFileSystem(new DirectoryInfo("/keys"))
    .SetApplicationName("MyApp");
```

**After (EricksonLopez.Security):**

```csharp
// Minimal setup (in-memory key store — development/test only)
builder.Services.AddEricksonLopezSecurity();

// Production: use Azure Key Vault for key storage
// dotnet add package EricksonLopez.Security.Azure
builder.Services.AddEricksonLopezSecurity();
builder.Services.AddAzureKeyVaultSecurity(options =>
{
    options.VaultUri = new Uri("https://myvault.vault.azure.net/");
});
```

### Step 3 — Replace Protect Calls

**Before (DataProtection):**

```csharp
public class CustomerService
{
    private readonly IDataProtector _protector;

    public CustomerService(IDataProtectionProvider provider)
    {
        _protector = provider.CreateProtector("CustomerPii");
    }

    public byte[] EncryptPii(byte[] pii) => _protector.Protect(pii);
    
    public byte[] DecryptPii(byte[] encrypted)
    {
        try { return _protector.Unprotect(encrypted); }
        catch (CryptographicException) { return Array.Empty<byte>(); }
    }
}
```

**After (EricksonLopez.Security):**

```csharp
public class CustomerService
{
    private readonly ISecretProtector _protector;

    public CustomerService(ISecretProtector protector)
    {
        _protector = protector;
    }

    public async Task<byte[]> EncryptPiiAsync(byte[] pii, CancellationToken ct = default)
    {
        var result = await _protector.ProtectAsync(secret: pii, purpose: KeyPurpose.SecretProtection, cancellationToken: ct);
        return result.IsSuccess ? result.Value : throw new InvalidOperationException(result.Error.Description);
    }

    public async Task<byte[]?> DecryptPiiAsync(byte[] encrypted, CancellationToken ct = default)
    {
        var result = await _protector.UnprotectAsync(protectedData: encrypted, cancellationToken: ct);
        return result.IsSuccess ? result.Value : null; // No exception — failure is a Result
    }
}
```

### Step 4 — Key Rotation

**Before (DataProtection):** Key rotation is automatic and opaque. You cannot control it beyond `NewKeyLifetime`.

**After (EricksonLopez.Security):** Explicit and observable.

```csharp
// Inject IKeyLifecycleManager
var rotateResult = await keyLifecycleManager.RotateKeyAsync(KeyPurpose.SecretProtection, cancellationToken: ct);
if (rotateResult.IsSuccess)
{
    logger.LogInformation("Key rotated to {KeyId}:{Version}",
        rotateResult.Value.Metadata.KeyId,
        rotateResult.Value.Metadata.Version);
}

// Data encrypted with the old key decrypts transparently — no re-encryption needed
```

### Step 5 — Migrate ASP.NET Core Cookie Protection

DataProtection is used internally by ASP.NET Core for cookie and session protection.
If you're replacing DataProtection only for your own data (not for ASP.NET Core internals),
you can keep DataProtection registered for the framework and use EL.Security for your domain data.

If you want to remove DataProtection entirely:
1. Use EL.Security for all your own data protection.
2. Implement custom `ITicketStore` (ASP.NET Core Auth) backed by EL.Security envelopes for session cookie protection.
3. This is an advanced scenario — verify your authentication middleware behavior thoroughly.

---

## Parallel Run Strategy (Zero Downtime Migration)

For production systems with live encrypted data:

### Phase 1 — Dual-Write (Weeks 1–2)

```csharp
// Keep DataProtection + add EricksonLopez.Security
// Write new data with EL.Security, still read old data from DataProtection

public async Task<byte[]?> DecryptAsync(byte[] data, CancellationToken ct)
{
    // Try EL.Security first (new format — has version header)
    if (IsElSecurityEnvelope(data))
    {
        var result = await _elProtector.UnprotectAsync(data, ct);
        return result.IsSuccess ? result.Value : null;
    }
    
    // Fall back to DataProtection (legacy format)
    try { return _dataProtector.Unprotect(data); }
    catch (CryptographicException) { return null; }
}

private static bool IsElSecurityEnvelope(byte[] data) =>
    data.Length >= 44 && data[0] == 0x01; // SecurityEnvelope FormatVersion (v1)
```

### Phase 2 — Re-Encrypt at Read (Weeks 3–8)

```csharp
// Transparently re-encrypt legacy data on read
if (!IsElSecurityEnvelope(data))
{
    var plain = _dataProtector.Unprotect(data);
    var newEnvelope = (await _elProtector.ProtectAsync(secret: plain, purpose: KeyPurpose.SecretProtection, cancellationToken: ct)).Value;
    await _repo.UpdateEncryptedDataAsync(recordId, newEnvelope, ct);
    return plain;
}
```

### Phase 3 — Remove DataProtection Dependency (After re-encryption completes)

Once all records have been re-encrypted (verify via database scan), remove DataProtection.

---

## Checklist

- [ ] Install `EricksonLopez.Security` and `EricksonLopez.Security.Azure` (or `Aws`) packages.
- [ ] Replace `services.AddDataProtection()` with `services.AddEricksonLopezSecurity()`.
- [ ] Update DI constructor injection: `IDataProtectionProvider` → `ISecretProtector`.
- [ ] Replace `Protect(byte[])` calls with `ProtectAsync(byte[], KeyPurpose)`.
- [ ] Replace `Unprotect(byte[])` calls with `UnprotectAsync(byte[])`. Handle `Result<T>` instead of `CryptographicException`.
- [ ] Replace key rotation configuration with `IKeyLifecycleManager` and `KeyRotationPolicy`.
- [ ] Implement parallel run strategy for existing encrypted data.
- [ ] Verify all tests pass (use `EricksonLopez.Security.Testing` test doubles).
- [ ] Monitor decryption failures during migration window.
- [ ] Remove DataProtection package after full re-encryption.

---

## FAQ

**Q: Do I need to re-encrypt all existing data immediately?**  
A: No. Use the parallel run strategy above. New writes use EL.Security AEAD envelopes. Old reads fall back to DataProtection. Re-encrypt at read over weeks/months.

**Q: Does EricksonLopez.Security support ASP.NET Core's antiforgery token protection?**  
A: Not yet. ASP.NET Core antiforgery uses DataProtection internally. Keep DataProtection for this use case while using EL.Security for your domain data.

**Q: What happens if decryption fails in EL.Security?**  
A: `UnprotectAsync` returns `Result<byte[], SecurityError>` with a `DecryptionFailed` error. No exception is thrown. This makes failure an explicit branch in your code.

**Q: Can I use EricksonLopez.Security in a Native AOT published app?**  
A: Yes. This is one of the primary design goals. DataProtection cannot be used in AOT-published apps without errors. EL.Security is `IsAotCompatible = true` throughout.

---

## Related Resources

- [Migration Guide: Identity PasswordHasher → EL.Security Passwords](./migration-from-identity-passwordhasher.md)
- [Quickstart: 5-Minute Getting Started](./quickstart.md)
- [ADR-002: AEAD Encryption Default](./adr/adr-002-authenticated-encryption-aead-default.md)
- [ADR-007: Memory Scrubbing and ZeroMemory](./adr/adr-007-memory-scrubbing-and-zero-allocation-primitives.md)
