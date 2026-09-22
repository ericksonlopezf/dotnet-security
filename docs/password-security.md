# Password Security & Rehash Migration

## 1. Password Hashing Specifications

`EricksonLopez.Security` provides modern password hashing based on official NIST SP 800-63B and OWASP guidelines:

### Supported Algorithms

| Algorithm | Default Parameters | Format Prefix | Native AOT | Substrate Details |
|---|---|---|---|---|
| **PBKDF2-HMAC-SHA512** (Default) | 210,000 iterations, 128-bit salt, 256-bit key | `$pbkdf2-sha512$` | 100% Native In-Box | Native .NET BCL `Rfc2898DeriveBytes.Pbkdf2` |
| **Argon2id** | 64MB memory (`m=65536`), 3 iterations (`t=3`), 4 parallelism (`p=4`) | `$argon2id$` | 100% In-Box / Managed | Modular crypt format. In v1.x, uses PBKDF2-HMAC-SHA512 substrate (`t × 70,000` = 210k iterations); `m` and `p` reserve the format slot for v2.x native RFC 9106 per [ADR-024](./adr/adr-024-argon2id-hasher-implementation-strategy.md) |

> [!NOTE]
> **Argon2id Cryptographic Substrate (ADR-024)**: Because .NET's BCL does not include an in-box RFC 9106 Argon2id implementation without native C dependencies (`libargon2`), `Argon2idPasswordHasher` formats hashes with `$argon2id$v=19$m=65536,t=3,p=4$...` while executing PBKDF2-HMAC-SHA512 under the hood. This maintains full Native AOT compatibility and zero external binary dependencies while preparing the database for transparent upgrade in v2.x.

---

## 2. NIST SP 800-63B Password Policy

`PasswordPolicy` provides immutable, zero-allocation span-based validation against modern credential rules:

### Built-In Policy Profiles

1. **`PasswordPolicy.Default` (Enterprise High-Security)**:
   - Minimum length: 12 characters (maximum: 128 characters).
   - Requires at least one numeric digit (`0`-`9`).
   - Requires at least one uppercase ASCII letter (`A`-`Z`).
   - Requires at least one lowercase ASCII letter (`a`-`z`).
   - Requires at least one non-alphanumeric special character.
   - Limits consecutive identical repeated characters to 3.

2. **`PasswordPolicy.NistAligned` (NIST SP 800-63B Passphrase Focus)**:
   - Minimum length: 15 characters (maximum: 128 characters).
   - No mandatory character composition rules (length-focused per NIST guidelines).
   - Limits consecutive identical repeated characters to 4.

```csharp
// Enterprise default policy
var defaultPolicy = PasswordPolicy.Default;
var defaultResult = defaultPolicy.Validate("CorrectHorseBatteryStaple!2026");

// NIST-aligned passphrase policy
var nistPolicy = PasswordPolicy.NistAligned;
var nistResult = nistPolicy.Validate("correct horse battery staple 2026");
```

---

## 3. Transparent Password Rehash Migration

When user credentials evolve, `CompositePasswordHasher` transparently routes verification to the matching hasher based on format prefix, and signals `PasswordVerificationResult.SuccessRehashNeeded` when the stored hash uses an older algorithm or lower iteration count:

```csharp
var verifyResult = passwordHasher.VerifyPassword(passwordInput.AsSpan(), storedHash);

if (verifyResult == PasswordVerificationResult.Success)
{
    // Authentication successful with primary hasher parameters
}
else if (verifyResult == PasswordVerificationResult.SuccessRehashNeeded)
{
    // Authentication successful, but hash needs updating to the primary hasher!
    string newHash = passwordHasher.HashPassword(passwordInput.AsSpan());
    await userRepository.UpdatePasswordHashAsync(userId, newHash);
}
else
{
    // Authentication failed (wrong password)
}
```

### Configuring Argon2id as Primary Hasher

By default, `AddEricksonLopezSecurity()` configures `CompositePasswordHasher` with `Pbkdf2PasswordHasher` as primary and `Argon2idPasswordHasher` as an additional hasher. To designate `Argon2idPasswordHasher` as primary for new hashes:

```csharp
services.AddSingleton<IPasswordHasher>(sp =>
    new CompositePasswordHasher(
        primaryHasher: sp.GetRequiredService<Argon2idPasswordHasher>(),
        additionalHashers: [sp.GetRequiredService<Pbkdf2PasswordHasher>()]));
```

---

## 4. Legacy Password Formats & ASP.NET Identity Integration

### Legacy PBKDF2 Migration (`LegacyPbkdf2PasswordHasher`)

Per [**ADR-030**](./adr/adr-030-explicit-legacy-pbkdf2-password-hasher-format-segregation.md), `LegacyPbkdf2PasswordHasher` provides backward compatibility for legacy `$argon2id$` and `$legacy-pbkdf2$` hashes, resolving SEC-005. It verifies older hashes and signals `SuccessRehashNeeded` so the application can upgrade user hashes to the current primary algorithm on next login.

### ASP.NET Core Identity Drop-In Bridge

Applications using ASP.NET Core Identity can bridge to `EricksonLopez.Security` without custom adapters via `IdentityPasswordHasherBridge<TUser>` (in `EricksonLopez.Security.AspNetCore`), backed by `ISimplePasswordHasher`:

```csharp
// Registers IdentityPasswordHasherBridge<TUser> as IPasswordHasher<TUser>
builder.Services.AddEricksonLopezIdentityPasswordHasher<ApplicationUser>();
```

For complete step-by-step guidance, see the [**ASP.NET Identity Migration Guide**](./migration-from-identity-passwordhasher.md).
