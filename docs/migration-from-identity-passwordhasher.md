# Migration Guide: ASP.NET Identity PasswordHasher → EricksonLopez.Security Passwords

> **Audience**: .NET developers using `Microsoft.AspNetCore.Identity` (or `Microsoft.AspNetCore.Identity.Core`)
> who want to upgrade to a stronger password hashing strategy without invalidating existing user passwords.
>
> **Key guarantee**: Existing password hashes continue to work during and after migration.
> No forced password resets.

---

## Why Migrate?

| Concern | ASP.NET Identity `PasswordHasher<T>` | EricksonLopez.Security |
|---|---|---|
| **Algorithm** (v3 default) | PBKDF2-HMAC-SHA256 with 100,000 iterations | PBKDF2-HMAC-SHA512 with 210,000 iterations + Argon2id ($argon2id$ MCF format, forward-compatible per [ADR-024](./adr/adr-024-argon2id-hasher-implementation-strategy.md)) |
| **OWASP 2024 compliance** | ⚠️ SHA256 at 100k is below current recommendation (SHA512 at 210k or Argon2id) | ✅ Both algorithms meet or exceed OWASP 2024 minimum requirements |
| **Algorithm agility** | ❌ Changing algorithm requires code changes + forced password reset | ✅ `CompositePasswordHasher` detects algorithm from MCF hash prefix and auto-rehashes transparently |
| **Memory-hard hashing** | ❌ PBKDF2 is not memory-hard — susceptible to GPU/ASIC attacks | ⚠️ RFC 9106 MCF format ready; v1.x uses PBKDF2-SHA512 substrate (210,000 rounds); full native C-binding memory hardness scheduled for v2.0 per [ADR-024](./adr/adr-024-argon2id-hasher-implementation-strategy.md) |
| **Native AOT** | ❌ `PasswordHasher<T>` uses generic type constraints incompatible with AOT trimming in some scenarios | ✅ Zero reflection in core |
| **Hash format** | Proprietary binary format (4-byte header + salt + subkey) | Modular Crypt Format (MCF) — human-readable, interoperable, tool-compatible |
| **Error handling** | Returns `PasswordVerificationResult` enum (same as EL.Security) | Returns `PasswordVerificationResult` (compatible enum) |

---

## Understanding the Migration Strategy: Transparent Rehash

The key to zero-downtime migration is **transparent rehash on successful login**:

1. User logs in with their plaintext password.
2. Verify against the stored (old) hash — succeeds.
3. `PasswordVerificationResult.SuccessRehashNeeded` is returned.
4. Your login handler re-hashes with the new algorithm and stores the updated hash.
5. On next login, the new algorithm is used.

This process is fully automatic with `CompositePasswordHasher` and `LegacyPbkdf2PasswordHasher` (see [ADR-030](./adr/adr-030-explicit-legacy-pbkdf2-password-hasher-format-segregation.md)). No users experience any change.

---

## API Equivalence Table

| Identity `PasswordHasher<TUser>` | EricksonLopez.Security | Notes |
|---|---|---|
| `HashPassword(user, password)` | `HashPassword(password)` | EL.Security doesn't require a user object |
| `VerifyHashedPassword(user, hash, password)` | `VerifyPassword(password, hash)` | — |
| `PasswordVerificationResult.Success` | `PasswordVerificationResult.Success` | Same enum value |
| `PasswordVerificationResult.SuccessRehashNeeded` | `PasswordVerificationResult.SuccessRehashNeeded` | Triggered when legacy algorithm detected |
| `PasswordVerificationResult.Failed` | `PasswordVerificationResult.Failed` | Same enum value |
| `services.AddIdentity<>()` (includes hasher) | `services.AddEricksonLopezSecurity()` | — |

---

## Step-by-Step Migration

### Step 1 — Install Packages

```bash
dotnet add package EricksonLopez.Security
dotnet add package EricksonLopez.Security.AspNetCore
```

### Step 2 — Configure DI with Built-in Identity Bridge

**Before (Identity):**

```csharp
builder.Services.AddIdentityCore<ApplicationUser>(options =>
{
    options.Password.RequiredLength = 8;
    // etc.
});
```

**After (EricksonLopez.Security — using the built-in `IdentityPasswordHasherBridge<TUser>`):**

```csharp
// Keep ASP.NET Core Identity for user management (claims, roles, etc.)
builder.Services.AddIdentityCore<ApplicationUser>();

// Register EricksonLopez.Security core services
builder.Services.AddEricksonLopezSecurity();

// Register the built-in ASP.NET Core Identity bridge provided by EricksonLopez.Security.AspNetCore:
builder.Services.AddEricksonLopezIdentityPasswordHasher<ApplicationUser>();
```

> [!TIP]
> **No Custom Adapter Required**: `EricksonLopez.Security.AspNetCore` includes `IdentityPasswordHasherBridge<TUser>` out of the box in the `EricksonLopez.Security.AspNetCore.Identity` namespace. It automatically bridges ASP.NET Core Identity's `Microsoft.AspNetCore.Identity.IPasswordHasher<TUser>` to the underlying `CompositePasswordHasher`.

### Step 3 — Handle Rehash in Login Flow

**Before (Identity — no auto-rehash handling):**

```csharp
var result = _passwordHasher.VerifyHashedPassword(user, user.PasswordHash, password);
if (result == PasswordVerificationResult.Failed)
    return Unauthorized();
```

**After (EricksonLopez.Security — with transparent rehash):**

```csharp
var result = _passwordHasher.VerifyHashedPassword(user, user.PasswordHash!, password);

if (result == PasswordVerificationResult.Failed)
    return Unauthorized();

// Transparent rehash: if old algorithm detected, upgrade silently
if (result == PasswordVerificationResult.SuccessRehashNeeded)
{
    user.PasswordHash = _passwordHasher.HashPassword(user, password);
    await _userManager.UpdateAsync(user);
    logger.LogInformation("Password hash upgraded for user {UserId}", user.Id);
}
// result == PasswordVerificationResult.Success — proceed normally
```

### Step 4 — Configure Password Policy

**Before (Identity options):**

```csharp
builder.Services.AddIdentityCore<ApplicationUser>(options =>
{
    options.Password.RequiredLength = 12;
    options.Password.RequireDigit = true;
    options.Password.RequireUppercase = true;
    options.Password.RequireLowercase = true;
    options.Password.RequireNonAlphanumeric = true;
});
```

**After (EricksonLopez.Security `PasswordPolicy`):**

```csharp
builder.Services.AddEricksonLopezSecurity(options =>
{
    options.PasswordPolicy = new PasswordPolicy(
        minimumLength: 12,
        requireDigit: true,
        requireUppercase: true,
        requireLowercase: true,
        requireNonAlphanumeric: true);
});

// Validate before hashing
var policy = serviceProvider.GetRequiredService<PasswordPolicy>();
var validationResult = policy.Validate(newPassword);
if (validationResult.IsFailure)
    return BadRequest(validationResult.Error.Message);
```

### Step 5 — (Optional) Enable Argon2id for New Hashes

By default, `CompositePasswordHasher` uses PBKDF2-SHA512. To enable Argon2id for new hashes (recommended for highest security):

```csharp
builder.Services.AddEricksonLopezSecurity(options =>
{
    options.DefaultPasswordHashingAlgorithm = PasswordHashingAlgorithm.Argon2id;
    options.Argon2Options = new Argon2Options
    {
        MemorySizeKb = 65536,   // 64 MB
        Iterations = 3,
        DegreeOfParallelism = 1
    };
});
```

Existing PBKDF2 hashes will continue to verify correctly and be upgraded to Argon2id on next login.

---

## Migration Rollout Plan

### Day 1: Install and Bridge
- Install `EricksonLopez.Security` and `EricksonLopez.Security.AspNetCore`.
- Register `builder.Services.AddEricksonLopezIdentityPasswordHasher<ApplicationUser>()` in DI.
- Deploy to staging.

### Day 2–7: Staging Validation
- Log `PasswordVerificationResult` values in staging.
- Verify `SuccessRehashNeeded` is being triggered for existing users.
- Verify `Success` is returned after rehash (second login).
- Verify login works for all user types (admin, regular, OAuth-linked).

### Day 8: Production Deploy
- Deploy with Argon2id enabled as the default.
- Monitor login success rate — should be unchanged.
- Monitor rehash events — should be > 0 (showing migration is working).

### Month 1–3: Let Rehash Complete Naturally
- Active users will rehash on first login after deploy.
- Inactive users retain old PBKDF2 hashes until they log in.
- No forced password resets needed.

### Optional: Batch Rehash (Advanced)
If you want to proactively rehash dormant accounts:

```csharp
// Run as a background job — rate limited to avoid DB pressure
await foreach (var user in _userRepo.StreamUsersWithLegacyHashes(batchSize: 1000, ct))
{
    // ONLY if you can retrieve the plaintext password — you can't.
    // Batch rehash of existing hashes without plaintext is NOT possible.
    // This is by design — if you have plaintext passwords stored, that's a separate problem.
}
```

> ⚠️ **Note**: Batch rehash without plaintext passwords is impossible by design (one-way function).
> The transparent rehash-on-login approach is the correct migration path.

---

## Checklist

- [ ] Install `EricksonLopez.Security` package.
- [ ] Create `ElSecurityPasswordHasherBridge<TUser>` adapter class.
- [ ] Register bridge in DI, overriding Identity's `IPasswordHasher<TUser>`.
- [ ] Add rehash handling in login flow (check `SuccessRehashNeeded`, update stored hash).
- [ ] Configure `PasswordPolicy` with same or stricter requirements than Identity.
- [ ] (Optional) Enable Argon2id as default algorithm for new hashes.
- [ ] Test in staging: login success rate, rehash triggered, second-login success.
- [ ] Deploy to production and monitor.
- [ ] Add `EricksonLopez.Security.Testing` test doubles to unit tests.

---

## NIST SP 800-63B Compliance Delta

| Requirement | Identity (default) | EricksonLopez.Security |
|---|---|---|
| Minimum 8 characters | ✅ Configurable | ✅ Configurable |
| Check against breached password lists | ❌ Not built-in | ✅ `EricksonLopez.Security.Privacy.Hibp` (`HibpPasswordChecker`) |
| Allow any printable ASCII character | ✅ | ✅ |
| Prohibited: composition rules (must have digit etc.) | ⚠️ Identity encourages complexity rules (technically non-compliant with NIST B2) | ⚠️ EL.Security also supports complexity rules — disable for strict NIST compliance |
| Memory-hard algorithm | ❌ PBKDF2 is not memory-hard | ✅ Argon2id is memory-hard (NIST recommends memory-hard KDFs in SP 800-63B Rev 4) |

---

## FAQ

**Q: Will existing users have to reset their passwords?**  
A: No. The bridge adapter handles legacy Identity hashes transparently. Users rehash automatically on next login.

**Q: Can I use EricksonLopez.Security without ASP.NET Core Identity at all?**  
A: Yes. If you manage user persistence yourself, inject `IPasswordHasher` directly. Identity is optional.

**Q: What if I'm using BCrypt (BCrypt.Net) instead of Identity?**  
A: Same approach — MCF format means `CompositePasswordHasher` can detect `$2a$` BCrypt prefixes if you add a `BCryptPasswordHasher` adapter. File a GitHub issue to request built-in BCrypt detection in the composite dispatcher.

**Q: What algorithm does the bridge use for new hashes?**  
A: PBKDF2-SHA512 (210,000 iterations) by default, or Argon2id if configured. Both are stronger than Identity's default PBKDF2-SHA256 (100,000 iterations).

---

## Related Resources

- [Migration Guide: DataProtection → EL.Security](./migration-from-dataprotection.md)
- [Quickstart: 5-Minute Getting Started](./quickstart.md)
- [ADR-005: Password Hashing — PBKDF2, Argon2id, and Auto-Rehash](./adr/adr-005-password-hashing-pbkdf2-argon2-and-auto-rehash.md)
- [Have I Been Pwned Integration](../src/EricksonLopez.Security.Privacy.Hibp/)
- [NIST SP 800-63B Digital Identity Guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html)
