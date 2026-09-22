# Level 09: Multi-Cloud KMS, HSM & Satellite Extensions

> **Showcase Level**: Level 9  
> **Source Code**: [`samples/EricksonLopez.Security.Sample/Levels/Level9_ExtensionsAndCloudKms.cs`](../../samples/EricksonLopez.Security.Sample/Levels/Level9_ExtensionsAndCloudKms.cs)  
> **Packages**: `EricksonLopez.Security.Azure`, `EricksonLopez.Security.Aws`, `EricksonLopez.Security.HashiCorpVault`, `EricksonLopez.Security.GoogleCloud`, `EricksonLopez.Security.Cryptography.Pkcs11`, `EricksonLopez.Security.WebAuthn.Fido2.Mds3`, `EricksonLopez.Security.Privacy.Hibp`

---

## 1. Overview & Architectural Role

Level 9 demonstrates integration options for multi-cloud key management, hardware security modules, and external threat intelligence:
- **Azure Key Vault**: Enterprise key management (`IKeyStore`) and secret storage (`ISecretStore`).
- **AWS KMS & Secrets Manager**: AWS KMS symmetric keys and hierarchical secret namespaces.
- **HashiCorp Vault**: Transit Encryption engine and KV v2 secrets engine.
- **Google Cloud KMS & Secret Manager**: Google Cloud KeyRing management and Secret Manager storage.
- **PKCS#11 Hardware Security Modules (HSM)**: Cryptoki standards for hardware key protection.
- **FIDO Alliance MDS3**: Authenticator metadata service and BLOB validation.
- **Have I Been Pwned (HIBP)**: k-Anonymity breach detection for compromised passwords.

> [!NOTE]
> **Status in v1.x (ADR-011, ADR-012, ADR-013)**: The cloud adapter packages (`Azure`, `Aws`, `HashiCorpVault`, `GoogleCloud`) currently provide thread-safe in-memory doubles (`ConcurrentDictionary`) implementing `IKeyStore` and `ISecretStore` without requiring external cloud SDK dependencies. Full cloud SDK integrations with Testcontainers are scheduled for v2.0.

---

## 2. Azure Key Vault Configuration & Registration

```csharp
using EricksonLopez.Security.Azure;
using Microsoft.Extensions.DependencyInjection;

var services = new ServiceCollection();
services.AddAzureKeyVaultSecurity(options =>
{
    options.VaultUri = new Uri("https://enterprise-vault-prod.vault.azure.net/");
    options.SecretPrefix = "fintech-app-";
    options.EnableDevelopmentInMemoryStub = true;
});

using var provider = services.BuildServiceProvider();
var secretStore = provider.GetRequiredService<ISecretStore>();
var keyStore = provider.GetRequiredService<IKeyStore>();

await secretStore.SetSecretAsync("database-conn", "Server=azure-sql.corp;Database=Fintech;Encrypted=true;");
var secret = await secretStore.GetSecretAsync("database-conn");
```

---

## 3. AWS KMS & Secrets Manager Configuration & Registration

```csharp
using EricksonLopez.Security.Aws;
using Microsoft.Extensions.DependencyInjection;

var services = new ServiceCollection();
services.AddAwsSecurity(options =>
{
    options.Region = "us-east-1";
    options.KmsKeyId = "arn:aws:kms:us-east-1:123456789012:key/bc25c123-4567-89ab-cdef-0123456789ab";
    options.SecretPrefix = "prod/banking/";
    options.EnableDevelopmentInMemoryStub = true;
});

using var provider = services.BuildServiceProvider();
var secretStore = provider.GetRequiredService<ISecretStore>();
var keyStore = provider.GetRequiredService<IKeyStore>();

await secretStore.SetSecretAsync("api-signing-key", "SuperSecretAwsSigningKeyString123456789");
var secret = await secretStore.GetSecretAsync("api-signing-key");
```

---

## 4. HashiCorp Vault Transit Engine & KV v2 Configuration

```csharp
using EricksonLopez.Security.HashiCorpVault;
using Microsoft.Extensions.DependencyInjection;

var services = new ServiceCollection();
services.AddHashiCorpVaultSecurity(options =>
{
    options.VaultUrl = new Uri("https://vault.internal.corp:8200/");
    options.TransitMountPath = "transit";
    options.KvMountPath = "secret";
    options.SecretPathPrefix = "app-security/";
    options.EnableDevelopmentInMemoryStub = true;
});

using var provider = services.BuildServiceProvider();
var secretStore = provider.GetRequiredService<ISecretStore>();
var keyStore = provider.GetRequiredService<IKeyStore>();

await secretStore.SetSecretAsync("jwt-signing-secret", "VaultProtectedHmacKeySecretString987654321");
var secret = await secretStore.GetSecretAsync("jwt-signing-secret");
```

---

## 5. Google Cloud KMS & Secret Manager Configuration

```csharp
using EricksonLopez.Security.GoogleCloud;
using Microsoft.Extensions.DependencyInjection;

var services = new ServiceCollection();
services.AddGoogleCloudSecurity(options =>
{
    options.ProjectId = "enterprise-sec-prod";
    options.LocationId = "global";
    options.KeyRingId = "banking-keys";
    options.SecretPrefix = "sec_";
    options.EnableDevelopmentInMemoryStub = true;
});

using var provider = services.BuildServiceProvider();
var secretStore = provider.GetRequiredService<ISecretStore>();
var keyStore = provider.GetRequiredService<IKeyStore>();

await secretStore.SetSecretAsync("oauth-client-secret", "GcpSecretManagerProtectedPayload456789123");
var secret = await secretStore.GetSecretAsync("oauth-client-secret");
```

---

## 6. PKCS#11 Hardware Security Module (HSM) Interop

```csharp
using EricksonLopez.Security.Cryptography.Pkcs11.Interop;

// Standards-compliant Cryptoki mechanism identifiers:
ulong ckrOk = Pkcs11Constants.CKR_OK;                   // 0x00000000
ulong ckmRsa = Pkcs11Constants.CKM_RSA_PKCS;             // 0x00000001
ulong ckmSha256Rsa = Pkcs11Constants.CKM_SHA256_RSA_PKCS;// 0x00000040
ulong ckmEcdsa = Pkcs11Constants.CKM_ECDSA;             // 0x00001041
```

---

## 7. FIDO Alliance MDS3 Metadata Service

```csharp
using EricksonLopez.Security.WebAuthn.Fido2.Mds3;

var mds3Options = new Mds3Options
{
    MetadataBlobUrl = "https://mds3.fidoalliance.org/",
    CacheDuration = TimeSpan.FromHours(24),
    ValidateJwtSignature = true,
    AllowUnknownAuthenticators = false
};
```

---

## 8. Have I Been Pwned (HIBP) k-Anonymity & DI Registration

```csharp
using EricksonLopez.Security.Privacy.Hibp.DependencyInjection;
using EricksonLopez.Security.Privacy.Hibp.Models;
using Microsoft.Extensions.DependencyInjection;

var services = new ServiceCollection();
services.AddHaveIBeenPwned(options =>
{
    options.UserAgent = "EricksonLopez-Security-Showcase/1.0";
    options.MaxAllowedBreachCount = 0; // Zero tolerance: any breach flags the password
});
```
