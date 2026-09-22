// Copyright © Erickson Lopez. MIT License.

using System;
using System.Threading.Tasks;
using EricksonLopez.Security.Abstractions.KeyManagement;
using EricksonLopez.Security.Abstractions.Secrets;
using EricksonLopez.Security.Aws;
using EricksonLopez.Security.Azure;
using EricksonLopez.Security.Cryptography.Pkcs11.Interop;
using EricksonLopez.Security.GoogleCloud;
using EricksonLopez.Security.HashiCorpVault;
using EricksonLopez.Security.Privacy.Hibp.DependencyInjection;
using EricksonLopez.Security.Privacy.Hibp.Models;
using EricksonLopez.Security.WebAuthn.Fido2.Mds3;
using Microsoft.Extensions.DependencyInjection;

namespace EricksonLopez.Security.Sample.Levels;

/// <summary>
/// Level 9: Cloud KMS Adapters, Hardware Security Modules (HSM) & External Integrations.
/// Demonstrates configuration contracts and store implementations for Azure Key Vault,
/// AWS KMS & Secrets Manager, HashiCorp Vault Transit / KV v2, Google Cloud KMS & Secret Manager,
/// PKCS#11 HSMs, FIDO Alliance MDS3, and HIBP k-Anonymity.
/// </summary>
public static class Level9_ExtensionsAndCloudKms
{
    public static void Run()
    {
        RunAsync().GetAwaiter().GetResult();
    }

    public static async Task RunAsync()
    {
        Console.WriteLine("\n================================================================================");
        Console.WriteLine("  LEVEL 9: CLOUD KMS ADAPTERS, HSM & ECOSYSTEM EXTENSIONS");
        Console.WriteLine("================================================================================");

        // -------------------------------------------------------------------------
        // 1. Azure Key Vault (Keys & Secrets Store)
        // -------------------------------------------------------------------------
        Console.WriteLine("\n[1] Azure Key Vault (KMS KeyStore & SecretStore Adapter):");
        var azureServices = new ServiceCollection();
        azureServices.AddAzureKeyVaultSecurity(options =>
        {
            options.VaultUri = new Uri("https://enterprise-vault-prod.vault.azure.net/");
            options.SecretPrefix = "fintech-app-";
            options.EnableDevelopmentInMemoryStub = true; // In-memory double for local development / testing
        });
        using var azureProvider = azureServices.BuildServiceProvider();
        var azureSecretStore = azureProvider.GetRequiredService<ISecretStore>();
        var azureKeyStore = azureProvider.GetRequiredService<IKeyStore>();

        await azureSecretStore.SetSecretAsync("database-conn", "Server=azure-sql.corp;Database=Fintech;Encrypted=true;");
        var azureSecret = await azureSecretStore.GetSecretAsync("database-conn");
        Console.WriteLine($"  -> Azure Key Vault Registration: SUCCESS (ISecretStore & IKeyStore resolved)");
        Console.WriteLine($"  -> Secret Retrieved: HasValue={azureSecret.Value.HasValue}, Redacted={azureSecret.Value}");

        // -------------------------------------------------------------------------
        // 2. AWS KMS & Secrets Manager
        // -------------------------------------------------------------------------
        Console.WriteLine("\n[2] AWS KMS & Secrets Manager Adapter:");
        var awsServices = new ServiceCollection();
        awsServices.AddAwsSecurity(options =>
        {
            options.Region = "us-east-1";
            options.KmsKeyId = "arn:aws:kms:us-east-1:123456789012:key/bc25c123-4567-89ab-cdef-0123456789ab";
            options.SecretPrefix = "prod/banking/";
            options.EnableDevelopmentInMemoryStub = true;
        });
        using var awsProvider = awsServices.BuildServiceProvider();
        var awsSecretStore = awsProvider.GetRequiredService<ISecretStore>();
        var awsKeyStore = awsProvider.GetRequiredService<IKeyStore>();

        await awsSecretStore.SetSecretAsync("api-signing-key", "SuperSecretAwsSigningKeyString123456789");
        var awsSecret = await awsSecretStore.GetSecretAsync("api-signing-key");
        Console.WriteLine($"  -> AWS KMS & Secrets Manager Registration: SUCCESS (ISecretStore & IKeyStore resolved)");
        Console.WriteLine($"  -> Secret Retrieved: HasValue={awsSecret.Value.HasValue}, Redacted={awsSecret.Value}");

        // -------------------------------------------------------------------------
        // 3. HashiCorp Vault Transit Engine & KV v2
        // -------------------------------------------------------------------------
        Console.WriteLine("\n[3] HashiCorp Vault Transit Encryption & KV v2 Secrets Engine:");
        var vaultServices = new ServiceCollection();
        vaultServices.AddHashiCorpVaultSecurity(options =>
        {
            options.VaultUrl = new Uri("https://vault.internal.corp:8200/");
            options.TransitMountPath = "transit";
            options.KvMountPath = "secret";
            options.SecretPathPrefix = "app-security/";
            options.EnableDevelopmentInMemoryStub = true;
        });
        using var vaultProvider = vaultServices.BuildServiceProvider();
        var vaultSecretStore = vaultProvider.GetRequiredService<ISecretStore>();
        var vaultKeyStore = vaultProvider.GetRequiredService<IKeyStore>();

        await vaultSecretStore.SetSecretAsync("jwt-signing-secret", "VaultProtectedHmacKeySecretString987654321");
        var vaultSecret = await vaultSecretStore.GetSecretAsync("jwt-signing-secret");
        Console.WriteLine($"  -> HashiCorp Vault Registration: SUCCESS (ISecretStore & IKeyStore resolved)");
        Console.WriteLine($"  -> Secret Retrieved: HasValue={vaultSecret.Value.HasValue}, Redacted={vaultSecret.Value}");

        // -------------------------------------------------------------------------
        // 4. Google Cloud KMS & Secret Manager
        // -------------------------------------------------------------------------
        Console.WriteLine("\n[4] Google Cloud KMS & Secret Manager Adapter:");
        var gcpServices = new ServiceCollection();
        gcpServices.AddGoogleCloudSecurity(options =>
        {
            options.ProjectId = "enterprise-sec-prod";
            options.LocationId = "global";
            options.KeyRingId = "banking-keys";
            options.SecretPrefix = "sec_";
            options.EnableDevelopmentInMemoryStub = true;
        });
        using var gcpProvider = gcpServices.BuildServiceProvider();
        var gcpSecretStore = gcpProvider.GetRequiredService<ISecretStore>();
        var gcpKeyStore = gcpProvider.GetRequiredService<IKeyStore>();

        await gcpSecretStore.SetSecretAsync("oauth-client-secret", "GcpSecretManagerProtectedPayload456789123");
        var gcpSecret = await gcpSecretStore.GetSecretAsync("oauth-client-secret");
        Console.WriteLine($"  -> Google Cloud KMS & Secret Manager Registration: SUCCESS (ISecretStore & IKeyStore resolved)");
        Console.WriteLine($"  -> Secret Retrieved: HasValue={gcpSecret.Value.HasValue}, Redacted={gcpSecret.Value}");

        // -------------------------------------------------------------------------
        // 5. PKCS#11 Hardware Security Module (HSM) Interop
        // -------------------------------------------------------------------------
        Console.WriteLine("\n[5] PKCS#11 Hardware Security Module (HSM) Mechanism Standards:");
        Console.WriteLine($"  -> PKCS#11 Return Code CKR_OK: 0x{Pkcs11Constants.CKR_OK:X8}");
        Console.WriteLine($"  -> PKCS#11 RSA PKCS Mechanism CKM_RSA_PKCS: 0x{Pkcs11Constants.CKM_RSA_PKCS:X8}");
        Console.WriteLine($"  -> PKCS#11 SHA256-RSA Mechanism CKM_SHA256_RSA_PKCS: 0x{Pkcs11Constants.CKM_SHA256_RSA_PKCS:X8}");
        Console.WriteLine($"  -> PKCS#11 ECDSA Mechanism CKM_ECDSA: 0x{Pkcs11Constants.CKM_ECDSA:X8}");

        // -------------------------------------------------------------------------
        // 6. FIDO Alliance MDS3 (Metadata Service v3)
        // -------------------------------------------------------------------------
        Console.WriteLine("\n[6] FIDO Alliance MDS3 Authenticator Metadata Service:");
        var mds3Options = new Mds3Options
        {
            MetadataBlobUrl = "https://mds3.fidoalliance.org/",
            CacheDuration = TimeSpan.FromHours(24),
            ValidateJwtSignature = true,
            AllowUnknownAuthenticators = false
        };
        Console.WriteLine($"  -> MDS3 Endpoint: {mds3Options.MetadataBlobUrl}");
        Console.WriteLine($"  -> MDS3 Cache Lifetime: {mds3Options.CacheDuration.TotalHours} hours");
        Console.WriteLine($"  -> Validate JWT Signature: {mds3Options.ValidateJwtSignature}");
        Console.WriteLine($"  -> Allow Unknown Authenticators: {mds3Options.AllowUnknownAuthenticators}");

        // -------------------------------------------------------------------------
        // 7. Have I Been Pwned (HIBP) k-Anonymity Options & DI
        // -------------------------------------------------------------------------
        Console.WriteLine("\n[7] Have I Been Pwned (HIBP) k-Anonymity API Options & DI Registration:");
        var hibpOptions = new HibpOptions
        {
            UserAgent = "EricksonLopez-Security-Showcase/1.0",
            MaxAllowedBreachCount = 0 // Zero tolerance: any breach flags the password
        };
        Console.WriteLine($"  -> HIBP User-Agent: {hibpOptions.UserAgent}");
        Console.WriteLine($"  -> Maximum Allowed Breaches: {hibpOptions.MaxAllowedBreachCount}");

        var hibpServices = new ServiceCollection();
        hibpServices.AddHaveIBeenPwned(opts =>
        {
            opts.UserAgent = hibpOptions.UserAgent;
            opts.MaxAllowedBreachCount = hibpOptions.MaxAllowedBreachCount;
        });
        Console.WriteLine("  -> AddHaveIBeenPwned() registered: IHaveIBeenPwnedClient, IPasswordPwnedValidator");

        Console.WriteLine("--------------------------------------------------------------------------------");
    }
}
