// Copyright © Erickson Lopez. MIT License.

using System;
using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using EricksonLopez.Security.Abstractions.Cryptography;
using EricksonLopez.Security.Abstractions.Events;
using EricksonLopez.Security.Abstractions.KeyManagement;
using EricksonLopez.Security.Abstractions.Primitives;
using EricksonLopez.Security.AspNetCore.Authentication;
using EricksonLopez.Security.AspNetCore.Context;
using EricksonLopez.Security.AspNetCore.Headers;
using EricksonLopez.Security.Network;
using EricksonLopez.Security.Pki;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

namespace EricksonLopez.Security.Sample.Levels;

/// <summary>
/// Level 4: Advanced Integration & Defense-in-Depth.
/// Demonstrates ASP.NET Core security response headers, request contextual security,
/// SSRF network mitigation with IP filtering, PKI X.509 certificate chain validation,
/// Security Events (audit event records) and direct IKeyRing access.
/// </summary>
public static class Level4_AdvancedIntegration
{
    public static async Task Run()
    {
        Console.WriteLine("\n================================================================================");
        Console.WriteLine("  LEVEL 4: ADVANCED INTEGRATION & DEFENSE-IN-DEPTH");
        Console.WriteLine("================================================================================");

        // -------------------------------------------------------------------------
        // 1. ASP.NET Core Security Headers Options
        // -------------------------------------------------------------------------
        Console.WriteLine("\n[1] ASP.NET Core Hardened Security Headers Options:");
        var headerOptions = new SecurityHeadersOptions
        {
            ContentSecurityPolicy = "default-src 'self'; script-src 'self' https://cdn.jsdelivr.net; frame-ancestors 'none';",
            StrictTransportSecurity = "max-age=31536000; includeSubDomains; preload",
            XContentTypeOptions = "nosniff",
            XFrameOptions = "DENY",
            ReferrerPolicy = "strict-origin-when-cross-origin",
            PermissionsPolicy = "camera=(), microphone=(), geolocation=()"
        };

        Console.WriteLine($"  -> Content-Security-Policy: {headerOptions.ContentSecurityPolicy}");
        Console.WriteLine($"  -> Strict-Transport-Security: {headerOptions.StrictTransportSecurity}");
        Console.WriteLine($"  -> X-Frame-Options: {headerOptions.XFrameOptions}");
        Console.WriteLine($"  -> X-Content-Type-Options: {headerOptions.XContentTypeOptions}");

        // -------------------------------------------------------------------------
        // 1b. AddSecurityAspNetCore() — ASP.NET Core DI Registration
        // -------------------------------------------------------------------------
        Console.WriteLine("\n[1b] ASP.NET Core DI Registration — AddSecurityAspNetCore():");
        // This is how you'd register in a real ASP.NET Core application:
        var aspNetCoreServices = new ServiceCollection();
        // Note: In a real app you'd call builder.Services.AddSecurityAspNetCore(...) from Program.cs
        aspNetCoreServices.AddSecurityAspNetCore(
            configureHeaders: opts =>
            {
                opts.ContentSecurityPolicy = "default-src 'self'";
                opts.XFrameOptions = "DENY";
                opts.ReferrerPolicy = "no-referrer";
            },
            configureApiKeyAuth: opts =>
            {
                opts.HeaderName = "X-Api-Key";       // default header name
                opts.RequireApiKey = false;            // allow unauthenticated requests to pass
                opts.AuthenticationScheme = "ApiKey"; // scheme identifier
            });
        Console.WriteLine("  -> AddSecurityAspNetCore() registered: IRequestSecurityContext (scoped),");
        Console.WriteLine("     SecurityHeadersOptions, ApiKeyAuthenticationOptions, IHttpContextAccessor");

        // -------------------------------------------------------------------------
        // 1c. ApiKeyAuthenticationOptions — All Properties
        // -------------------------------------------------------------------------
        Console.WriteLine("\n[1c] ApiKeyAuthenticationOptions — All Configuration Properties:");
        var apiKeyAuthOptions = new ApiKeyAuthenticationOptions
        {
            HeaderName = "X-Api-Key",
            RequireApiKey = true,
            AuthenticationScheme = "ApiKey"
        };
        Console.WriteLine($"  -> HeaderName: {apiKeyAuthOptions.HeaderName}");
        Console.WriteLine($"  -> RequireApiKey: {apiKeyAuthOptions.RequireApiKey}");
        Console.WriteLine($"  -> AuthenticationScheme: {apiKeyAuthOptions.AuthenticationScheme}");
        Console.WriteLine("  Middleware pipeline setup:");
        Console.WriteLine("    app.UseSecurityHeaders()       → Adds SecurityHeadersMiddleware");
        Console.WriteLine("    app.UseApiKeyAuthentication()  → Adds ApiKeyAuthenticationMiddleware");

        // -------------------------------------------------------------------------
        // 2. Request Security Context
        // -------------------------------------------------------------------------
        Console.WriteLine("\n[2] Request Security Context (HttpContext Accessor Integration):");
        var httpContext = new DefaultHttpContext();
        var claims = new[]
        {
            new Claim(ClaimTypes.NameIdentifier, "usr_executive_8841"),
            new Claim("scope", "payments:process")
        };
        httpContext.User = new ClaimsPrincipal(new ClaimsIdentity(claims, "ApiKey"));
        var contextAccessor = new HttpContextAccessor { HttpContext = httpContext };

        var requestContext = new RequestSecurityContext(contextAccessor);

        Console.WriteLine($"  -> Is Authenticated: {requestContext.IsAuthenticated}");
        Console.WriteLine($"  -> Actor ID: {requestContext.ActorId}");
        Console.WriteLine($"  -> Has Scope 'payments:process': {requestContext.HasScope("payments:process")}");
        Console.WriteLine($"  -> Has Scope 'admin:delete': {requestContext.HasScope("admin:delete")}");
        // IRequestSecurityContext.ApiKey — null if request not authenticated via API key middleware
        Console.WriteLine($"  -> ApiKey (no API key auth middleware here): {requestContext.ApiKey?.Id.ToString() ?? "null (no ApiKey auth)"}");
        // IRequestSecurityContext.Principal — ClaimsPrincipal forwarded from HttpContext
        Console.WriteLine($"  -> Principal.Identity.Name: {requestContext.Principal?.Identity?.Name ?? "null"}");

        // -------------------------------------------------------------------------
        // 3. Network SSRF (Server-Side Request Forgery) Prevention
        // -------------------------------------------------------------------------
        Console.WriteLine("\n[3] Network SSRF Defense & IP Address Filtering (SafeSocketsHttpHandler):");
        var ssrfOptions = new SsrfProtectionOptions();

        var testAddresses = new (string Label, IPAddress IP)[]
        {
            ("AWS/Cloud Instance Metadata", IPAddress.Parse("169.254.169.254")),
            ("Localhost Loopback", IPAddress.Parse("127.0.0.1")),
            ("Corporate Private Network (RFC 1918)", IPAddress.Parse("10.240.0.5")),
            ("Public Internet IP (Allowed Gateway)", IPAddress.Parse("93.184.216.34"))
        };

        foreach (var (label, ip) in testAddresses)
        {
            bool isBlocked = false;
            foreach (var blockedRange in ssrfOptions.BlockedRanges)
            {
                if (blockedRange.Contains(ip))
                {
                    isBlocked = true;
                    break;
                }
            }

            var decision = isBlocked ? "BLOCKED (SSRF Threat Neutralized)" : "PERMITTED (Public Routable)";
            Console.WriteLine($"  -> Address: {ip,-16} [{label,-36}] => {decision}");
        }

        // SafeHttpClientFactory — factory for creating pre-configured SSRF-safe HttpClient instances
        using var safeClient = SafeHttpClientFactory.CreateClient(opts =>
        {
            opts.AllowedHostnames.Add("api.partner-service.com");
            opts.RestrictToAllowedHostnames = false;
        });
        Console.WriteLine($"  -> SafeHttpClientFactory.CreateClient(): Created SSRF-safe HttpClient instance (BaseAddress: {safeClient.BaseAddress?.ToString() ?? "unbound"})");

        // -------------------------------------------------------------------------
        // 4. PKI X.509 Certificate Chain & Trust Anchor Validation
        // -------------------------------------------------------------------------
        Console.WriteLine("\n[4] PKI X.509 Certificate Chain Validation:");
        var pkiValidator = new CertificateChainValidator();

        // Create an in-memory ephemeral self-signed test certificate for demonstration
        using var rsa = RSA.Create(2048);
        var certRequest = new CertificateRequest("CN=EricksonLopez Enterprise Root CA, O=EricksonLopez, C=US", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var testCert = certRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(5));

        var validationOptions = new CertificateValidationOptions
        {
            RevocationMode = X509RevocationMode.NoCheck,
            CustomTrustAnchors = { testCert }
        };

        var validationResult = pkiValidator.ValidateCertificate(testCert, validationOptions);
        Console.WriteLine($"  -> Certificate Subject: {testCert.Subject}");
        Console.WriteLine($"  -> Custom Root Trust Validation: {(validationResult.IsSuccess ? "VALID (Trusted Anchor)" : "FAILED")}");

        // -------------------------------------------------------------------------
        // 5. Security Events — Strongly-Typed Audit Event Records
        // -------------------------------------------------------------------------
        Console.WriteLine("\n[5] Security Events — Strongly-Typed Audit Event Catalog:");

        // Simulate a key rotation audit event
        var rotatedKeyId = KeyIdentifier.New();
        var keyRotatedEvt = KeyRotatedEvent.Create(
            keyId: rotatedKeyId,
            previousVersion: KeyVersion.Initial,
            newVersion: KeyVersion.Initial.Next(),
            purpose: KeyPurpose.SecretProtection,
            tenantId: "tenant_fintech_enterprise_42",
            actorId: "system.key-rotation-job");

        Console.WriteLine($"  -> KeyRotatedEvent: {keyRotatedEvt.EventType} (Severity: {keyRotatedEvt.Severity})");
        Console.WriteLine($"     EventId: {keyRotatedEvt.EventId} | Tenant: {keyRotatedEvt.TenantId} | Actor: {keyRotatedEvt.ActorId}");
        Console.WriteLine($"     KeyId: {keyRotatedEvt.KeyId} | v{keyRotatedEvt.PreviousVersion.Value} -> v{keyRotatedEvt.NewVersion.Value}");

        // Key revoked event
        var keyRevokedEvt = KeyRevokedEvent.Create(
            keyId: rotatedKeyId,
            version: KeyVersion.Initial.Next(),
            purpose: KeyPurpose.SecretProtection,
            reason: "Breach: Unauthorized access detected to key store (Incident #SEC-2026-0042).",
            tenantId: "tenant_fintech_enterprise_42",
            actorId: "security.incident-response-bot");

        Console.WriteLine($"  -> KeyRevokedEvent: {keyRevokedEvt.EventType} (Severity: {keyRevokedEvt.Severity})");
        Console.WriteLine($"     Reason: {keyRevokedEvt.Reason}");

        // API Key created event
        var apiKeyCreatedEvt = ApiKeyCreatedEvent.Create(
            keyId: ApiKeyId.New(),
            ownerId: "tenant_fintech_enterprise_42",
            displayPrefix: "ek_live_9f8a...",
            tenantId: "tenant_fintech_enterprise_42",
            actorId: "usr_admin_001");

        Console.WriteLine($"  -> ApiKeyCreatedEvent: {apiKeyCreatedEvt.EventType} (Severity: {apiKeyCreatedEvt.Severity})");
        Console.WriteLine($"     Owner: {apiKeyCreatedEvt.OwnerId}, Prefix: {apiKeyCreatedEvt.DisplayPrefix}");

        // API Key revoked event
        var apiKeyRevokedEvt = ApiKeyRevokedEvent.Create(
            keyId: apiKeyCreatedEvt.KeyId,
            ownerId: "tenant_fintech_enterprise_42",
            reason: "User-initiated revocation from security dashboard.",
            actorId: "usr_admin_001");

        Console.WriteLine($"  -> ApiKeyRevokedEvent: {apiKeyRevokedEvt.EventType} (Severity: {apiKeyRevokedEvt.Severity})");
        Console.WriteLine($"     Reason: {apiKeyRevokedEvt.Reason}");

        // Secret rotation event
        var secretRotatedEvt = SecretRotatedEvent.Create(
            secretName: "Database:ConnectionString",
            tenantId: "tenant_fintech_enterprise_42",
            actorId: "system.secret-rotation-job");

        Console.WriteLine($"  -> SecretRotatedEvent: {secretRotatedEvt.EventType} (Severity: {secretRotatedEvt.Severity})");
        Console.WriteLine($"     SecretName: {secretRotatedEvt.SecretName}");

        // Security policy violated event
        var policyViolatedEvt = SecurityPolicyViolatedEvent.Create(
            policyName: "PasswordPolicy",
            violationDetails: "Password contains repeated sequences (aaaa) violating MaxConsecutiveRepeatedChars=3.",
            tenantId: "tenant_fintech_enterprise_42",
            actorId: "usr_consumer_007");

        Console.WriteLine($"  -> SecurityPolicyViolatedEvent: {policyViolatedEvt.EventType} (Severity: {policyViolatedEvt.Severity})");
        Console.WriteLine($"     Policy: {policyViolatedEvt.PolicyName} | Details: {policyViolatedEvt.ViolationDetails}");

        // -------------------------------------------------------------------------
        // 6. IKeyRing — Direct Key Ring Query
        // -------------------------------------------------------------------------
        Console.WriteLine("\n[6] IKeyRing — Direct Key Ring Query Interface:");

        var keyServices = new ServiceCollection();
        keyServices.AddEricksonLopezSecurity();
        using var keyProvider = keyServices.BuildServiceProvider();

        var keyLifecycle = keyProvider.GetRequiredService<IKeyLifecycleManager>();
        var keyRing = keyProvider.GetRequiredService<IKeyRing>();
        var encryptionKeyProvider = keyProvider.GetRequiredService<IEncryptionKeyProvider>();

        // Pre-populate ring with an active key
        var seedKey = await keyLifecycle.GenerateAndActivateKeyAsync(KeyPurpose.SecretProtection);
        Console.WriteLine($"  -> Active key seeded: {seedKey.Value.Metadata.KeyId} (v{seedKey.Value.Metadata.Version})");

        // IKeyRing.GetActiveKey() — synchronous (prefer GetActiveKeyAsync in async contexts)
        var activeKeyResult = keyRing.GetActiveKey(KeyPurpose.SecretProtection);
        Console.WriteLine($"  -> GetActiveKey() [sync]: {(activeKeyResult.IsSuccess ? "FOUND" : "NOT FOUND")} — {activeKeyResult.Value.Metadata.KeyId}");

        // IKeyRing.GetActiveKeyAsync() — async overload
        var activeKeyAsyncResult = await keyRing.GetActiveKeyAsync(KeyPurpose.SecretProtection);
        Console.WriteLine($"  -> GetActiveKeyAsync() [async]: {(activeKeyAsyncResult.IsSuccess ? "FOUND" : "NOT FOUND")} — {activeKeyAsyncResult.Value.Metadata.KeyId}");

        // IKeyRing.GetKey() by ID + Version — synchronous (prefer GetKeyAsync in async contexts)
        var specificKeyResult = keyRing.GetKey(seedKey.Value.Metadata.KeyId, seedKey.Value.Metadata.Version);
        Console.WriteLine($"  -> GetKey(id, version) [sync]: Status={specificKeyResult.Value.Metadata.Status}");

        // IKeyRing.GetKeyAsync() — async overload
        var specificKeyAsyncResult = await keyRing.GetKeyAsync(seedKey.Value.Metadata.KeyId, seedKey.Value.Metadata.Version);
        Console.WriteLine($"  -> GetKeyAsync(id, version) [async]: Status={specificKeyAsyncResult.Value.Metadata.Status}");

        // IKeyRing.ListMetadataAsync()
        var allKeys = await keyRing.ListMetadataAsync(KeyPurpose.SecretProtection);
        Console.WriteLine($"  -> ListMetadataAsync(): {allKeys.Value.Count} key(s) in ring for SecretProtection");

        // KeyMetadata — direct property inspection
        var keyMeta = seedKey.Value.Metadata;
        Console.WriteLine($"  -> KeyMetadata: KeyId={keyMeta.KeyId} | Version={keyMeta.Version} | Purpose={keyMeta.Purpose} | Status={keyMeta.Status} | Algorithm={keyMeta.AlgorithmId}");
        Console.WriteLine($"  -> KeyMetadata.CreatedAtUtc: {keyMeta.CreatedAtUtc:O} | ExpiresAtUtc: {keyMeta.ExpiresAtUtc?.ToString("O") ?? "null (no expiry)"}");

        // IEncryptionKeyProvider — key resolution abstraction used internally by AesGcmSecretProtector
        Console.WriteLine("\n[7] IEncryptionKeyProvider — Key Resolution for Encryption/Decryption:");
        var activeEncKey = await encryptionKeyProvider.GetActiveEncryptionKeyAsync(KeyPurpose.SecretProtection);
        Console.WriteLine($"  -> GetActiveEncryptionKeyAsync(): {(activeEncKey.IsSuccess ? "FOUND" : "NOT FOUND")} — {activeEncKey.Value.Metadata.KeyId}");

        var decKey = await encryptionKeyProvider.GetDecryptionKeyAsync(
            seedKey.Value.Metadata.KeyId,
            seedKey.Value.Metadata.Version);
        Console.WriteLine($"  -> GetDecryptionKeyAsync(id, version): {(decKey.IsSuccess ? "FOUND" : "NOT FOUND")} — Status={decKey.Value.Metadata.Status}");

        Console.WriteLine("--------------------------------------------------------------------------------");
    }
}
