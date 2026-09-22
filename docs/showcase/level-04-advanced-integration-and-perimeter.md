# Level 04: Advanced Integration, Perimeter Defense & PKI

> **Showcase Level**: Level 4  
> **Source Code**: [`samples/EricksonLopez.Security.Sample/Levels/Level4_AdvancedIntegration.cs`](../../samples/EricksonLopez.Security.Sample/Levels/Level4_AdvancedIntegration.cs)  
> **Packages**: `EricksonLopez.Security.AspNetCore`, `EricksonLopez.Security.Network`, `EricksonLopez.Security.Pki`, `EricksonLopez.Security.Abstractions`

---

## 1. Overview & Architectural Role

Level 4 demonstrates defense-in-depth at the application and network perimeter:
- **HTTP Security Response Headers**: Mitigating XSS, clickjacking, MIME-sniffing, and SSL-stripping attacks via hardened HTTP headers.
- **Request Security Context**: Scoped, thread-safe accessor extracting actor identity, authentication state, and authorization scopes from `HttpContext`.
- **Network SSRF Prevention**: Socket-level defense preventing Server-Side Request Forgery against loopback, RFC 1918 private subnets, link-local addresses, and cloud instance metadata endpoints (`169.254.169.254`).
- **PKI & X.509 Chain Validation**: Custom trust anchor validation, strict revocation checking (CRL/OCSP), and leaf-level SAN validation without relying on machine-wide trust stores.
- **Cryptographic Domain Events**: Audit-logging lifecycle events (`KeyCreatedEvent`, `KeyRotatedEvent`, `KeyRevokedEvent`, `KeyDestroyedEvent`).

---

## 2. Hardened ASP.NET Core Response Headers

```csharp
using EricksonLopez.Security.AspNetCore.Headers;

var headerOptions = new SecurityHeadersOptions
{
    ContentSecurityPolicy = "default-src 'self'; script-src 'self' https://cdn.jsdelivr.net; frame-ancestors 'none';",
    StrictTransportSecurity = "max-age=31536000; includeSubDomains; preload",
    XContentTypeOptions = "nosniff",
    XFrameOptions = "DENY",
    ReferrerPolicy = "strict-origin-when-cross-origin",
    PermissionsPolicy = "camera=(), microphone=(), geolocation=()"
};
```

---

## 3. Scoped Request Security Context

Extracting verified actor information in API controllers and minimal endpoints:

```csharp
using System.Security.Claims;
using EricksonLopez.Security.AspNetCore.Context;
using Microsoft.AspNetCore.Http;

var httpContext = new DefaultHttpContext();
var claims = new[]
{
    new Claim(ClaimTypes.NameIdentifier, "usr_executive_8841"),
    new Claim("scope", "payments:process")
};
httpContext.User = new ClaimsPrincipal(new ClaimsIdentity(claims, "ApiKey"));
var contextAccessor = new HttpContextAccessor { HttpContext = httpContext };

var requestContext = new RequestSecurityContext(contextAccessor);

bool isAuthenticated = requestContext.IsAuthenticated; // true
string? actorId = requestContext.ActorId;             // "usr_executive_8841"
bool canProcess = requestContext.HasScope("payments:process"); // true
```

---

## 4. Network SSRF Mitigation (`SafeSocketsHttpHandler`)

Outbound HTTP requests are validated at the socket resolution level, neutralizing DNS rebinding and loopback bypasses:

```csharp
using System.Net;
using EricksonLopez.Security.Network;

var ssrfOptions = new SsrfProtectionOptions();

// Blocked Ranges include:
// - 127.0.0.0/8 (Loopback)
// - 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 (RFC 1918 Private)
// - 169.254.169.254/32 (AWS/Azure/GCP Instance Metadata)

var metadataIp = IPAddress.Parse("169.254.169.254");
bool isBlocked = ssrfOptions.BlockedRanges.Any(range => range.Contains(metadataIp));
// Result: true (SSRF exfiltration attempt blocked before socket connection)

// Hardened HttpClient instantiation via SafeHttpClientFactory:
using HttpClient safeClient = SafeHttpClientFactory.CreateClient(opts =>
{
    opts.RestrictToAllowedHostnames = false; // or true with opts.AllowedHostnames
    opts.AllowedHostnames.Add("api.partner-bank.com");
});
```

---

## 5. PKI & X.509 Certificate Chain Validation

Validating partner certificates with isolated trust anchors:

```csharp
using System.Security.Cryptography.X509Certificates;
using EricksonLopez.Security.Pki;

var pkiOptions = new CertificateValidationOptions
{
    CheckRevocation = false, // Configurable for offline or test environments
    ValidateKeyUsage = true,
    AllowedSubjectAlternativeNames = { "api.partner-bank.com", "gateway.partner-bank.com" }
};

var pkiValidator = new CertificateChainValidator(pkiOptions);
// Validates chain, dates, and SAN against pkiOptions
```

---

## 6. Cryptographic Domain Audit Events

Immutable records tracking key state transitions for SIEM compliance:

```csharp
using EricksonLopez.Security.Abstractions.Events;
using EricksonLopez.Security.Abstractions.KeyManagement;
using EricksonLopez.Security.Abstractions.Primitives;

var createdEvent = new KeyCreatedEvent(
    KeyId: KeyIdentifier.New(),
    Version: KeyVersion.Initial,
    Purpose: KeyPurpose.SecretProtection,
    CreatedAtUtc: DateTimeOffset.UtcNow);

var rotatedEvent = new KeyRotatedEvent(
    KeyId: createdEvent.KeyId,
    OldVersion: KeyVersion.Initial,
    NewVersion: KeyVersion.Initial.Next(),
    RotatedAtUtc: DateTimeOffset.UtcNow);
```
