# Integration Guide (Clean Architecture & ASP.NET Core)

## 1. Quick Dependency Injection Setup

In your application's bootstrap (`Program.cs`):

```csharp
using Microsoft.Extensions.DependencyInjection;

var builder = WebApplication.CreateBuilder(args);

// Register complete EricksonLopez.Security ecosystem
builder.Services.AddEricksonLopezSecurity();

// Register ASP.NET Core middleware & security headers
builder.Services.AddSecurityAspNetCore(
    configureHeaders: options =>
    {
        options.ContentSecurityPolicy = "default-src 'self'; frame-ancestors 'none';";
        options.StrictTransportSecurity = "max-age=31536000; includeSubDomains; preload";
    },
    configureApiKeyAuth: options =>
    {
        options.HeaderName = "X-Api-Key";
        options.RequireApiKey = true;
    });

var app = builder.Build();

// Configure Middleware Pipeline
app.UseSecurityHeaders();
app.UseApiKeyAuthentication();

app.MapGet("/api/secure-data", (IRequestSecurityContext securityContext) =>
{
    return Results.Ok(new
    {
        ActorId = securityContext.ActorId,
        IsAuthenticated = securityContext.IsAuthenticated,
        HasAdmin = securityContext.HasScope("admin:read")
    });
});

app.Run();
```

---

## 2. Clean Architecture Layering Recommendations

```text
Domain Layer:
  - References: EricksonLopez.Security.Abstractions
  - Uses: KeyIdentifier, KeyVersion, Redacted<T>, SecurityStamp, PasswordPolicy

Application Layer:
  - References: EricksonLopez.Security.Abstractions
  - Injects: ISecretProtector, IPasswordHasher, ITokenGenerator, IKeyLifecycleManager
  - Handles: Commands, Queries, Domain Event dispatch

Infrastructure Layer:
  - References: EricksonLopez.Security
  - Implements: Custom IKeyStore (e.g. PostgreSQL Dapper KeyStore), Custom IApiKeyStore

Presentation / API Layer:
  - References: EricksonLopez.Security.AspNetCore
  - Injects: IRequestSecurityContext, Uses: SecurityHeadersMiddleware, ApiKeyAuthenticationMiddleware
```
