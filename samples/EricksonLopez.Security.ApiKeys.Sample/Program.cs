// Copyright © Erickson Lopez. MIT License.
// Sample: ASP.NET Core Minimal API with EricksonLopez.Security API Key Authentication
//
// This sample demonstrates:
//   1. Implementing an in-memory IApiKeyStore (replace with EF Core / Dapper in production).
//   2. Generating a structured API key via IApiKeyGenerator.
//   3. Persisting only the hashed secret — plaintext is shown once and discarded.
//   4. Async constant-time API key validation via IApiKeyValidator.
//   5. Security headers middleware (CSP, HSTS, X-Frame-Options, Referrer-Policy, etc.).
//
// To run:
//   cd samples/EricksonLopez.Security.ApiKeys.Sample
//   dotnet run
//
// Test with curl (use the key printed in the startup log):
//   curl -H "X-API-Key: ek_live_..." http://localhost:5000/api/data
//   curl http://localhost:5000/api/data  # Returns 401

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using EricksonLopez.Result;
using EricksonLopez.Security;
using EricksonLopez.Security.Abstractions.Errors;
using EricksonLopez.Security.Abstractions.Primitives;
using EricksonLopez.Security.Abstractions.Tokens;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

// ─── Bootstrap ────────────────────────────────────────────────────────────────

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddEricksonLopezSecurity();
builder.Services.AddSecurityAspNetCore();

// Register the in-memory store as a singleton — swap for a real DB implementation in production
var apiKeyStore = new InMemoryApiKeyStore();
builder.Services.AddSingleton<IApiKeyStore>(apiKeyStore);

builder.Logging.SetMinimumLevel(LogLevel.Information);

var app = builder.Build();

// Inject security response headers on every response (CSP, HSTS, X-Frame-Options, etc.)
app.UseSecurityHeaders();

// ─── Issue a Demo API Key at startup ─────────────────────────────────────────

var apiKeyGenerator = app.Services.GetRequiredService<IApiKeyGenerator>();
var logger = app.Services.GetRequiredService<ILogger<Program>>();

var issuance = apiKeyGenerator.GenerateApiKey(
    ownerId: "demo-user-001",
    name: "Sample Application Key",
    prefix: "ek_live",
    lifetime: TimeSpan.FromDays(30),
    scopes: new HashSet<string>(StringComparer.Ordinal) { "data:read", "data:write" });

// Persist only the hashed key record (NEVER store the plaintext)
await apiKeyStore.SaveAsync(issuance.Key);

if (logger.IsEnabled(LogLevel.Information))
{
    logger.LogInformation(
        "=== DEMO API KEY (shown once — copy it now) ===\n" +
        "  Key ID:    {KeyId}\n" +
        "  Plaintext: {PlaintextKey}\n" +
        "  Scopes:    {Scopes}\n" +
        "  Expires:   {ExpiresAt}\n" +
        "Header:  X-API-Key: {PlaintextKey}",
        issuance.Key.Id,
        issuance.PlaintextApiKey,
        string.Join(", ", (IEnumerable<string>?)issuance.Key.Scopes ?? Array.Empty<string>()),
        issuance.Key.ExpiresAtUtc?.ToString("o") ?? "never",
        issuance.PlaintextApiKey);
}

// ─── API Key Validation Middleware ────────────────────────────────────────────

var apiKeyValidator = app.Services.GetRequiredService<IApiKeyValidator>();

app.Use(async (HttpContext context, RequestDelegate next) =>
{
    if (!context.Request.Path.StartsWithSegments("/api"))
    {
        await next(context);
        return;
    }

    if (!context.Request.Headers.TryGetValue("X-API-Key", out var rawKeyValue)
        || string.IsNullOrWhiteSpace(rawKeyValue))
    {
        context.Response.StatusCode = StatusCodes.Status401Unauthorized;
        await context.Response.WriteAsJsonAsync(new { error = "Missing X-API-Key header." });
        return;
    }

    // Constant-time validation — no timing oracle possible
    var validationResult = await apiKeyValidator.ValidateApiKeyAsync(
        rawKeyValue.ToString(),
        context.RequestAborted);

    if (validationResult.IsFailure)
    {
        context.Response.StatusCode = StatusCodes.Status401Unauthorized;
        await context.Response.WriteAsJsonAsync(new
        {
            error = "Invalid or expired API key.",
            detail = validationResult.Error.Description
        });
        return;
    }

    var validKey = validationResult.Value;
    context.Items["ApiKeyOwner"] = validKey.OwnerId;
    context.Items["ApiKeyScopes"] = validKey.Scopes;

    await next(context);
});

// ─── Endpoints ────────────────────────────────────────────────────────────────

app.MapGet("/api/data", (HttpContext ctx) =>
{
    var owner = ctx.Items["ApiKeyOwner"] as string ?? "unknown";
    var scopes = ctx.Items["ApiKeyScopes"] as IReadOnlySet<string> ?? new HashSet<string>();

    if (logger.IsEnabled(LogLevel.Information))
        logger.LogInformation("Authenticated request from {Owner} with scopes [{Scopes}]",
            owner, string.Join(", ", scopes));

    return Results.Ok(new
    {
        message = "Access granted.",
        owner,
        scopes,
        timestamp = DateTimeOffset.UtcNow
    });
});

app.MapGet("/health", () => Results.Ok(new { status = "healthy", timestamp = DateTimeOffset.UtcNow }));

app.MapPost("/api/keys/revoke/{keyId}", async (string keyId) =>
{
    var revokeResult = await apiKeyStore.RevokeAsync(new ApiKeyId(keyId));
    return revokeResult.IsSuccess
        ? Results.Ok(new { message = $"Key {keyId} revoked." })
        : Results.NotFound(new { error = revokeResult.Error.Description });
});

app.MapGet("/", () => Results.Redirect("/api/data"));

logger.LogInformation("API Key sample running on http://localhost:5000");
app.Run();

// ─── Type declarations MUST follow top-level statements in C# ────────────────

/// <summary>
/// Minimal in-memory implementation of <see cref="IApiKeyStore"/> for demonstration purposes.
/// In production, implement this against your database (EF Core, Dapper, etc.).
/// </summary>
sealed class InMemoryApiKeyStore : IApiKeyStore
{
    private readonly ConcurrentDictionary<string, ApiKey> _store = new();

    public ValueTask<Result<ApiKey>> GetByIdAsync(ApiKeyId keyId, CancellationToken ct = default)
    {
        return _store.TryGetValue(keyId.Value, out var key)
            ? ValueTask.FromResult(Result<ApiKey>.Success(key))
            : ValueTask.FromResult(Result<ApiKey>.Failure(
                SecurityError.InvalidToken($"API key '{keyId.Value}' not found.")));
    }

    public ValueTask<Result> SaveAsync(ApiKey apiKey, CancellationToken ct = default)
    {
        _store[apiKey.Id.Value] = apiKey;
        return ValueTask.FromResult(Result.Success());
    }

    public ValueTask<Result> RevokeAsync(ApiKeyId keyId, CancellationToken ct = default)
    {
        if (_store.TryGetValue(keyId.Value, out var key))
        {
            _store[keyId.Value] = key with { RevokedAtUtc = DateTimeOffset.UtcNow };
            return ValueTask.FromResult(Result.Success());
        }

        return ValueTask.FromResult(Result.Failure(
            SecurityError.InvalidToken($"Key '{keyId.Value}' not found.")));
    }
}

// Make the implicit Program class accessible for integration testing
public partial class Program { }
