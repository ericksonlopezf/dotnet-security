// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.AspNetCore.Headers;

using System;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;

/// <summary>
/// Middleware that enforces enterprise security response headers on all outgoing HTTP responses
/// to mitigate clickjacking, MIME-sniffing, XSS, and transport downgrade attacks.
/// </summary>
public sealed class SecurityHeadersMiddleware
{
    private readonly RequestDelegate _next;
    private readonly SecurityHeadersOptions _options;

    /// <summary>
    /// Initializes a new instance of the <see cref="SecurityHeadersMiddleware"/> class.
    /// </summary>
    /// <param name="next">The next middleware in the pipeline.</param>
    /// <param name="options">Security headers configuration options.</param>
    /// <exception cref="ArgumentNullException"><paramref name="next"/> is <see langword="null"/></exception>
    public SecurityHeadersMiddleware(RequestDelegate next, IOptions<SecurityHeadersOptions> options)
    {
        _next = next ?? throw new ArgumentNullException(nameof(next));
        _options = options?.Value ?? new SecurityHeadersOptions();
    }

    /// <summary>
    /// Injects the configured security headers into the response headers collection.
    /// </summary>
    /// <param name="context">The HTTP context.</param>
    /// <returns>A task representing the asynchronous pipeline operation.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="context"/> is <see langword="null"/></exception>
    public async Task InvokeAsync(HttpContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        context.Response.OnStarting(static state =>
        {
            var (ctx, self) = ((HttpContext, SecurityHeadersMiddleware))state;
            self.ApplyHeaders(ctx);
            return Task.CompletedTask;
        }, (context, this));

        ApplyHeaders(context);

        try
        {
            await _next(context).ConfigureAwait(false);
        }
        finally
        {
            if (!context.Response.HasStarted)
            {
                ApplyHeaders(context);
            }
        }
    }

    private void ApplyHeaders(HttpContext context)
    {
        var headers = context.Response.Headers;

        if (!string.IsNullOrEmpty(_options.ContentSecurityPolicy) && !headers.ContainsKey("Content-Security-Policy"))
        {
            headers.Append("Content-Security-Policy", _options.ContentSecurityPolicy);
        }

        if (!string.IsNullOrEmpty(_options.StrictTransportSecurity) && context.Request.IsHttps && !headers.ContainsKey("Strict-Transport-Security"))
        {
            headers.Append("Strict-Transport-Security", _options.StrictTransportSecurity);
        }

        if (!string.IsNullOrEmpty(_options.XContentTypeOptions) && !headers.ContainsKey("X-Content-Type-Options"))
        {
            headers.Append("X-Content-Type-Options", _options.XContentTypeOptions);
        }

        if (!string.IsNullOrEmpty(_options.XFrameOptions) && !headers.ContainsKey("X-Frame-Options"))
        {
            headers.Append("X-Frame-Options", _options.XFrameOptions);
        }

        if (!string.IsNullOrEmpty(_options.ReferrerPolicy) && !headers.ContainsKey("Referrer-Policy"))
        {
            headers.Append("Referrer-Policy", _options.ReferrerPolicy);
        }

        if (!string.IsNullOrEmpty(_options.PermissionsPolicy) && !headers.ContainsKey("Permissions-Policy"))
        {
            headers.Append("Permissions-Policy", _options.PermissionsPolicy);
        }

        if (!string.IsNullOrEmpty(_options.XPermittedCrossDomainPolicies) && !headers.ContainsKey("X-Permitted-Cross-Domain-Policies"))
        {
            headers.Append("X-Permitted-Cross-Domain-Policies", _options.XPermittedCrossDomainPolicies);
        }
    }
}
