// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.AspNetCore.Headers;

/// <summary>
/// Specifies configuration options for injecting enterprise security response headers.
/// </summary>
public sealed class SecurityHeadersOptions
{
    /// <summary>
    /// Gets or sets the Content-Security-Policy (CSP) header value.
    /// Default: <c>default-src 'self'; frame-ancestors 'none'; object-src 'none'; base-uri 'self';</c>.
    /// </summary>
    public string ContentSecurityPolicy { get; set; } = "default-src 'self'; frame-ancestors 'none'; object-src 'none'; base-uri 'self';";

    /// <summary>
    /// Gets or sets the HTTP Strict Transport Security (HSTS) header value.
    /// Default: <c>max-age=31536000; includeSubDomains; preload</c>.
    /// </summary>
    public string StrictTransportSecurity { get; set; } = "max-age=31536000; includeSubDomains; preload";

    /// <summary>
    /// Gets or sets the X-Content-Type-Options header value.
    /// Default: <c>nosniff</c>.
    /// </summary>
    public string XContentTypeOptions { get; set; } = "nosniff";

    /// <summary>
    /// Gets or sets the X-Frame-Options header value.
    /// Default: <c>DENY</c>.
    /// </summary>
    public string XFrameOptions { get; set; } = "DENY";

    /// <summary>
    /// Gets or sets the Referrer-Policy header value.
    /// Default: <c>strict-origin-when-cross-origin</c>.
    /// </summary>
    public string ReferrerPolicy { get; set; } = "strict-origin-when-cross-origin";

    /// <summary>
    /// Gets or sets the Permissions-Policy header value.
    /// Default: <c>accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()</c>.
    /// </summary>
    public string PermissionsPolicy { get; set; } = "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()";

    /// <summary>
    /// Gets or sets the X-Permitted-Cross-Domain-Policies header value.
    /// Default: <c>none</c>.
    /// </summary>
    public string XPermittedCrossDomainPolicies { get; set; } = "none";
}
