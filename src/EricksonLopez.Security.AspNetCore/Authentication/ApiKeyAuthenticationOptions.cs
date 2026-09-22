// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.AspNetCore.Authentication;

using Microsoft.AspNetCore.Authentication;

/// <summary>
/// Specifies configuration options for HTTP API key authentication middleware and extraction.
/// </summary>
public class ApiKeyAuthenticationOptions : AuthenticationSchemeOptions
{
    /// <summary>
    /// Gets or sets the HTTP request header name for passing API keys (default: "X-Api-Key").
    /// </summary>
    public string HeaderName { get; set; } = "X-Api-Key";

    /// <summary>
    /// Gets or sets a value indicating whether requests missing an API key should return 401 Unauthorized immediately.
    /// </summary>
    /// <remarks>
    /// The default value is <see langword="true"/> to enforce secure-by-default behavior.
    /// </remarks>
    public bool RequireApiKey { get; set; } = true;

    /// <summary>
    /// Gets or sets the authentication scheme name (default: "ApiKey").
    /// </summary>
    public string AuthenticationScheme { get; set; } = "ApiKey";
}
