// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Privacy.Hibp.Models;

using System;

/// <summary>
/// Specifies configuration options for the Have I Been Pwned (HIBP) API client and validator.
/// </summary>
public sealed class HibpOptions
{
    /// <summary>
    /// Gets or sets the base URL for the HIBP Pwned Passwords API.
    /// </summary>
    public string BaseUrl { get; set; } = "https://api.pwnedpasswords.com/";

    /// <summary>
    /// Gets or sets the User-Agent header string (mandatory per HIBP API policy).
    /// </summary>
    public string UserAgent { get; set; } = "EricksonLopez-Security-Hibp-Client";

    /// <summary>
    /// Gets or sets a value indicating whether to include the <c>Add-Padding: true</c> HTTP header to protect against side-channel traffic analysis.
    /// </summary>
    public bool AddPadding { get; set; } = true;

    /// <summary>
    /// Gets or sets the HTTP request timeout.
    /// </summary>
    public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(5);

    /// <summary>
    /// Gets or sets the maximum allowable breach count for password validation (0 requires password to be completely unbreached).
    /// </summary>
    public long MaxAllowedBreachCount { get; set; }
}
