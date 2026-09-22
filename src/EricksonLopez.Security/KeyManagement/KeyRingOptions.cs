// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.KeyManagement;

using System;

/// <summary>
/// Specifies configuration options for <see cref="KeyRing"/> instance-level caching and lifecycle behaviors.
/// </summary>
public sealed class KeyRingOptions
{
    /// <summary>
    /// Initializes a new instance of the <see cref="KeyRingOptions"/> class.
    /// </summary>
    public KeyRingOptions()
    {
    }

    /// <summary>
    /// Gets or sets the time-to-live for in-memory cached cryptographic keys.
    /// Defaults to 30 seconds to minimize plaintext exposure in memory dumps.
    /// Set to <see cref="TimeSpan.Zero"/> to disable caching.
    /// </summary>
    public TimeSpan CacheTtl { get; set; } = TimeSpan.FromSeconds(30);
}
