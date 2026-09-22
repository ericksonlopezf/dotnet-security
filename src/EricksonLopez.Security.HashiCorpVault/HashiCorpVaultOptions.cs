// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.HashiCorpVault;

using System;

/// <summary>
/// Specifies configuration options for connecting to HashiCorp Vault.
/// </summary>
public sealed class HashiCorpVaultOptions
{
    /// <summary>
    /// Gets or sets the Vault server URL (e.g. "https://vault.internal:8200/").
    /// </summary>
    public Uri? VaultUrl { get; set; }

    /// <summary>
    /// Gets or sets the Transit secrets engine mount path (default: "transit").
    /// </summary>
    public string TransitMountPath { get; set; } = "transit";

    /// <summary>
    /// Gets or sets the KV v2 secrets engine mount path (default: "secret").
    /// </summary>
    public string KvMountPath { get; set; } = "secret";

    /// <summary>
    /// Gets or sets the optional path prefix for secret names.
    /// </summary>
    public string SecretPathPrefix { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets a value indicating whether to allow running the in-memory development stub.
    /// Default is <see langword="false"/> to prevent accidental stub usage in production.
    /// </summary>
    public bool EnableDevelopmentInMemoryStub { get; set; }

    /// <summary>
    /// Gets or sets the static Vault authentication token (sent in the X-Vault-Token header).
    /// </summary>
    public string? Token { get; set; }

    /// <summary>
    /// Gets or sets the AppRole Role ID for automated enterprise service authentication.
    /// </summary>
    public string? RoleId { get; set; }

    /// <summary>
    /// Gets or sets the AppRole Secret ID for automated enterprise service authentication.
    /// </summary>
    public string? SecretId { get; set; }

    /// <summary>
    /// Gets or sets the mount path for AppRole authentication (default: "approle").
    /// </summary>
    public string AppRoleMountPath { get; set; } = "approle";

    /// <summary>
    /// Gets or sets an optional Vault Enterprise namespace (sent in the X-Vault-Namespace header).
    /// </summary>
    public string? Namespace { get; set; }

    /// <summary>
    /// Gets or sets an optional pre-configured <see cref="System.Net.Http.HttpClient"/> instance (e.g., configured with mTLS certificates).
    /// </summary>
    public System.Net.Http.HttpClient? HttpClient { get; set; }
}
