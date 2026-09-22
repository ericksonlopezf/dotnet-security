// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Azure;

using System;

/// <summary>
/// Specifies configuration options for connecting to Azure Key Vault services.
/// </summary>
public sealed class AzureKeyVaultOptions
{
    /// <summary>
    /// Gets or sets the Azure Key Vault Uri (e.g. "https://my-vault.vault.azure.net/").
    /// </summary>
    public Uri? VaultUri { get; set; }

    /// <summary>
    /// Gets or sets an optional secret prefix for namespace isolation in Key Vault (e.g. "app-").
    /// </summary>
    public string SecretPrefix { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets a value indicating whether to allow running the in-memory development stub.
    /// Default is <see langword="false"/> to prevent accidental stub usage in production.
    /// </summary>
    public bool EnableDevelopmentInMemoryStub { get; set; }

    /// <summary>
    /// Gets or sets the custom Azure <see cref="global::Azure.Core.TokenCredential"/> for authenticating against Azure Key Vault.
    /// </summary>
    /// <remarks>
    /// If not specified, <see cref="global::Azure.Identity.DefaultAzureCredential"/> is used by default when <see cref="VaultUri"/> is provided.
    /// </remarks>
    public global::Azure.Core.TokenCredential? Credential { get; set; }

    /// <summary>
    /// Gets or sets an explicit pre-configured <see cref="global::Azure.Security.KeyVault.Secrets.SecretClient"/> instance.
    /// When set, this instance takes precedence over creating a new client from <see cref="VaultUri"/>.
    /// </summary>
    public global::Azure.Security.KeyVault.Secrets.SecretClient? SecretClient { get; set; }

    /// <summary>
    /// Gets or sets an explicit pre-configured <see cref="global::Azure.Security.KeyVault.Keys.KeyClient"/> instance.
    /// When set, this instance takes precedence over creating a new client from <see cref="VaultUri"/>.
    /// </summary>
    public global::Azure.Security.KeyVault.Keys.KeyClient? KeyClient { get; set; }
}
