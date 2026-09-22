// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.GoogleCloud;

/// <summary>
/// Specifies configuration options for connecting to Google Cloud KMS (including Cloud HSM) and Secret Manager.
/// </summary>
public sealed class GoogleCloudSecurityOptions
{
    /// <summary>
    /// Gets or sets the Google Cloud project identifier (e.g. "opushydra-prod" or "jeiyelfe26-prod").
    /// </summary>
    public string? ProjectId { get; set; }

    /// <summary>
    /// Gets or sets the Google Cloud KMS location identifier (default: "global", or specific region such as "us-east1").
    /// </summary>
    public string LocationId { get; set; } = "global";

    /// <summary>
    /// Gets or sets the default Google Cloud KMS KeyRing ID (e.g. "signing-keys" or "app-keys").
    /// </summary>
    public string? KeyRingId { get; set; }

    /// <summary>
    /// Gets or sets the Google Cloud KMS CryptoKey ID for envelope encryption of keys stored in Secret Manager.
    /// </summary>
    public string? KmsCryptoKeyId { get; set; }

    /// <summary>
    /// Gets or sets an optional prefix for secret names in Google Cloud Secret Manager for namespace isolation.
    /// </summary>
    public string SecretPrefix { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets a value indicating whether to allow running the in-memory development stub.
    /// </summary>
    /// <remarks>
    /// The default value is <see langword="false"/> to prevent accidental stub usage in production environments.
    /// </remarks>
    public bool EnableDevelopmentInMemoryStub { get; set; }

    /// <summary>
    /// Gets or sets an explicit pre-configured <see cref="Google.Cloud.SecretManager.V1.SecretManagerServiceClient"/> instance.
    /// </summary>
    /// <remarks>
    /// When set, this instance takes precedence over creating a new client.
    /// </remarks>
    public Google.Cloud.SecretManager.V1.SecretManagerServiceClient? SecretManagerClient { get; set; }

    /// <summary>
    /// Gets or sets an explicit pre-configured <see cref="Google.Cloud.Kms.V1.KeyManagementServiceClient"/> instance.
    /// </summary>
    /// <remarks>
    /// When set, this instance takes precedence over creating a new client.
    /// </remarks>
    public Google.Cloud.Kms.V1.KeyManagementServiceClient? KmsClient { get; set; }
}
