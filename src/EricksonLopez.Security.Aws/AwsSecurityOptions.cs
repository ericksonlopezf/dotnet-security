// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Aws;

/// <summary>
/// Specifies configuration options for connecting to AWS Key Management Service (KMS) and Secrets Manager.
/// </summary>
public sealed class AwsSecurityOptions
{
    /// <summary>
    /// Gets or sets the AWS region (e.g. "us-east-1").
    /// </summary>
    public string Region { get; set; } = "us-east-1";

    /// <summary>
    /// Gets or sets the default AWS KMS Master Key ID or ARN.
    /// </summary>
    public string? KmsKeyId { get; set; }

    /// <summary>
    /// Gets or sets an optional secret prefix for namespace isolation (e.g. "prod/").
    /// </summary>
    public string SecretPrefix { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets a value indicating whether to allow running the in-memory development stub.
    /// Default is <see langword="false"/> to prevent accidental stub usage in production.
    /// </summary>
    public bool EnableDevelopmentInMemoryStub { get; set; }

    /// <summary>
    /// Gets or sets optional custom AWS credentials. If not specified, standard AWS credential resolution is used.
    /// </summary>
    public Amazon.Runtime.AWSCredentials? Credentials { get; set; }

    /// <summary>
    /// Gets or sets an explicit pre-configured <see cref="Amazon.SecretsManager.IAmazonSecretsManager"/> instance.
    /// When set, this instance takes precedence over creating a new client.
    /// </summary>
    public Amazon.SecretsManager.IAmazonSecretsManager? SecretsManagerClient { get; set; }

    /// <summary>
    /// Gets or sets an explicit pre-configured <see cref="Amazon.KeyManagementService.IAmazonKeyManagementService"/> instance.
    /// When set, this instance takes precedence over creating a new client.
    /// </summary>
    public Amazon.KeyManagementService.IAmazonKeyManagementService? KmsClient { get; set; }
}
