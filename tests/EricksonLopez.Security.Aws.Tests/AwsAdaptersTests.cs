// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Aws.Tests;

using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using AwesomeAssertions;
using EricksonLopez.Security.Abstractions.Errors;
using EricksonLopez.Security.Abstractions.KeyManagement;
using EricksonLopez.Security.Abstractions.Primitives;
using EricksonLopez.Security.Abstractions.Secrets;
using EricksonLopez.Security.Aws;
using EricksonLopez.Security.Memory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Xunit;

public sealed class AwsAdaptersTests
{
    private static IOptions<AwsSecurityOptions> CreateOptions(Action<AwsSecurityOptions>? configure = null)
    {
        var options = new AwsSecurityOptions { EnableDevelopmentInMemoryStub = true };
        configure?.Invoke(options);
        return Options.Create(options);
    }

    [Fact]
    public void AwsSecurityOptions_PropertiesGetAndSet()
    {
        var options = new AwsSecurityOptions();
        options.Region.Should().Be("us-east-1");
        options.KmsKeyId.Should().BeNull();
        options.SecretPrefix.Should().Be(string.Empty);
        options.EnableDevelopmentInMemoryStub.Should().BeFalse();
        options.Credentials.Should().BeNull();
        options.SecretsManagerClient.Should().BeNull();
        options.KmsClient.Should().BeNull();

        options.Region = "eu-west-1";
        options.KmsKeyId = "arn:aws:kms:eu-west-1:12345:key/xyz";
        options.SecretPrefix = "app/";
        options.EnableDevelopmentInMemoryStub = true;
        options.Credentials = null;
        options.SecretsManagerClient = null;
        options.KmsClient = null;

        options.Region.Should().Be("eu-west-1");
        options.KmsKeyId.Should().Be("arn:aws:kms:eu-west-1:12345:key/xyz");
        options.SecretPrefix.Should().Be("app/");
        options.EnableDevelopmentInMemoryStub.Should().BeTrue();
        options.Credentials.Should().BeNull();
        options.SecretsManagerClient.Should().BeNull();
        options.KmsClient.Should().BeNull();
    }

    [Fact]
    public void Aws_DefaultOptions_ThrowsInvalidOperationException_WhenStubNotEnabled()
    {
        var defaultOptions = Options.Create(new AwsSecurityOptions());
        Assert.Throws<InvalidOperationException>(() => new AwsSecretsManagerSecretStore(defaultOptions));
        Assert.Throws<InvalidOperationException>(() => new AwsKmsKeyStore(defaultOptions));
    }

    [Fact]
    public async Task AwsSecretsManagerSecretStore_SetAndGetSecret_RoundtripsSuccessfully()
    {
        var options = CreateOptions(o => o.SecretPrefix = "prod/");
        var secretStore = new AwsSecretsManagerSecretStore(options);

        var setResult1 = await secretStore.SetSecretAsync("StripeApiKey", "sk_live_aws_secret_key_123");
        setResult1.IsSuccess.Should().BeTrue();

        var setResult2 = await secretStore.SetSecretAsync("SendGridApiKey", "SG.aws_secondary_key_456");
        setResult2.IsSuccess.Should().BeTrue();

        var getResult1 = await secretStore.GetSecretAsync("StripeApiKey");
        getResult1.IsSuccess.Should().BeTrue();
        getResult1.Value.UnsafeValue.Should().Be("sk_live_aws_secret_key_123");
        getResult1.Value.ToString().Should().Be("[REDACTED]");

        var getResult2 = await secretStore.GetSecretAsync("SendGridApiKey");
        getResult2.IsSuccess.Should().BeTrue();
        getResult2.Value.UnsafeValue.Should().Be("SG.aws_secondary_key_456");
    }

    [Fact]
    public async Task AwsSecretsManagerSecretStore_InvalidAndMissingSecrets_ReturnFailure()
    {
        var options = CreateOptions();
        var secretStore = new AwsSecretsManagerSecretStore(options);

        var emptyGet1 = await secretStore.GetSecretAsync("");
        emptyGet1.IsFailure.Should().BeTrue();
        emptyGet1.Error.Description.Should().Be("The secret 'Empty secret name.' was not found.");

        var emptyGet2 = await secretStore.GetSecretAsync("   ");
        emptyGet2.IsFailure.Should().BeTrue();
        emptyGet2.Error.Description.Should().Be("The secret 'Empty secret name.' was not found.");

        (await secretStore.GetSecretAsync("missing_secret")).IsFailure.Should().BeTrue();

        var emptySet1 = await secretStore.SetSecretAsync("", "val");
        emptySet1.IsFailure.Should().BeTrue();
        emptySet1.Error.Description.Should().Be("The secret 'Empty secret name.' was not found.");

        var emptySet2 = await secretStore.SetSecretAsync("   ", "val");
        emptySet2.IsFailure.Should().BeTrue();
        emptySet2.Error.Description.Should().Be("The secret 'Empty secret name.' was not found.");
    }

    [Fact]
    public void AwsSecretsManagerSecretStore_NullOptions_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => new AwsSecretsManagerSecretStore(null!));
    }

    [Fact]
    public void AwsKmsKeyStore_NullOptions_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => new AwsKmsKeyStore(null!));
    }

    [Fact]
    public async Task AwsKmsKeyStore_SaveAndRetrieveKey_RoundtripsSuccessfully()
    {
        var options = CreateOptions(o =>
        {
            o.Region = "us-east-1";
            o.KmsKeyId = "arn:aws:kms:us-east-1:123456789012:key/abc";
        });
        var keyStore = new AwsKmsKeyStore(options);

        var keyId = KeyIdentifier.Prefixed("aws");
        var version = KeyVersion.Initial;
        var metadata = new KeyMetadata(keyId, version, KeyPurpose.Encryption, KeyStatus.Active, "AES-256-GCM", DateTimeOffset.UtcNow);
        var buffer = SecretBuffer.CreateRandom(32);
        var key = new CryptographicKey(metadata, buffer);

        // Null key throws
        await Assert.ThrowsAsync<ArgumentNullException>(() => keyStore.SaveKeyAsync(null!).AsTask());

        // Save
        var saveResult = await keyStore.SaveKeyAsync(key);
        saveResult.IsSuccess.Should().BeTrue();

        // Get existing key
        var getResult = await keyStore.GetKeyAsync(keyId, version);
        getResult.IsSuccess.Should().BeTrue();
        getResult.Value.Metadata.KeyId.Should().Be(keyId);
        getResult.Value.Metadata.Version.Should().Be(version);

        // Get missing key
        var missingKeyId = KeyIdentifier.Prefixed("missing");
        var missingResult = await keyStore.GetKeyAsync(missingKeyId, KeyVersion.Initial);
        missingResult.IsFailure.Should().BeTrue();
        missingResult.Error.Description.Should().Contain(missingKeyId.ToString());
        missingResult.Error.Description.Should().Contain(KeyVersion.Initial.ToString());
    }

    [Fact]
    public async Task AwsKmsKeyStore_ListMetadata_FiltersAndSortsCorrectly()
    {
        var options = CreateOptions();
        var keyStore = new AwsKmsKeyStore(options);

        var keyId = KeyIdentifier.Prefixed("aws");
        var v1 = new KeyVersion(1);
        var v2 = new KeyVersion(2);
        var v3 = new KeyVersion(3);

        var m1 = new KeyMetadata(keyId, v1, KeyPurpose.Encryption, KeyStatus.Active, "AES-256", DateTimeOffset.UtcNow);
        var m2 = new KeyMetadata(keyId, v2, KeyPurpose.Signing, KeyStatus.Active, "HMAC-SHA256", DateTimeOffset.UtcNow);
        var m3 = new KeyMetadata(keyId, v3, KeyPurpose.Encryption, KeyStatus.Active, "AES-256", DateTimeOffset.UtcNow);

        await keyStore.SaveKeyAsync(new CryptographicKey(m1, SecretBuffer.CreateRandom(32)));
        await keyStore.SaveKeyAsync(new CryptographicKey(m2, SecretBuffer.CreateRandom(32)));
        await keyStore.SaveKeyAsync(new CryptographicKey(m3, SecretBuffer.CreateRandom(32)));

        // List all
        var allList = (await keyStore.ListMetadataAsync()).Value;
        allList.Should().HaveCount(3);
        allList[0].Version.Value.Should().Be(3);
        allList[1].Version.Value.Should().Be(2);
        allList[2].Version.Value.Should().Be(1);

        // List filtered by Purpose
        var encList = (await keyStore.ListMetadataAsync(KeyPurpose.Encryption)).Value;
        encList.Should().HaveCount(2);
        encList.All(m => m.Purpose == KeyPurpose.Encryption).Should().BeTrue();
    }

    [Fact]
    public async Task AwsKmsKeyStore_UpdateStatus_UpdatesCorrectlyAndSetsRevocationTime()
    {
        var options = CreateOptions();
        var keyStore = new AwsKmsKeyStore(options);

        var keyId = KeyIdentifier.Prefixed("aws");
        var version = KeyVersion.Initial;
        var metadata = new KeyMetadata(keyId, version, KeyPurpose.Encryption, KeyStatus.Active, "AES-256", DateTimeOffset.UtcNow);
        var key = new CryptographicKey(metadata, SecretBuffer.CreateRandom(32));

        await keyStore.SaveKeyAsync(key);

        // Update to Revoked
        var revokeResult = await keyStore.UpdateStatusAsync(keyId, version, KeyStatus.Revoked);
        revokeResult.IsSuccess.Should().BeTrue();

        var revokedKey = (await keyStore.GetKeyAsync(keyId, version)).Value;
        revokedKey.Metadata.Status.Should().Be(KeyStatus.Revoked);
        revokedKey.Metadata.RevokedAtUtc.Should().NotBeNull();

        // Update non-existing key returns failure
        var missingKeyId = KeyIdentifier.Prefixed("missing");
        var missingUpdate = await keyStore.UpdateStatusAsync(missingKeyId, KeyVersion.Initial, KeyStatus.Destroyed);
        missingUpdate.IsFailure.Should().BeTrue();
        missingUpdate.Error.Description.Should().Contain(missingKeyId.ToString());
        missingUpdate.Error.Description.Should().Contain(KeyVersion.Initial.ToString());
    }

    [Fact]
    public void AddAwsSecurity_RegistersServicesInContainer()
    {
        var services = new ServiceCollection();

        services.AddAwsSecurity(options =>
        {
            options.Region = "us-west-2";
            options.KmsKeyId = "alias/my-key";
            options.EnableDevelopmentInMemoryStub = true;
        });

        using var provider = services.BuildServiceProvider();

        provider.GetService<IKeyStore>().Should().NotBeNull();
        provider.GetService<ISecretStore>().Should().NotBeNull();
    }

    [Fact]
    public void AddAwsSecurity_NullArguments_ThrowsArgumentNullException()
    {
        var services = new ServiceCollection();
        Assert.Throws<ArgumentNullException>(() => ((IServiceCollection)null!).AddAwsSecurity(_ => { }));
        Assert.Throws<ArgumentNullException>(() => services.AddAwsSecurity(null!));
    }

    [Fact]
    public async Task AwsKmsKeyStore_UpdateStatus_ToRetired_DoesNotSetRevocationTime()
    {
        var options = CreateOptions();
        var keyStore = new AwsKmsKeyStore(options);

        var keyId = KeyIdentifier.Prefixed("aws");
        var version = KeyVersion.Initial;
        var metadata = new KeyMetadata(keyId, version, KeyPurpose.Encryption, KeyStatus.Active, "AES-256", DateTimeOffset.UtcNow);
        var key = new CryptographicKey(metadata, SecretBuffer.CreateRandom(32));

        await keyStore.SaveKeyAsync(key);

        var retireResult = await keyStore.UpdateStatusAsync(keyId, version, KeyStatus.Retired);
        retireResult.IsSuccess.Should().BeTrue();

        var retiredKey = (await keyStore.GetKeyAsync(keyId, version)).Value;
        retiredKey.Metadata.Status.Should().Be(KeyStatus.Retired);
        retiredKey.Metadata.RevokedAtUtc.Should().BeNull();
    }

    [Fact]
    public async Task AwsSecretsManagerSecretStore_OverwritingExistingSecret_UpdatesSuccessfully()
    {
        var options = CreateOptions();
        var secretStore = new AwsSecretsManagerSecretStore(options);

        await secretStore.SetSecretAsync("Token", "InitialValue");
        var first = await secretStore.GetSecretAsync("Token");
        first.Value.UnsafeValue.Should().Be("InitialValue");

        await secretStore.SetSecretAsync("Token", "UpdatedValue");
        var second = await secretStore.GetSecretAsync("Token");
        second.Value.UnsafeValue.Should().Be("UpdatedValue");
    }

    [Fact]
    public async Task AwsSecretsManagerSecretStore_WithInjectedError_ReturnsFailure()
    {
        var options = CreateOptions();
        var secretStore = new AwsSecretsManagerSecretStore(options);

        // Pre-save secret so it exists
        (await secretStore.SetSecretAsync("secret", "val")).IsSuccess.Should().BeTrue();

        secretStore.InjectedError = SecurityError.InvalidCiphertext("AWS Secrets Manager outage");

        var getResult = await secretStore.GetSecretAsync("secret");
        getResult.IsFailure.Should().BeTrue();
        getResult.Error.Description.Should().Be("AWS Secrets Manager outage");

        var setResult = await secretStore.SetSecretAsync("secret", "new-val");
        setResult.IsFailure.Should().BeTrue();
        setResult.Error.Description.Should().Be("AWS Secrets Manager outage");
    }

    [Fact]
    public async Task AwsKmsKeyStore_WithInjectedError_ReturnsFailure()
    {
        var options = CreateOptions();
        var keyStore = new AwsKmsKeyStore(options);

        var keyId = KeyIdentifier.Prefixed("aws");
        var version = KeyVersion.Initial;
        var metadata = new KeyMetadata(keyId, version, KeyPurpose.Encryption, KeyStatus.Active, "AES-256", DateTimeOffset.UtcNow);
        var key = new CryptographicKey(metadata, SecretBuffer.CreateRandom(32));

        // Pre-save key so it exists in store
        (await keyStore.SaveKeyAsync(key)).IsSuccess.Should().BeTrue();

        keyStore.InjectedError = SecurityError.InvalidCiphertext("AWS KMS throttling");

        var saveResult = await keyStore.SaveKeyAsync(key);
        saveResult.IsFailure.Should().BeTrue();
        saveResult.Error.Description.Should().Be("AWS KMS throttling");

        var getResult = await keyStore.GetKeyAsync(keyId, version);
        getResult.IsFailure.Should().BeTrue();
        getResult.Error.Description.Should().Be("AWS KMS throttling");

        var listResult = await keyStore.ListMetadataAsync();
        listResult.IsFailure.Should().BeTrue();
        listResult.Error.Description.Should().Be("AWS KMS throttling");

        var updateResult = await keyStore.UpdateStatusAsync(keyId, version, KeyStatus.Revoked);
        updateResult.IsFailure.Should().BeTrue();
        updateResult.Error.Description.Should().Be("AWS KMS throttling");
    }

    [Fact]
    public async Task Aws_CancelledToken_ThrowsOperationCanceledException()
    {
        var options = CreateOptions();
        var secretStore = new AwsSecretsManagerSecretStore(options);
        var keyStore = new AwsKmsKeyStore(options);

        using var cts = new CancellationTokenSource();
        cts.Cancel();

        var keyId = KeyIdentifier.Prefixed("aws");
        var version = KeyVersion.Initial;
        var metadata = new KeyMetadata(keyId, version, KeyPurpose.Encryption, KeyStatus.Active, "AES-256", DateTimeOffset.UtcNow);
        var key = new CryptographicKey(metadata, SecretBuffer.CreateRandom(32));

        await Assert.ThrowsAsync<OperationCanceledException>(() => secretStore.GetSecretAsync("test", cts.Token).AsTask());
        await Assert.ThrowsAsync<OperationCanceledException>(() => secretStore.SetSecretAsync("test", "val", cts.Token).AsTask());
        await Assert.ThrowsAsync<OperationCanceledException>(() => keyStore.SaveKeyAsync(key, cts.Token).AsTask());
        await Assert.ThrowsAsync<OperationCanceledException>(() => keyStore.GetKeyAsync(keyId, version, cts.Token).AsTask());
        await Assert.ThrowsAsync<OperationCanceledException>(() => keyStore.ListMetadataAsync(cancellationToken: cts.Token).AsTask());
        await Assert.ThrowsAsync<OperationCanceledException>(() => keyStore.UpdateStatusAsync(keyId, version, KeyStatus.Retired, cts.Token).AsTask());
    }
}
