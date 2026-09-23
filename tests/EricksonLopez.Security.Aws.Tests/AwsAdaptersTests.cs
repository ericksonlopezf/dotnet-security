// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Aws.Tests;

using System;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Amazon;
using Amazon.KeyManagementService;
using Amazon.KeyManagementService.Model;
using Amazon.Runtime;
using Amazon.SecretsManager;
using Amazon.SecretsManager.Model;
using AwesomeAssertions;
using EricksonLopez.Security.Abstractions.Errors;
using EricksonLopez.Security.Abstractions.KeyManagement;
using EricksonLopez.Security.Abstractions.Primitives;
using EricksonLopez.Security.Abstractions.Secrets;
using EricksonLopez.Security.Aws;
using EricksonLopez.Security.Memory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using NSubstitute;
using NSubstitute.ExceptionExtensions;
using Xunit;
using KeyMetadata = EricksonLopez.Security.Abstractions.Primitives.KeyMetadata;

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
        var exSecret = Assert.Throws<InvalidOperationException>(() => new AwsSecretsManagerSecretStore(defaultOptions));
        exSecret.Message.Should().Be("AwsSecretsManagerSecretStore requires configured Credentials, a pre-configured SecretsManagerClient, or EnableDevelopmentInMemoryStub = true for testing environments.");

        var exKey = Assert.Throws<InvalidOperationException>(() => new AwsKmsKeyStore(defaultOptions));
        exKey.Message.Should().Be("AwsKmsKeyStore requires configured KmsKeyId, Credentials, pre-configured clients, or EnableDevelopmentInMemoryStub = true for testing environments.");

        var emptyOptions = Options.Create(new AwsSecurityOptions { KmsKeyId = "", SecretPrefix = "" });
        Assert.Throws<InvalidOperationException>(() => new AwsSecretsManagerSecretStore(emptyOptions));
        Assert.Throws<InvalidOperationException>(() => new AwsKmsKeyStore(emptyOptions));

        var whitespaceOptions = Options.Create(new AwsSecurityOptions { KmsKeyId = "   ", SecretPrefix = "   " });
        Assert.Throws<InvalidOperationException>(() => new AwsSecretsManagerSecretStore(whitespaceOptions));
        Assert.Throws<InvalidOperationException>(() => new AwsKmsKeyStore(whitespaceOptions));

        // When KmsKeyId is valid, AwsKmsKeyStore initializes without throwing
        using var validKeyStore = new AwsKmsKeyStore(Options.Create(new AwsSecurityOptions { KmsKeyId = "arn:aws:kms:us-east-1:123456789012:key/test" }));
        validKeyStore.Should().NotBeNull();

        // When SecretPrefix is valid, AwsSecretsManagerSecretStore initializes without throwing
        using var validSecretStore = new AwsSecretsManagerSecretStore(Options.Create(new AwsSecurityOptions { SecretPrefix = "app/" }));
        validSecretStore.Should().NotBeNull();

        // When Credentials are valid, both initialize without throwing
        var creds = new BasicAWSCredentials("testAccess", "testSecret");
        using var credKeyStore = new AwsKmsKeyStore(Options.Create(new AwsSecurityOptions { Credentials = creds }));
        using var credSecretStore = new AwsSecretsManagerSecretStore(Options.Create(new AwsSecurityOptions { Credentials = creds }));
        credKeyStore.Should().NotBeNull();
        credSecretStore.Should().NotBeNull();

        // When pre-configured clients are provided, both initialize without throwing
        var kmsMock = Substitute.For<IAmazonKeyManagementService>();
        var secretsMock = Substitute.For<IAmazonSecretsManager>();
        using var clientKeyStore = new AwsKmsKeyStore(Options.Create(new AwsSecurityOptions { KmsClient = kmsMock, SecretsManagerClient = secretsMock }));
        using var clientSecretStore = new AwsSecretsManagerSecretStore(Options.Create(new AwsSecurityOptions { SecretsManagerClient = secretsMock }));
        clientKeyStore.Should().NotBeNull();
        clientSecretStore.Should().NotBeNull();

        // Single KmsClient provided without SecretsManagerClient
        using var singleKmsStore = new AwsKmsKeyStore(Options.Create(new AwsSecurityOptions { KmsClient = kmsMock }));
        singleKmsStore.Should().NotBeNull();

        // Single SecretsManagerClient provided without KmsClient
        using var singleSecretsStore = new AwsKmsKeyStore(Options.Create(new AwsSecurityOptions { SecretsManagerClient = secretsMock }));
        singleSecretsStore.Should().NotBeNull();
    }

    [Fact]
    public void Aws_Constructors_NullArgumentChecks()
    {
        var stubOptions = CreateOptions();
        var liveOptions = Options.Create(new AwsSecurityOptions { KmsKeyId = "test-key", SecretPrefix = "test/" });

        var exKeyOpt = Assert.Throws<ArgumentNullException>("options", () => new AwsKmsKeyStore(null!, Microsoft.Extensions.Logging.Abstractions.NullLogger<AwsKmsKeyStore>.Instance));
        exKeyOpt.ParamName.Should().Be("options");

        var exKeyLog1 = Assert.Throws<ArgumentNullException>("logger", () => new AwsKmsKeyStore(stubOptions, null!));
        exKeyLog1.ParamName.Should().Be("logger");

        var exKeyLog2 = Assert.Throws<ArgumentNullException>("logger", () => new AwsKmsKeyStore(liveOptions, null!));
        exKeyLog2.ParamName.Should().Be("logger");

        var exSecOpt = Assert.Throws<ArgumentNullException>("options", () => new AwsSecretsManagerSecretStore(null!, Microsoft.Extensions.Logging.Abstractions.NullLogger<AwsSecretsManagerSecretStore>.Instance));
        exSecOpt.ParamName.Should().Be("options");

        var exSecLog1 = Assert.Throws<ArgumentNullException>("logger", () => new AwsSecretsManagerSecretStore(stubOptions, null!));
        exSecLog1.ParamName.Should().Be("logger");

        var exSecLog2 = Assert.Throws<ArgumentNullException>("logger", () => new AwsSecretsManagerSecretStore(liveOptions, null!));
        exSecLog2.ParamName.Should().Be("logger");
    }

    [Fact]
    public void AddAwsSecurity_RegistersServicesAndValidatesNullArguments()
    {
        IServiceCollection nullServices = null!;
        var exNull1 = Assert.Throws<ArgumentNullException>("services", () => nullServices.AddAwsSecurity());
        exNull1.ParamName.Should().Be("services");

        var exNull2 = Assert.Throws<ArgumentNullException>("services", () => nullServices.AddAwsSecurity(_ => { }));
        exNull2.ParamName.Should().Be("services");
        exNull2.StackTrace.Should().NotContain("OptionsServiceCollectionExtensions");

        var exNull3 = Assert.Throws<ArgumentNullException>("configure", () => new ServiceCollection().AddAwsSecurity(null!));
        exNull3.ParamName.Should().Be("configure");

        var services = new ServiceCollection();
        services.AddSingleton(typeof(Microsoft.Extensions.Logging.ILogger<>), typeof(Microsoft.Extensions.Logging.Abstractions.NullLogger<>));
        services.AddAwsSecurity(o => o.EnableDevelopmentInMemoryStub = true);

        using var provider = services.BuildServiceProvider();
        var keyStore = provider.GetRequiredService<IKeyStore>();
        var secretStore = provider.GetRequiredService<ISecretStore>();

        keyStore.Should().NotBeNull().And.BeOfType<AwsKmsKeyStore>();
        secretStore.Should().NotBeNull().And.BeOfType<AwsSecretsManagerSecretStore>();

        var defaultServices = new ServiceCollection();
        defaultServices.AddSingleton(typeof(Microsoft.Extensions.Logging.ILogger<>), typeof(Microsoft.Extensions.Logging.Abstractions.NullLogger<>));
        defaultServices.AddAwsSecurity();
        using var defaultProvider = defaultServices.BuildServiceProvider();
        defaultProvider.GetRequiredService<IOptions<AwsSecurityOptions>>().Value.Region.Should().Be("us-east-1");
    }

    [Fact]
    public async Task Aws_Stores_Dispose_ClearsResources()
    {
        var options = CreateOptions();
        var keyStore = new AwsKmsKeyStore(options);
        var secretStore = new AwsSecretsManagerSecretStore(options);

        var keyId = KeyIdentifier.Prefixed("aws-disp");
        var version = KeyVersion.Initial;
        var metadata = new KeyMetadata(keyId, version, KeyPurpose.Encryption, KeyStatus.Active, "AES-256", DateTimeOffset.UtcNow);
        var key = new CryptographicKey(metadata, SecretBuffer.CreateRandom(32));

        var saveResult = await keyStore.SaveKeyAsync(key);
        saveResult.IsSuccess.Should().BeTrue();

        keyStore.Dispose();
        secretStore.Dispose();

        // Calling Dispose multiple times should be safe
        keyStore.Dispose();
        secretStore.Dispose();

        // Stored in-memory keys are cleared upon disposal
        var getAfterDispose = await keyStore.GetKeyAsync(keyId, version);
        getAfterDispose.IsFailure.Should().BeTrue();
        getAfterDispose.Error.Code.Should().Be("Security.KeyNotFound");
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

    [Fact]
    public async Task AwsSecretsManagerSecretStore_LiveClient_GetSecret_SuccessAndFailures()
    {
        var secretsMock = Substitute.For<IAmazonSecretsManager>();
        var options = Options.Create(new AwsSecurityOptions
        {
            SecretPrefix = "app/",
            SecretsManagerClient = secretsMock
        });
        using var store = new AwsSecretsManagerSecretStore(options);

        // Success
        secretsMock.GetSecretValueAsync(
            Arg.Is<GetSecretValueRequest>(r => r.SecretId == "app/db-password"),
            Arg.Any<CancellationToken>())
            .Returns(new GetSecretValueResponse { SecretString = "super-secret-db-pass" });

        var success = await store.GetSecretAsync("db-password");
        success.IsSuccess.Should().BeTrue();
        success.Value.UnsafeValue.Should().Be("super-secret-db-pass");

        // Success with null SecretString
        secretsMock.GetSecretValueAsync(
            Arg.Is<GetSecretValueRequest>(r => r.SecretId == "app/empty-secret"),
            Arg.Any<CancellationToken>())
            .Returns(new GetSecretValueResponse { SecretString = null });

        var emptySuccess = await store.GetSecretAsync("empty-secret");
        emptySuccess.IsSuccess.Should().BeTrue();
        emptySuccess.Value.UnsafeValue.Should().Be(string.Empty);

        // ResourceNotFoundException
        secretsMock.GetSecretValueAsync(
            Arg.Is<GetSecretValueRequest>(r => r.SecretId == "app/missing"),
            Arg.Any<CancellationToken>())
            .Throws(new ResourceNotFoundException("Secret not found"));

        var notFound = await store.GetSecretAsync("missing");
        notFound.IsFailure.Should().BeTrue();
        notFound.Error.Code.Should().Be("Security.SecretNotFound");

        // AmazonSecretsManagerException
        secretsMock.GetSecretValueAsync(
            Arg.Is<GetSecretValueRequest>(r => r.SecretId == "app/error"),
            Arg.Any<CancellationToken>())
            .Throws(new AmazonSecretsManagerException("Access denied"));

        var error = await store.GetSecretAsync("error");
        error.IsFailure.Should().BeTrue();
        error.Error.Description.Should().Contain("AWS Secrets Manager request failed: Access denied");
    }

    [Fact]
    public async Task AwsSecretsManagerSecretStore_LiveClient_SetSecret_SuccessAndFailures()
    {
        var secretsMock = Substitute.For<IAmazonSecretsManager>();
        var options = Options.Create(new AwsSecurityOptions
        {
            SecretPrefix = "app/",
            SecretsManagerClient = secretsMock
        });
        using var store = new AwsSecretsManagerSecretStore(options);

        // Existing secret update success
        secretsMock.PutSecretValueAsync(
            Arg.Is<PutSecretValueRequest>(r => r.SecretId == "app/existing" && r.SecretString == "new-val"),
            Arg.Any<CancellationToken>())
            .Returns(new PutSecretValueResponse());

        var updateSuccess = await store.SetSecretAsync("existing", "new-val");
        updateSuccess.IsSuccess.Should().BeTrue();

        // PutSecretValue throws ResourceNotFoundException -> falls back to CreateSecretAsync success
        secretsMock.PutSecretValueAsync(
            Arg.Is<PutSecretValueRequest>(r => r.SecretId == "app/new-secret"),
            Arg.Any<CancellationToken>())
            .Throws(new ResourceNotFoundException("Secret does not exist"));

        secretsMock.CreateSecretAsync(
            Arg.Is<CreateSecretRequest>(r => r.Name == "app/new-secret" && r.SecretString == "initial-val"),
            Arg.Any<CancellationToken>())
            .Returns(new CreateSecretResponse());

        var createSuccess = await store.SetSecretAsync("new-secret", "initial-val");
        createSuccess.IsSuccess.Should().BeTrue();

        // CreateSecretAsync throws AmazonSecretsManagerException
        secretsMock.PutSecretValueAsync(
            Arg.Is<PutSecretValueRequest>(r => r.SecretId == "app/fail-create"),
            Arg.Any<CancellationToken>())
            .Throws(new ResourceNotFoundException("Secret does not exist"));

        secretsMock.CreateSecretAsync(
            Arg.Is<CreateSecretRequest>(r => r.Name == "app/fail-create"),
            Arg.Any<CancellationToken>())
            .Throws(new AmazonSecretsManagerException("Quota exceeded"));

        var createFail = await store.SetSecretAsync("fail-create", "val");
        createFail.IsFailure.Should().BeTrue();
        createFail.Error.Description.Should().Contain("AWS Secrets Manager create failed: Quota exceeded");

        // PutSecretValueAsync throws direct AmazonSecretsManagerException
        secretsMock.PutSecretValueAsync(
            Arg.Is<PutSecretValueRequest>(r => r.SecretId == "app/fail-put"),
            Arg.Any<CancellationToken>())
            .Throws(new AmazonSecretsManagerException("Internal error"));

        var putFail = await store.SetSecretAsync("fail-put", "val");
        putFail.IsFailure.Should().BeTrue();
        putFail.Error.Description.Should().Contain("AWS Secrets Manager update failed: Internal error");
    }

    [Fact]
    public void AwsSecretsManagerSecretStore_LiveClient_Disposal_Behavior()
    {
        var secretsMock = Substitute.For<IAmazonSecretsManager>();
        var unownedOptions = Options.Create(new AwsSecurityOptions
        {
            SecretsManagerClient = secretsMock
        });
        var unownedStore = new AwsSecretsManagerSecretStore(unownedOptions);
        unownedStore.Dispose();
        secretsMock.DidNotReceive().Dispose();

        var ownedOptions = Options.Create(new AwsSecurityOptions
        {
            SecretPrefix = "test/"
        });
        var ownedStore = new AwsSecretsManagerSecretStore(ownedOptions);
        ownedStore.Dispose();
        // Multiple disposals should be safe
        ownedStore.Dispose();
    }

    [Fact]
    public async Task AwsKmsKeyStore_LiveClient_SaveKey_SuccessAndFailures()
    {
        var kmsMock = Substitute.For<IAmazonKeyManagementService>();
        var secretsMock = Substitute.For<IAmazonSecretsManager>();
        var options = Options.Create(new AwsSecurityOptions
        {
            KmsKeyId = "arn:aws:kms:us-east-1:12345:key/xyz",
            SecretPrefix = "app/",
            KmsClient = kmsMock,
            SecretsManagerClient = secretsMock
        });
        using var store = new AwsKmsKeyStore(options);

        var keyId = KeyIdentifier.Prefixed("enc");
        var version = KeyVersion.Initial;
        var now = DateTimeOffset.UtcNow;
        var metadata = new KeyMetadata(keyId, version, KeyPurpose.Encryption, KeyStatus.Active, "AES-256-GCM", now, now.AddDays(30), now.AddDays(60));
        var key = new CryptographicKey(metadata, SecretBuffer.CreateRandom(32));

        kmsMock.EncryptAsync(
            Arg.Any<EncryptRequest>(),
            Arg.Any<CancellationToken>())
            .Returns(new EncryptResponse { CiphertextBlob = new MemoryStream(new byte[] { 11, 22, 33 }) });

        string? capturedSecretString = null;
        secretsMock.PutSecretValueAsync(
            Arg.Do<PutSecretValueRequest>(r => capturedSecretString = r.SecretString),
            Arg.Any<CancellationToken>())
            .Returns(new PutSecretValueResponse());

        var result = await store.SaveKeyAsync(key);
        result.IsSuccess.Should().BeTrue();
        capturedSecretString.Should().NotBeNull();
        capturedSecretString.Should().Contain("expires_at");
        capturedSecretString.Should().Contain("revoked_at");
        capturedSecretString.Should().Contain("key_bytes");

        // Save key without optional expires_at and revoked_at
        var simpleMeta = new KeyMetadata(keyId, new KeyVersion(2), KeyPurpose.Signing, KeyStatus.Active, "HMAC-SHA256", now);
        var simpleKey = new CryptographicKey(simpleMeta, SecretBuffer.CreateRandom(32));
        string? simpleCaptured = null;
        secretsMock.PutSecretValueAsync(
            Arg.Do<PutSecretValueRequest>(r => simpleCaptured = r.SecretString),
            Arg.Any<CancellationToken>())
            .Returns(new PutSecretValueResponse());

        var simpleResult = await store.SaveKeyAsync(simpleKey);
        simpleResult.IsSuccess.Should().BeTrue();
        simpleCaptured.Should().NotBeNull();
        simpleCaptured.Should().NotContain("expires_at");
        simpleCaptured.Should().NotContain("revoked_at");

        // Put throws ResourceNotFoundException -> fallback CreateSecretAsync success
        var keyV3 = new CryptographicKey(new KeyMetadata(keyId, new KeyVersion(3), KeyPurpose.Encryption, KeyStatus.Active, "AES-256", now), SecretBuffer.CreateRandom(32));
        secretsMock.PutSecretValueAsync(
            Arg.Is<PutSecretValueRequest>(r => r.SecretId.Contains("v3")),
            Arg.Any<CancellationToken>())
            .Throws(new ResourceNotFoundException("Not found"));

        CreateSecretRequest? capturedCreate = null;
        secretsMock.CreateSecretAsync(
            Arg.Do<CreateSecretRequest>(r => capturedCreate = r),
            Arg.Any<CancellationToken>())
            .Returns(new CreateSecretResponse());

        var createResult = await store.SaveKeyAsync(keyV3);
        createResult.IsSuccess.Should().BeTrue();
        capturedCreate.Should().NotBeNull();
        capturedCreate!.KmsKeyId.Should().Be("arn:aws:kms:us-east-1:12345:key/xyz");

        // Test with empty KmsKeyId options -> CreateSecretRequest.KmsKeyId is null
        var noKmsIdOptions = Options.Create(new AwsSecurityOptions
        {
            KmsKeyId = null,
            SecretPrefix = "app/",
            KmsClient = kmsMock,
            SecretsManagerClient = secretsMock
        });
        using var noKmsStore = new AwsKmsKeyStore(noKmsIdOptions);
        CreateSecretRequest? capturedCreateNoKms = null;
        secretsMock.CreateSecretAsync(
            Arg.Do<CreateSecretRequest>(r => capturedCreateNoKms = r),
            Arg.Any<CancellationToken>())
            .Returns(new CreateSecretResponse());

        var createNoKmsResult = await noKmsStore.SaveKeyAsync(keyV3);
        createNoKmsResult.IsSuccess.Should().BeTrue();
        capturedCreateNoKms.Should().NotBeNull();
        capturedCreateNoKms!.KmsKeyId.Should().BeNull();

        // CreateSecretAsync throws AmazonSecretsManagerException
        secretsMock.CreateSecretAsync(
            Arg.Any<CreateSecretRequest>(),
            Arg.Any<CancellationToken>())
            .Throws(new AmazonSecretsManagerException("Create failed"));

        var createFailResult = await store.SaveKeyAsync(keyV3);
        createFailResult.IsFailure.Should().BeTrue();
        createFailResult.Error.Description.Should().Contain("AWS Secrets Manager create failed: Create failed");

        // PutSecretValueAsync throws direct AmazonSecretsManagerException
        secretsMock.PutSecretValueAsync(
            Arg.Any<PutSecretValueRequest>(),
            Arg.Any<CancellationToken>())
            .Throws(new AmazonSecretsManagerException("Put failed"));

        var putFailResult = await store.SaveKeyAsync(key);
        putFailResult.IsFailure.Should().BeTrue();
        putFailResult.Error.Description.Should().Contain("AWS Secrets Manager save failed: Put failed");
    }

    [Fact]
    public async Task AwsKmsKeyStore_LiveClient_GetKey_SuccessAndFailures()
    {
        var kmsMock = Substitute.For<IAmazonKeyManagementService>();
        var secretsMock = Substitute.For<IAmazonSecretsManager>();
        var options = Options.Create(new AwsSecurityOptions
        {
            KmsKeyId = "arn:aws:kms:us-east-1:12345:key/xyz",
            SecretPrefix = "app/",
            KmsClient = kmsMock,
            SecretsManagerClient = secretsMock
        });
        using var store = new AwsKmsKeyStore(options);

        var keyId = KeyIdentifier.Prefixed("lookup");
        var version = KeyVersion.Initial;
        var encryptedBlob = new byte[] { 101, 102, 103 };
        var decryptedPlaintext = new byte[32];
        decryptedPlaintext[0] = 42;

        var jsonRecord = JsonSerializer.Serialize(new
        {
            key_bytes = Convert.ToBase64String(encryptedBlob),
            key_id = keyId.Value,
            version = "1"
        });

        secretsMock.GetSecretValueAsync(
            Arg.Is<GetSecretValueRequest>(r => r.SecretId.Contains("lookup")),
            Arg.Any<CancellationToken>())
            .Returns(new GetSecretValueResponse { SecretString = jsonRecord });

        kmsMock.DecryptAsync(
            Arg.Any<DecryptRequest>(),
            Arg.Any<CancellationToken>())
            .Returns(new DecryptResponse { Plaintext = new MemoryStream(decryptedPlaintext) });

        var result = await store.GetKeyAsync(keyId, version);
        result.IsSuccess.Should().BeTrue();
        result.Value.GetKeyBytes()[0].Should().Be(42);

        // GetSecretValue returns null/whitespace SecretString
        secretsMock.GetSecretValueAsync(
            Arg.Is<GetSecretValueRequest>(r => r.SecretId.Contains("empty")),
            Arg.Any<CancellationToken>())
            .Returns(new GetSecretValueResponse { SecretString = "   " });

        var emptyResult = await store.GetKeyAsync(KeyIdentifier.Prefixed("empty"), version);
        emptyResult.IsFailure.Should().BeTrue();
        emptyResult.Error.Code.Should().Be("Security.KeyNotFound");

        // Exception thrown during KMS decrypt
        kmsMock.DecryptAsync(
            Arg.Any<DecryptRequest>(),
            Arg.Any<CancellationToken>())
            .Throws(new AmazonKeyManagementServiceException("KMS decrypt denied"));

        var decryptFail = await store.GetKeyAsync(keyId, version);
        decryptFail.IsFailure.Should().BeTrue();
        decryptFail.Error.Description.Should().Contain("AWS retrieve/decrypt failed: KMS decrypt denied");
    }

    [Fact]
    public async Task AwsKmsKeyStore_LiveClient_ListMetadata_ReturnsEmpty()
    {
        var kmsMock = Substitute.For<IAmazonKeyManagementService>();
        var secretsMock = Substitute.For<IAmazonSecretsManager>();
        var options = Options.Create(new AwsSecurityOptions
        {
            KmsClient = kmsMock,
            SecretsManagerClient = secretsMock
        });
        using var store = new AwsKmsKeyStore(options);

        var listResult = await store.ListMetadataAsync();
        listResult.IsSuccess.Should().BeTrue();
        listResult.Value.Should().BeEmpty();
    }

    [Fact]
    public async Task AwsKmsKeyStore_LiveClient_UpdateStatus_SuccessAndFailures()
    {
        var kmsMock = Substitute.For<IAmazonKeyManagementService>();
        var secretsMock = Substitute.For<IAmazonSecretsManager>();
        var options = Options.Create(new AwsSecurityOptions
        {
            KmsKeyId = "arn:aws:kms:us-east-1:12345:key/xyz",
            SecretPrefix = "app/",
            KmsClient = kmsMock,
            SecretsManagerClient = secretsMock
        });
        using var store = new AwsKmsKeyStore(options);

        var keyId = KeyIdentifier.Prefixed("status-test");
        var version = KeyVersion.Initial;
        var encryptedBlob = new byte[] { 101, 102, 103 };
        var decryptedPlaintext = new byte[32];

        var jsonRecord = JsonSerializer.Serialize(new
        {
            key_bytes = Convert.ToBase64String(encryptedBlob),
            key_id = keyId.Value,
            version = "1"
        });

        secretsMock.GetSecretValueAsync(
            Arg.Any<GetSecretValueRequest>(),
            Arg.Any<CancellationToken>())
            .Returns(new GetSecretValueResponse { SecretString = jsonRecord });

        kmsMock.DecryptAsync(
            Arg.Any<DecryptRequest>(),
            Arg.Any<CancellationToken>())
            .Returns(new DecryptResponse { Plaintext = new MemoryStream(decryptedPlaintext) });

        string? capturedPut = null;
        secretsMock.PutSecretValueAsync(
            Arg.Do<PutSecretValueRequest>(r => capturedPut = r.SecretString),
            Arg.Any<CancellationToken>())
            .Returns(new PutSecretValueResponse());

        // Update to Revoked -> sets RevokedAtUtc
        var revokeResult = await store.UpdateStatusAsync(keyId, version, KeyStatus.Revoked);
        revokeResult.IsSuccess.Should().BeTrue();
        capturedPut.Should().NotBeNull();
        capturedPut.Should().Contain("Revoked");
        capturedPut.Should().Contain("revoked_at");

        // Update to Active -> does not add revoked_at if original didn't have it
        capturedPut = null;
        var activeResult = await store.UpdateStatusAsync(keyId, version, KeyStatus.Active);
        activeResult.IsSuccess.Should().BeTrue();
        capturedPut.Should().NotBeNull();
        capturedPut.Should().Contain("Active");
        capturedPut.Should().NotContain("revoked_at");

        // When GetKeyAsync fails, returns error directly
        secretsMock.GetSecretValueAsync(
            Arg.Is<GetSecretValueRequest>(r => r.SecretId.Contains("missing")),
            Arg.Any<CancellationToken>())
            .Returns(new GetSecretValueResponse { SecretString = null });

        var notFoundUpdate = await store.UpdateStatusAsync(KeyIdentifier.Prefixed("missing"), version, KeyStatus.Retired);
        notFoundUpdate.IsFailure.Should().BeTrue();

        // PutSecretValue throws AmazonSecretsManagerException
        secretsMock.PutSecretValueAsync(
            Arg.Any<PutSecretValueRequest>(),
            Arg.Any<CancellationToken>())
            .Throws(new AmazonSecretsManagerException("Update write failed"));

        var putFailUpdate = await store.UpdateStatusAsync(keyId, version, KeyStatus.Retired);
        putFailUpdate.IsFailure.Should().BeTrue();
        putFailUpdate.Error.Description.Should().Contain("AWS Secrets Manager update failed: Update write failed");
    }

    [Fact]
    public void AwsKmsKeyStore_LiveClient_Disposal_Behavior()
    {
        var kmsMock = Substitute.For<IAmazonKeyManagementService>();
        var secretsMock = Substitute.For<IAmazonSecretsManager>();
        var unownedOptions = Options.Create(new AwsSecurityOptions
        {
            KmsClient = kmsMock,
            SecretsManagerClient = secretsMock
        });
        var unownedStore = new AwsKmsKeyStore(unownedOptions);
        unownedStore.Dispose();
        kmsMock.DidNotReceive().Dispose();
        secretsMock.DidNotReceive().Dispose();

        var ownedOptions = Options.Create(new AwsSecurityOptions
        {
            KmsKeyId = "arn:aws:kms:us-east-1:12345:key/test"
        });
        var ownedStore = new AwsKmsKeyStore(ownedOptions);
        ownedStore.Dispose();
        ownedStore.Dispose();
    }
}
