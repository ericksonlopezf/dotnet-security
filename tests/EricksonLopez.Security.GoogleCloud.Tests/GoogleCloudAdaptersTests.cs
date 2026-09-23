// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.GoogleCloud.Tests;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using AwesomeAssertions;
using EricksonLopez.Security.Abstractions.Errors;
using EricksonLopez.Security.Abstractions.KeyManagement;
using EricksonLopez.Security.Abstractions.Primitives;
using EricksonLopez.Security.Abstractions.Secrets;
using EricksonLopez.Security.GoogleCloud;
using EricksonLopez.Security.Memory;
using Google.Api.Gax.ResourceNames;
using Google.Cloud.Kms.V1;
using Google.Cloud.SecretManager.V1;
using Google.Protobuf;
using Grpc.Core;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using NSubstitute;
using NSubstitute.ExceptionExtensions;
using Xunit;

public sealed class GoogleCloudAdaptersTests
{
    private static IOptions<GoogleCloudSecurityOptions> CreateOptions(Action<GoogleCloudSecurityOptions>? configure = null)
    {
        var options = new GoogleCloudSecurityOptions
        {
            ProjectId = "test-project-123",
            EnableDevelopmentInMemoryStub = true
        };
        configure?.Invoke(options);
        return Options.Create(options);
    }

    [Fact]
    public void GoogleCloudSecurityOptions_DefaultAndCustomValues_GetAndSetExpectedly()
    {
        var options = new GoogleCloudSecurityOptions();
        options.ProjectId.Should().BeNull();
        options.LocationId.Should().Be("global");
        options.KeyRingId.Should().BeNull();
        options.SecretPrefix.Should().BeEmpty();
        options.EnableDevelopmentInMemoryStub.Should().BeFalse();
        options.KmsClient.Should().BeNull();
        options.SecretManagerClient.Should().BeNull();

        options.ProjectId = "my-gcp-project";
        options.LocationId = "us-east1";
        options.KeyRingId = "hsm-ring";
        options.SecretPrefix = "myapp-";
        options.EnableDevelopmentInMemoryStub = true;
        options.KmsClient = null;
        options.SecretManagerClient = null;

        options.ProjectId.Should().Be("my-gcp-project");
        options.LocationId.Should().Be("us-east1");
        options.KeyRingId.Should().Be("hsm-ring");
        options.SecretPrefix.Should().Be("myapp-");
        options.EnableDevelopmentInMemoryStub.Should().BeTrue();
        options.KmsClient.Should().BeNull();
        options.SecretManagerClient.Should().BeNull();
    }

    [Fact]
    public void GoogleCloud_DefaultOptions_ThrowsInvalidOperationException_WhenStubNotEnabled()
    {
        var defaultOptions = Options.Create(new GoogleCloudSecurityOptions());
        var exSecret = Assert.Throws<InvalidOperationException>(() => new GoogleCloudSecretManagerStore(defaultOptions));
        exSecret.Message.Should().Contain("GoogleCloudSecretManagerStore requires configured ProjectId");

        var exKey = Assert.Throws<InvalidOperationException>(() => new GoogleCloudKmsKeyStore(defaultOptions));
        exKey.Message.Should().Contain("GoogleCloudKmsKeyStore requires configured ProjectId");

        var whitespaceOptions = Options.Create(new GoogleCloudSecurityOptions { ProjectId = "   " });
        Assert.Throws<InvalidOperationException>(() => new GoogleCloudSecretManagerStore(whitespaceOptions));
        Assert.Throws<InvalidOperationException>(() => new GoogleCloudKmsKeyStore(whitespaceOptions));
    }

    [Fact]
    public void GoogleCloudSecretStore_NullOptions_ThrowsArgumentNullException()
    {
        var options = CreateOptions();
        Assert.Throws<ArgumentNullException>(() => new GoogleCloudSecretManagerStore(null!));
        Assert.Throws<ArgumentNullException>(() => new GoogleCloudSecretManagerStore(null!, Microsoft.Extensions.Logging.Abstractions.NullLogger<GoogleCloudSecretManagerStore>.Instance));
        Assert.Throws<ArgumentNullException>(() => new GoogleCloudSecretManagerStore(options, null!));
    }

    [Fact]
    public void GoogleCloudKeyStore_NullOptions_ThrowsArgumentNullException()
    {
        var options = CreateOptions();
        Assert.Throws<ArgumentNullException>(() => new GoogleCloudKmsKeyStore(null!));
        Assert.Throws<ArgumentNullException>(() => new GoogleCloudKmsKeyStore(null!, Microsoft.Extensions.Logging.Abstractions.NullLogger<GoogleCloudKmsKeyStore>.Instance));
        Assert.Throws<ArgumentNullException>(() => new GoogleCloudKmsKeyStore(options, null!));
    }

    [Fact]
    public void AddGoogleCloudSecurity_RegistersServicesAndValidatesNullArguments()
    {
        IServiceCollection nullServices = null!;
        Assert.Throws<ArgumentNullException>(() => nullServices.AddGoogleCloudSecurity());
        Assert.Throws<ArgumentNullException>(() => nullServices.AddGoogleCloudSecurity(_ => { }));
        Assert.Throws<ArgumentNullException>(() => new ServiceCollection().AddGoogleCloudSecurity(null!));

        var services = new ServiceCollection();
        services.AddSingleton(typeof(Microsoft.Extensions.Logging.ILogger<>), typeof(Microsoft.Extensions.Logging.Abstractions.NullLogger<>));
        services.AddGoogleCloudSecurity(o => o.EnableDevelopmentInMemoryStub = true);

        using var provider = services.BuildServiceProvider();
        var keyStore = provider.GetRequiredService<IKeyStore>();
        var secretStore = provider.GetRequiredService<ISecretStore>();

        keyStore.Should().NotBeNull().And.BeOfType<GoogleCloudKmsKeyStore>();
        secretStore.Should().NotBeNull().And.BeOfType<GoogleCloudSecretManagerStore>();

        var defaultServices = new ServiceCollection();
        defaultServices.AddSingleton(typeof(Microsoft.Extensions.Logging.ILogger<>), typeof(Microsoft.Extensions.Logging.Abstractions.NullLogger<>));
        defaultServices.AddGoogleCloudSecurity();
        using var defaultProvider = defaultServices.BuildServiceProvider();
        defaultProvider.GetRequiredService<IOptions<GoogleCloudSecurityOptions>>().Value.Should().NotBeNull();
    }

    [Fact]
    public async Task GoogleCloud_Stores_Dispose_ClearsResources()
    {
        var options = CreateOptions();
        var keyStore = new GoogleCloudKmsKeyStore(options);

        var keyId = KeyIdentifier.Prefixed("gcp-disp");
        var version = KeyVersion.Initial;
        var metadata = new KeyMetadata(keyId, version, KeyPurpose.Encryption, KeyStatus.Active, "AES-256", DateTimeOffset.UtcNow);
        var key = new CryptographicKey(metadata, SecretBuffer.CreateRandom(32));

        var saveResult = await keyStore.SaveKeyAsync(key);
        saveResult.IsSuccess.Should().BeTrue();

        keyStore.Dispose();

        // Calling Dispose multiple times should be safe
        keyStore.Dispose();

        // Stored in-memory keys are cleared upon disposal
        var getAfterDispose = await keyStore.GetKeyAsync(keyId, version);
        getAfterDispose.IsFailure.Should().BeTrue();
        getAfterDispose.Error.Code.Should().Be("Security.KeyNotFound");
    }

    [Fact]
    public async Task GoogleCloudSecretStore_SetAndGetSecret_RoundtripsSuccessfully()
    {
        var options = CreateOptions(o => o.SecretPrefix = "gcp-");
        var secretStore = new GoogleCloudSecretManagerStore(options);

        var setResult1 = await secretStore.SetSecretAsync("Database.Password:Production", "SuperGcpSecurePassword2026!");
        setResult1.IsSuccess.Should().BeTrue();

        var setResult2 = await secretStore.SetSecretAsync("OpusHydra:ApiKey", "HydraSecretKey999!");
        setResult2.IsSuccess.Should().BeTrue();

        var getResult1 = await secretStore.GetSecretAsync("Database.Password:Production");
        getResult1.IsSuccess.Should().BeTrue();
        getResult1.Value.UnsafeValue.Should().Be("SuperGcpSecurePassword2026!");
        getResult1.Value.ToString().Should().Be("[REDACTED]");

        var getResult2 = await secretStore.GetSecretAsync("OpusHydra:ApiKey");
        getResult2.IsSuccess.Should().BeTrue();
        getResult2.Value.UnsafeValue.Should().Be("HydraSecretKey999!");
    }

    [Fact]
    public async Task GoogleCloudSecretStore_InvalidAndMissingSecrets_ReturnsFailure()
    {
        var options = CreateOptions();
        var secretStore = new GoogleCloudSecretManagerStore(options);

        var emptyGet1 = await secretStore.GetSecretAsync("");
        emptyGet1.IsFailure.Should().BeTrue();
        emptyGet1.Error.Description.Should().Be("The secret 'Empty secret name.' was not found.");

        var emptyGet2 = await secretStore.GetSecretAsync("   ");
        emptyGet2.IsFailure.Should().BeTrue();
        emptyGet2.Error.Description.Should().Be("The secret 'Empty secret name.' was not found.");

        var missingGet = await secretStore.GetSecretAsync("non_existent_key");
        missingGet.IsFailure.Should().BeTrue();
        missingGet.Error.Description.Should().Contain("non_existent_key");

        var emptySet1 = await secretStore.SetSecretAsync("", "some-val");
        emptySet1.IsFailure.Should().BeTrue();
        emptySet1.Error.Description.Should().Be("The secret 'Empty secret name.' was not found.");

        var emptySet2 = await secretStore.SetSecretAsync("   ", "some-val");
        emptySet2.IsFailure.Should().BeTrue();
        emptySet2.Error.Description.Should().Be("The secret 'Empty secret name.' was not found.");
    }

    [Fact]
    public async Task GoogleCloudSecretStore_OverwritingExistingSecret_UpdatesValueSuccessfully()
    {
        var options = CreateOptions(o => o.ProjectId = "gcp-prod-1");
        var secretStore = new GoogleCloudSecretManagerStore(options);

        await secretStore.SetSecretAsync("OAuthClientSecret", "InitialSecretVal");
        var first = await secretStore.GetSecretAsync("OAuthClientSecret");
        first.Value.UnsafeValue.Should().Be("InitialSecretVal");

        await secretStore.SetSecretAsync("OAuthClientSecret", "RotatedSecretVal");
        var second = await secretStore.GetSecretAsync("OAuthClientSecret");
        second.Value.UnsafeValue.Should().Be("RotatedSecretVal");
    }

    [Fact]
    public async Task GoogleCloudSecretStore_WithInjectedError_ReturnsFailure()
    {
        var options = CreateOptions();
        var secretStore = new GoogleCloudSecretManagerStore(options);

        (await secretStore.SetSecretAsync("test-key", "test-value")).IsSuccess.Should().BeTrue();

        secretStore.InjectedError = SecurityError.InvalidCiphertext("Google Cloud Secret Manager simulated 503 outage");

        var getResult = await secretStore.GetSecretAsync("test-key");
        getResult.IsFailure.Should().BeTrue();
        getResult.Error.Description.Should().Be("Google Cloud Secret Manager simulated 503 outage");

        var setResult = await secretStore.SetSecretAsync("test-key", "new-value");
        setResult.IsFailure.Should().BeTrue();
        setResult.Error.Description.Should().Be("Google Cloud Secret Manager simulated 503 outage");
    }

    [Fact]
    public async Task GoogleCloudKeyStore_SaveAndRetrieveKey_RoundtripsSuccessfully()
    {
        var options = CreateOptions();
        using var keyStore = new GoogleCloudKmsKeyStore(options);

        var keyId = KeyIdentifier.Prefixed("gcp");
        var version = KeyVersion.Initial;
        var metadata = new KeyMetadata(keyId, version, KeyPurpose.Signing, KeyStatus.Active, "ECDSA-P256-SHA256", DateTimeOffset.UtcNow);
        var buffer = SecretBuffer.CreateRandom(32);
        var key = new CryptographicKey(metadata, buffer);

        // Null key throws
        await Assert.ThrowsAsync<ArgumentNullException>(() => keyStore.SaveKeyAsync(null!).AsTask());

        // Save
        var saveResult = await keyStore.SaveKeyAsync(key);
        saveResult.IsSuccess.Should().BeTrue();

        // Retrieve existing key
        var getResult = await keyStore.GetKeyAsync(keyId, version);
        getResult.IsSuccess.Should().BeTrue();
        getResult.Value.Metadata.KeyId.Should().Be(keyId);
        getResult.Value.Metadata.Version.Should().Be(version);
        getResult.Value.Metadata.Status.Should().Be(KeyStatus.Active);
        getResult.Value.Metadata.AlgorithmId.Should().Be("ECDSA-P256-SHA256");

        // Missing key returns failure
        var missingKeyId = KeyIdentifier.Prefixed("missing");
        var missingResult = await keyStore.GetKeyAsync(missingKeyId, KeyVersion.Initial);
        missingResult.IsFailure.Should().BeTrue();
        missingResult.Error.Description.Should().Contain(missingKeyId.ToString());
    }

    [Fact]
    public async Task GoogleCloudKeyStore_ListMetadata_FiltersAndSortsCorrectly()
    {
        var options = CreateOptions();
        using var keyStore = new GoogleCloudKmsKeyStore(options);

        var keyId = KeyIdentifier.Prefixed("gcp-hsm");
        var v1 = new KeyVersion(1);
        var v2 = new KeyVersion(2);
        var v3 = new KeyVersion(3);

        var m1 = new KeyMetadata(keyId, v1, KeyPurpose.Encryption, KeyStatus.Active, "AES-256", DateTimeOffset.UtcNow);
        var m2 = new KeyMetadata(keyId, v2, KeyPurpose.Signing, KeyStatus.Active, "ECDSA-P256", DateTimeOffset.UtcNow);
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
        var signList = (await keyStore.ListMetadataAsync(KeyPurpose.Signing)).Value;
        signList.Should().HaveCount(1);
        signList[0].Purpose.Should().Be(KeyPurpose.Signing);
    }

    [Fact]
    public async Task GoogleCloudKeyStore_UpdateStatus_UpdatesCorrectlyAndSetsRevocationTime()
    {
        var options = CreateOptions();
        using var keyStore = new GoogleCloudKmsKeyStore(options);

        var keyId = KeyIdentifier.Prefixed("gcp-ecf");
        var version = KeyVersion.Initial;
        var metadata = new KeyMetadata(keyId, version, KeyPurpose.Signing, KeyStatus.Active, "RSA-2048", DateTimeOffset.UtcNow);
        var key = new CryptographicKey(metadata, SecretBuffer.CreateRandom(32));

        await keyStore.SaveKeyAsync(key);

        // Update to Revoked
        var revokeResult = await keyStore.UpdateStatusAsync(keyId, version, KeyStatus.Revoked);
        revokeResult.IsSuccess.Should().BeTrue();

        var revokedKey = (await keyStore.GetKeyAsync(keyId, version)).Value;
        revokedKey.Metadata.Status.Should().Be(KeyStatus.Revoked);
        revokedKey.Metadata.RevokedAtUtc.Should().NotBeNull();

        // Non-existing key returns failure
        var missingKeyId = KeyIdentifier.Prefixed("unknown");
        var missingUpdate = await keyStore.UpdateStatusAsync(missingKeyId, KeyVersion.Initial, KeyStatus.Destroyed);
        missingUpdate.IsFailure.Should().BeTrue();
        missingUpdate.Error.Description.Should().Contain(missingKeyId.ToString());
    }

    [Fact]
    public async Task GoogleCloudKeyStore_UpdateStatus_ToRetired_DoesNotSetRevocationTime()
    {
        var options = CreateOptions();
        using var keyStore = new GoogleCloudKmsKeyStore(options);

        var keyId = KeyIdentifier.Prefixed("gcp-ret");
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
    public async Task GoogleCloudKeyStore_WithInjectedError_ReturnsFailure()
    {
        var options = CreateOptions();
        using var keyStore = new GoogleCloudKmsKeyStore(options);

        var keyId = KeyIdentifier.Prefixed("gcp");
        var version = KeyVersion.Initial;
        var metadata = new KeyMetadata(keyId, version, KeyPurpose.Encryption, KeyStatus.Active, "AES-256", DateTimeOffset.UtcNow);
        var key = new CryptographicKey(metadata, SecretBuffer.CreateRandom(32));

        (await keyStore.SaveKeyAsync(key)).IsSuccess.Should().BeTrue();

        keyStore.InjectedError = SecurityError.InvalidCiphertext("Cloud KMS unreachable");

        var saveResult = await keyStore.SaveKeyAsync(key);
        saveResult.IsFailure.Should().BeTrue();
        saveResult.Error.Description.Should().Be("Cloud KMS unreachable");

        var getResult = await keyStore.GetKeyAsync(keyId, version);
        getResult.IsFailure.Should().BeTrue();
        getResult.Error.Description.Should().Be("Cloud KMS unreachable");

        var listResult = await keyStore.ListMetadataAsync();
        listResult.IsFailure.Should().BeTrue();
        listResult.Error.Description.Should().Be("Cloud KMS unreachable");

        var updateResult = await keyStore.UpdateStatusAsync(keyId, version, KeyStatus.Revoked);
        updateResult.IsFailure.Should().BeTrue();
        updateResult.Error.Description.Should().Be("Cloud KMS unreachable");
    }

    [Fact]
    public async Task GoogleCloud_CancelledToken_ThrowsOperationCanceledException()
    {
        var options = CreateOptions();
        var secretStore = new GoogleCloudSecretManagerStore(options);
        using var keyStore = new GoogleCloudKmsKeyStore(options);

        using var cts = new CancellationTokenSource();
        cts.Cancel();

        var keyId = KeyIdentifier.Prefixed("gcp");
        var version = KeyVersion.Initial;
        var metadata = new KeyMetadata(keyId, version, KeyPurpose.Signing, KeyStatus.Active, "ECDSA", DateTimeOffset.UtcNow);
        var key = new CryptographicKey(metadata, SecretBuffer.CreateRandom(32));

        await Assert.ThrowsAsync<OperationCanceledException>(() => secretStore.GetSecretAsync("secret", cts.Token).AsTask());
        await Assert.ThrowsAsync<OperationCanceledException>(() => secretStore.SetSecretAsync("secret", "val", cts.Token).AsTask());
        await Assert.ThrowsAsync<OperationCanceledException>(() => keyStore.SaveKeyAsync(key, cts.Token).AsTask());
        await Assert.ThrowsAsync<OperationCanceledException>(() => keyStore.GetKeyAsync(keyId, version, cts.Token).AsTask());
        await Assert.ThrowsAsync<OperationCanceledException>(() => keyStore.ListMetadataAsync(cancellationToken: cts.Token).AsTask());
        await Assert.ThrowsAsync<OperationCanceledException>(() => keyStore.UpdateStatusAsync(keyId, version, KeyStatus.Retired, cts.Token).AsTask());
    }

    [Fact]
    public void AddGoogleCloudSecurity_RegistersServicesInContainer()
    {
        var services = new ServiceCollection();

        services.AddGoogleCloudSecurity(options =>
        {
            options.ProjectId = "my-gcp-project";
            options.SecretPrefix = "app-";
            options.EnableDevelopmentInMemoryStub = true;
        });

        using var provider = services.BuildServiceProvider();

        provider.GetService<IKeyStore>().Should().NotBeNull();
        provider.GetService<ISecretStore>().Should().NotBeNull();
    }

    [Fact]
    public void AddGoogleCloudSecurity_NullArguments_ThrowsArgumentNullException()
    {
        var services = new ServiceCollection();
        var exServices = Assert.Throws<ArgumentNullException>(() => ((IServiceCollection)null!).AddGoogleCloudSecurity(_ => { }));
        exServices.ParamName.Should().Be("services");

        var exConfigure = Assert.Throws<ArgumentNullException>(() => services.AddGoogleCloudSecurity(null!));
        exConfigure.ParamName.Should().Be("configure");
        exConfigure.StackTrace.Should().NotContain("OptionsServiceCollectionExtensions");
    }

    [Fact]
    public void GoogleCloud_ConstructorBranches_BehaveCorrectly()
    {
        var kms = Substitute.For<KeyManagementServiceClient>();
        var sm = Substitute.For<SecretManagerServiceClient>();

        var options = Options.Create(new GoogleCloudSecurityOptions
        {
            ProjectId = "proj",
            KmsClient = kms,
            SecretManagerClient = sm,
            EnableDevelopmentInMemoryStub = false
        });

        using var keyStore = new GoogleCloudKmsKeyStore(options);
        var secretStore = new GoogleCloudSecretManagerStore(options);
        keyStore.Should().NotBeNull();
        secretStore.Should().NotBeNull();
    }

    [Fact]
    public async Task GoogleCloudKeyStore_MissingSecretClientOrProjectId_ReturnsInvalidCiphertext()
    {
        var kms = Substitute.For<KeyManagementServiceClient>();
        var options = Options.Create(new GoogleCloudSecurityOptions
        {
            ProjectId = null,
            KmsClient = kms,
            SecretManagerClient = null,
            EnableDevelopmentInMemoryStub = false
        });
        using var store = new GoogleCloudKmsKeyStore(options);

        var key = new CryptographicKey(new KeyMetadata(KeyIdentifier.Prefixed("k"), KeyVersion.Initial, KeyPurpose.Encryption, KeyStatus.Active, "AES-256", DateTimeOffset.UtcNow), SecretBuffer.CreateRandom(32));

        var saveResult = await store.SaveKeyAsync(key);
        saveResult.IsFailure.Should().BeTrue();
        saveResult.Error.Description.Should().Contain("Google Cloud SecretManagerClient or ProjectId is required");

        var getResult = await store.GetKeyAsync(KeyIdentifier.Prefixed("k"), KeyVersion.Initial);
        getResult.IsFailure.Should().BeTrue();
        getResult.Error.Description.Should().Contain("Google Cloud SecretManagerClient or ProjectId is required");

        await Assert.ThrowsAsync<ArgumentNullException>(() => store.SaveKeyAsync(null!).AsTask());
    }

    [Fact]
    public async Task GoogleCloudSecretStore_LiveClient_GetSecret_SuccessAndFailures()
    {
        var client = Substitute.For<SecretManagerServiceClient>();
        var options = Options.Create(new GoogleCloudSecurityOptions
        {
            ProjectId = "test-proj",
            SecretPrefix = "app-",
            SecretManagerClient = client,
            EnableDevelopmentInMemoryStub = false
        });
        var store = new GoogleCloudSecretManagerStore(options);

        // Success
        client.AccessSecretVersionAsync(
            Arg.Is<SecretVersionName>(n => n.SecretId == "app-db-pwd" && n.ProjectId == "test-proj" && n.SecretVersionId == "latest"),
            Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(new AccessSecretVersionResponse
            {
                Payload = new SecretPayload { Data = ByteString.CopyFromUtf8("my-db-pass") }
            }));

        var result = await store.GetSecretAsync("db.pwd");
        result.IsSuccess.Should().BeTrue();
        result.Value.UnsafeValue.Should().Be("my-db-pass");

        // 404 Not Found
        client.AccessSecretVersionAsync(
            Arg.Is<SecretVersionName>(n => n.SecretId == "app-missing"),
            Arg.Any<CancellationToken>())
            .Throws(new RpcException(new Status(StatusCode.NotFound, "Secret not found")));

        var notFound = await store.GetSecretAsync("missing");
        notFound.IsFailure.Should().BeTrue();
        notFound.Error.Code.Should().Be("Security.SecretNotFound");

        // General error
        client.AccessSecretVersionAsync(
            Arg.Is<SecretVersionName>(n => n.SecretId == "app-error"),
            Arg.Any<CancellationToken>())
            .Throws(new RpcException(new Status(StatusCode.Internal, "Server crash")));

        var errResult = await store.GetSecretAsync("error");
        errResult.IsFailure.Should().BeTrue();
        errResult.Error.Description.Should().Contain("Google Cloud Secret Manager error (Internal): Server crash");

        // Empty secretName
        (await store.GetSecretAsync("")).IsFailure.Should().BeTrue();
        (await store.GetSecretAsync("   ")).IsFailure.Should().BeTrue();
    }

    [Fact]
    public async Task GoogleCloudSecretStore_LiveClient_SetSecret_SuccessAndFailures()
    {
        var client = Substitute.For<SecretManagerServiceClient>();
        var options = Options.Create(new GoogleCloudSecurityOptions
        {
            ProjectId = "test-proj",
            SecretPrefix = "app-",
            SecretManagerClient = client,
            EnableDevelopmentInMemoryStub = false
        });
        var store = new GoogleCloudSecretManagerStore(options);

        // Success direct AddSecretVersion
        client.AddSecretVersionAsync(
            Arg.Is<SecretName>(n => n.SecretId == "app-direct" && n.ProjectId == "test-proj"),
            Arg.Is<SecretPayload>(p => p.Data.ToStringUtf8() == "direct-val"),
            Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(new SecretVersion()));

        var directResult = await store.SetSecretAsync("direct", "direct-val");
        directResult.IsSuccess.Should().BeTrue();

        // 404 on AddSecretVersion triggers CreateSecretAsync then retry AddSecretVersion
        var callCount = 0;
        client.AddSecretVersionAsync(
            Arg.Is<SecretName>(n => n.SecretId == "app-create-retry"),
            Arg.Any<SecretPayload>(),
            Arg.Any<CancellationToken>())
            .Returns(callInfo =>
            {
                callCount++;
                if (callCount == 1)
                {
                    throw new RpcException(new Status(StatusCode.NotFound, "Secret not found"));
                }
                return Task.FromResult(new SecretVersion());
            });

        client.CreateSecretAsync(
            Arg.Is<ProjectName>(p => p.ProjectId == "test-proj"),
            Arg.Is<string>(s => s == "app-create-retry"),
            Arg.Any<Secret>(),
            Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(new Secret()));

        var createRetryResult = await store.SetSecretAsync("create-retry", "val");
        createRetryResult.IsSuccess.Should().BeTrue();

        // 404 then CreateSecretAsync throws
        client.AddSecretVersionAsync(
            Arg.Is<SecretName>(n => n.SecretId == "app-fail-create"),
            Arg.Any<SecretPayload>(),
            Arg.Any<CancellationToken>())
            .Throws(new RpcException(new Status(StatusCode.NotFound, "Not found")));

        client.CreateSecretAsync(
            Arg.Is<ProjectName>(p => p.ProjectId == "test-proj"),
            Arg.Is<string>(s => s == "app-fail-create"),
            Arg.Any<Secret>(),
            Arg.Any<CancellationToken>())
            .Throws(new RpcException(new Status(StatusCode.PermissionDenied, "Denied")));

        var failCreateResult = await store.SetSecretAsync("fail-create", "val");
        failCreateResult.IsFailure.Should().BeTrue();
        failCreateResult.Error.Description.Should().Contain("Google Cloud Secret Manager create failed (PermissionDenied): Denied");

        // General error on AddSecretVersionAsync
        client.AddSecretVersionAsync(
            Arg.Is<SecretName>(n => n.SecretId == "app-fail-add"),
            Arg.Any<SecretPayload>(),
            Arg.Any<CancellationToken>())
            .Throws(new RpcException(new Status(StatusCode.Unavailable, "Unavailable")));

        var failAddResult = await store.SetSecretAsync("fail-add", "val");
        failAddResult.IsFailure.Should().BeTrue();
        failAddResult.Error.Description.Should().Contain("Google Cloud Secret Manager update failed (Unavailable): Unavailable");

        // Empty secretName
        (await store.SetSecretAsync("", "val")).IsFailure.Should().BeTrue();
        (await store.SetSecretAsync("   ", "val")).IsFailure.Should().BeTrue();
    }

    [Fact]
    public async Task GoogleCloudKeyStore_LiveClient_SaveKey_WithoutKms_SuccessAndFailures()
    {
        var kms = Substitute.For<KeyManagementServiceClient>();
        var sm = Substitute.For<SecretManagerServiceClient>();
        var options = Options.Create(new GoogleCloudSecurityOptions
        {
            ProjectId = "test-proj",
            SecretPrefix = "app-",
            KmsClient = kms,
            SecretManagerClient = sm,
            EnableDevelopmentInMemoryStub = false
        });
        using var store = new GoogleCloudKmsKeyStore(options);

        var keyId = KeyIdentifier.Prefixed("k1");
        var version = KeyVersion.Initial;
        var metadata = new KeyMetadata(keyId, version, KeyPurpose.Encryption, KeyStatus.Active, "AES-256-GCM", DateTimeOffset.UtcNow);
        var key = new CryptographicKey(metadata, SecretBuffer.CreateRandom(32));

        // Direct success
        sm.AddSecretVersionAsync(
            Arg.Is<SecretName>(n => n.ProjectId == "test-proj" && n.SecretId.Contains("kms-key-k1")),
            Arg.Any<SecretPayload>(),
            Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(new SecretVersion()));

        var saveResult = await store.SaveKeyAsync(key);
        saveResult.IsSuccess.Should().BeTrue();

        // 404 then CreateSecret then AddSecretVersion succeeds
        var callCount = 0;
        sm.AddSecretVersionAsync(
            Arg.Is<SecretName>(n => n.SecretId.Contains("kms-key-k2")),
            Arg.Any<SecretPayload>(),
            Arg.Any<CancellationToken>())
            .Returns(callInfo =>
            {
                callCount++;
                if (callCount == 1)
                {
                    throw new RpcException(new Status(StatusCode.NotFound, "Not found"));
                }
                return Task.FromResult(new SecretVersion());
            });

        Secret? capturedSecret = null;
        sm.CreateSecretAsync(
            Arg.Is<ProjectName>(p => p.ProjectId == "test-proj"),
            Arg.Is<string>(s => s.Contains("kms-key-k2")),
            Arg.Do<Secret>(s => capturedSecret = s),
            Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(new Secret()));

        var k2 = new CryptographicKey(metadata with { KeyId = KeyIdentifier.Prefixed("k2") }, SecretBuffer.CreateRandom(32));
        var saveK2 = await store.SaveKeyAsync(k2);
        saveK2.IsSuccess.Should().BeTrue();
        capturedSecret.Should().NotBeNull();
        capturedSecret!.Labels["erickson-key-id"].Should().StartWith("k2");
        capturedSecret.Labels["erickson-version"].Should().Be("1");
        capturedSecret.Labels["erickson-purpose"].Should().Be("encryption");

        // 404 then CreateSecret throws RpcException
        sm.AddSecretVersionAsync(
            Arg.Is<SecretName>(n => n.SecretId.Contains("kms-key-k3")),
            Arg.Any<SecretPayload>(),
            Arg.Any<CancellationToken>())
            .Throws(new RpcException(new Status(StatusCode.NotFound, "Not found")));

        sm.CreateSecretAsync(
            Arg.Is<ProjectName>(p => p.ProjectId == "test-proj"),
            Arg.Is<string>(s => s.Contains("kms-key-k3")),
            Arg.Any<Secret>(),
            Arg.Any<CancellationToken>())
            .Throws(new RpcException(new Status(StatusCode.PermissionDenied, "Denied")));

        var k3 = new CryptographicKey(metadata with { KeyId = KeyIdentifier.Prefixed("k3") }, SecretBuffer.CreateRandom(32));
        var saveK3 = await store.SaveKeyAsync(k3);
        saveK3.IsFailure.Should().BeTrue();
        saveK3.Error.Description.Should().Contain("Google Cloud KMS key secret create failed (PermissionDenied): Denied");

        // Direct RpcException on AddSecretVersionAsync
        sm.AddSecretVersionAsync(
            Arg.Is<SecretName>(n => n.SecretId.Contains("kms-key-k4")),
            Arg.Any<SecretPayload>(),
            Arg.Any<CancellationToken>())
            .Throws(new RpcException(new Status(StatusCode.Internal, "Internal crash")));

        var k4 = new CryptographicKey(metadata with { KeyId = KeyIdentifier.Prefixed("k4") }, SecretBuffer.CreateRandom(32));
        var saveK4 = await store.SaveKeyAsync(k4);
        saveK4.IsFailure.Should().BeTrue();
        saveK4.Error.Description.Should().Contain("Google Cloud KMS key save failed (Internal): Internal crash");
    }

    [Fact]
    public async Task GoogleCloudKeyStore_LiveClient_SaveAndGet_WithKmsEncryption_Roundtrip()
    {
        var kms = Substitute.For<KeyManagementServiceClient>();
        var sm = Substitute.For<SecretManagerServiceClient>();
        var options = Options.Create(new GoogleCloudSecurityOptions
        {
            ProjectId = "test-proj",
            LocationId = "us-east1",
            KeyRingId = "ring-1",
            KmsCryptoKeyId = "crypto-key-1",
            KmsClient = kms,
            SecretManagerClient = sm,
            EnableDevelopmentInMemoryStub = false
        });
        using var store = new GoogleCloudKmsKeyStore(options);

        var keyId = KeyIdentifier.Prefixed("kms-enc");
        var version = KeyVersion.Initial;
        var metadata = new KeyMetadata(keyId, version, KeyPurpose.Encryption, KeyStatus.Active, "AES-256-GCM", DateTimeOffset.UtcNow);
        var rawKey = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 };
        var key = new CryptographicKey(metadata, SecretBuffer.FromSpan(rawKey));

        var encryptedBytes = new byte[] { 99, 88, 77, 66 };
        kms.EncryptAsync(
            Arg.Is<EncryptRequest>(r => r.Name.Contains("crypto-key-1") && r.Plaintext.SequenceEqual(ByteString.CopyFrom(rawKey))),
            Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(new EncryptResponse { Ciphertext = ByteString.CopyFrom(encryptedBytes) }));

        SecretPayload? capturedPayload = null;
        sm.AddSecretVersionAsync(
            Arg.Any<SecretName>(),
            Arg.Do<SecretPayload>(p => capturedPayload = p),
            Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(new SecretVersion()));

        var saveResult = await store.SaveKeyAsync(key);
        saveResult.IsSuccess.Should().BeTrue();
        capturedPayload.Should().NotBeNull();
        var jsonText = capturedPayload!.Data.ToStringUtf8();
        jsonText.Should().Contain(Convert.ToBase64String(encryptedBytes));

        // Get key with KMS decrypt
        sm.AccessSecretVersionAsync(
            Arg.Is<SecretVersionName>(v => v.SecretId.Contains("kms-enc") && v.SecretVersionId == "latest"),
            Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(new AccessSecretVersionResponse { Payload = capturedPayload }));

        kms.DecryptAsync(
            Arg.Is<DecryptRequest>(r => r.Ciphertext.SequenceEqual(ByteString.CopyFrom(encryptedBytes))),
            Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(new DecryptResponse { Plaintext = ByteString.CopyFrom(rawKey) }));

        var getResult = await store.GetKeyAsync(keyId, version);
        getResult.IsSuccess.Should().BeTrue();
        getResult.Value.GetKeyBytes()[0].Should().Be(1);

        // KMS Decrypt failure
        kms.DecryptAsync(
            Arg.Any<DecryptRequest>(),
            Arg.Any<CancellationToken>())
            .Throws(new RpcException(new Status(StatusCode.InvalidArgument, "Decryption error")));

        var decryptFail = await store.GetKeyAsync(keyId, version);
        decryptFail.IsFailure.Should().BeTrue();
        decryptFail.Error.Description.Should().Contain("Google Cloud KMS decryption failed: Decryption error");
    }

    [Fact]
    public async Task GoogleCloudKeyStore_LiveClient_GetKey_WithoutKms_SuccessAndFailures()
    {
        var kms = Substitute.For<KeyManagementServiceClient>();
        var sm = Substitute.For<SecretManagerServiceClient>();
        var options = Options.Create(new GoogleCloudSecurityOptions
        {
            ProjectId = "test-proj",
            KmsClient = kms,
            SecretManagerClient = sm,
            EnableDevelopmentInMemoryStub = false
        });
        using var store = new GoogleCloudKmsKeyStore(options);

        var keyId = KeyIdentifier.Prefixed("raw-key");
        var version = KeyVersion.Initial;
        var rawKey = new byte[32];
        rawKey[0] = 42;

        var json = JsonSerializer.Serialize(new Dictionary<string, string>
        {
            ["key_bytes"] = Convert.ToBase64String(rawKey),
            ["key_id"] = "raw-key",
            ["version"] = "1",
            ["purpose"] = "Signing",
            ["status"] = "Active",
            ["algorithm"] = "HMACSHA256",
            ["created_at"] = DateTimeOffset.UtcNow.ToString("O"),
            ["expires_at"] = DateTimeOffset.UtcNow.AddDays(30).ToString("O"),
            ["revoked_at"] = DateTimeOffset.UtcNow.ToString("O")
        });

        sm.AccessSecretVersionAsync(
            Arg.Is<SecretVersionName>(v => v.SecretId.Contains("raw-key")),
            Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(new AccessSecretVersionResponse
            {
                Payload = new SecretPayload { Data = ByteString.CopyFromUtf8(json) }
            }));

        var getResult = await store.GetKeyAsync(keyId, version);
        getResult.IsSuccess.Should().BeTrue();
        getResult.Value.Metadata.Purpose.Should().Be(KeyPurpose.Signing);
        getResult.Value.Metadata.AlgorithmId.Should().Be("HMACSHA256");
        getResult.Value.Metadata.ExpiresAtUtc.Should().NotBeNull();
        getResult.Value.Metadata.RevokedAtUtc.Should().NotBeNull();
        getResult.Value.GetKeyBytes()[0].Should().Be(42);

        // 404 KeyNotFound
        sm.AccessSecretVersionAsync(
            Arg.Is<SecretVersionName>(v => v.SecretId.Contains("missing")),
            Arg.Any<CancellationToken>())
            .Throws(new RpcException(new Status(StatusCode.NotFound, "Not found")));

        var notFound = await store.GetKeyAsync(KeyIdentifier.Prefixed("missing"), version);
        notFound.IsFailure.Should().BeTrue();
        notFound.Error.Code.Should().Be("Security.KeyNotFound");

        // General RpcException
        sm.AccessSecretVersionAsync(
            Arg.Is<SecretVersionName>(v => v.SecretId.Contains("err")),
            Arg.Any<CancellationToken>())
            .Throws(new RpcException(new Status(StatusCode.Internal, "DB error")));

        var errResult = await store.GetKeyAsync(KeyIdentifier.Prefixed("err"), version);
        errResult.IsFailure.Should().BeTrue();
        errResult.Error.Description.Should().Contain("Google Cloud KMS retrieve failed (Internal): DB error");
    }

    [Fact]
    public async Task GoogleCloudKeyStore_LiveClient_UpdateStatus_And_ListMetadata()
    {
        var kms = Substitute.For<KeyManagementServiceClient>();
        var sm = Substitute.For<SecretManagerServiceClient>();
        var options = Options.Create(new GoogleCloudSecurityOptions
        {
            ProjectId = "test-proj",
            KmsClient = kms,
            SecretManagerClient = sm,
            EnableDevelopmentInMemoryStub = false
        });
        using var store = new GoogleCloudKmsKeyStore(options);

        // ListMetadata in live mode returns empty list
        var listResult = await store.ListMetadataAsync();
        listResult.IsSuccess.Should().BeTrue();
        listResult.Value.Should().BeEmpty();

        var keyId = KeyIdentifier.Prefixed("update-key");
        var version = KeyVersion.Initial;
        var rawKey = new byte[32];

        var json = JsonSerializer.Serialize(new Dictionary<string, string>
        {
            ["key_bytes"] = Convert.ToBase64String(rawKey),
            ["key_id"] = "update-key",
            ["version"] = "1",
            ["purpose"] = "Encryption",
            ["status"] = "Active",
            ["algorithm"] = "AES-256-GCM",
            ["created_at"] = DateTimeOffset.UtcNow.ToString("O")
        });

        sm.AccessSecretVersionAsync(
            Arg.Is<SecretVersionName>(v => v.SecretId.Contains("update-key")),
            Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(new AccessSecretVersionResponse
            {
                Payload = new SecretPayload { Data = ByteString.CopyFromUtf8(json) }
            }));

        SecretPayload? updatedPayload = null;
        sm.AddSecretVersionAsync(
            Arg.Is<SecretName>(n => n.SecretId.Contains("update-key")),
            Arg.Do<SecretPayload>(p => updatedPayload = p),
            Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(new SecretVersion()));

        // Revoke sets RevokedAtUtc
        var revokeResult = await store.UpdateStatusAsync(keyId, version, KeyStatus.Revoked);
        revokeResult.IsSuccess.Should().BeTrue();
        updatedPayload.Should().NotBeNull();
        var updatedJson = updatedPayload!.Data.ToStringUtf8();
        updatedJson.Should().Contain("\"status\":\"Revoked\"");
        updatedJson.Should().Contain("\"revoked_at\":");

        // Active status
        updatedPayload = null;
        var activeResult = await store.UpdateStatusAsync(keyId, version, KeyStatus.Active);
        activeResult.IsSuccess.Should().BeTrue();
        updatedPayload!.Data.ToStringUtf8().Should().Contain("\"status\":\"Active\"");

        // KeyNotFound during update
        sm.AccessSecretVersionAsync(
            Arg.Is<SecretVersionName>(v => v.SecretId.Contains("missing")),
            Arg.Any<CancellationToken>())
            .Throws(new RpcException(new Status(StatusCode.NotFound, "Not found")));

        var notFound = await store.UpdateStatusAsync(KeyIdentifier.Prefixed("missing"), version, KeyStatus.Retired);
        notFound.IsFailure.Should().BeTrue();
        notFound.Error.Code.Should().Be("Security.KeyNotFound");

        // AddSecretVersion fails during update
        sm.AddSecretVersionAsync(
            Arg.Is<SecretName>(n => n.SecretId.Contains("update-key")),
            Arg.Any<SecretPayload>(),
            Arg.Any<CancellationToken>())
            .Throws(new RpcException(new Status(StatusCode.Internal, "Write fail")));

        var updateFail = await store.UpdateStatusAsync(keyId, version, KeyStatus.Retired);
        updateFail.IsFailure.Should().BeTrue();
        updateFail.Error.Description.Should().Contain("Google Cloud KMS status update failed (Internal): Write fail");
    }
}
