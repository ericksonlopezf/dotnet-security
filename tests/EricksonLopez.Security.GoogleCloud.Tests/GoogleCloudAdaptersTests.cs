// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.GoogleCloud.Tests;

using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using AwesomeAssertions;
using EricksonLopez.Security.Abstractions.Errors;
using EricksonLopez.Security.Abstractions.KeyManagement;
using EricksonLopez.Security.Abstractions.Primitives;
using EricksonLopez.Security.Abstractions.Secrets;
using EricksonLopez.Security.GoogleCloud;
using EricksonLopez.Security.Memory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
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
        Assert.Throws<InvalidOperationException>(() => new GoogleCloudSecretManagerStore(defaultOptions));
        Assert.Throws<InvalidOperationException>(() => new GoogleCloudKmsKeyStore(defaultOptions));
    }

    [Fact]
    public void GoogleCloudSecretStore_NullOptions_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => new GoogleCloudSecretManagerStore(null!));
    }

    [Fact]
    public void GoogleCloudKeyStore_NullOptions_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => new GoogleCloudKmsKeyStore(null!));
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
        Assert.Throws<ArgumentNullException>(() => ((IServiceCollection)null!).AddGoogleCloudSecurity(_ => { }));
        Assert.Throws<ArgumentNullException>(() => services.AddGoogleCloudSecurity(null!));
    }
}
