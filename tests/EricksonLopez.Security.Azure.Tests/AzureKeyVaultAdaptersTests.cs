// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Azure.Tests;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using global::Azure;
using global::Azure.Security.KeyVault.Secrets;
using AwesomeAssertions;
using EricksonLopez.Security.Abstractions.Errors;
using EricksonLopez.Security.Abstractions.KeyManagement;
using EricksonLopez.Security.Abstractions.Primitives;
using EricksonLopez.Security.Abstractions.Secrets;
using EricksonLopez.Security.Azure;
using EricksonLopez.Security.Memory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using NSubstitute;
using NSubstitute.ExceptionExtensions;
using Xunit;
using KeyMetadata = EricksonLopez.Security.Abstractions.Primitives.KeyMetadata;

public sealed class AzureKeyVaultAdaptersTests
{
    private static IOptions<AzureKeyVaultOptions> CreateOptions(Action<AzureKeyVaultOptions>? configure = null)
    {
        var options = new AzureKeyVaultOptions { EnableDevelopmentInMemoryStub = true };
        configure?.Invoke(options);
        return Options.Create(options);
    }

    [Fact]
    public void AzureKeyVaultOptions_PropertiesGetAndSet()
    {
        var options = new AzureKeyVaultOptions();
        options.VaultUri.Should().BeNull();
        options.SecretPrefix.Should().Be(string.Empty);
        options.EnableDevelopmentInMemoryStub.Should().BeFalse();

        var uri = new Uri("https://custom.vault.azure.net/");
        options.VaultUri = uri;
        options.SecretPrefix = "custom-";
        options.EnableDevelopmentInMemoryStub = true;
        options.Credential = null;
        options.SecretClient = null;
        options.KeyClient = null;

        options.VaultUri.Should().Be(uri);
        options.SecretPrefix.Should().Be("custom-");
        options.EnableDevelopmentInMemoryStub.Should().BeTrue();
        options.Credential.Should().BeNull();
        options.SecretClient.Should().BeNull();
        options.KeyClient.Should().BeNull();
    }

    [Fact]
    public void AzureKeyVault_DefaultOptions_ThrowsInvalidOperationException_WhenStubNotEnabled()
    {
        var defaultOptions = Options.Create(new AzureKeyVaultOptions());
        var exSecret = Assert.Throws<InvalidOperationException>(() => new AzureKeyVaultSecretStore(defaultOptions));
        exSecret.Message.Should().Be("AzureKeyVaultSecretStore requires either a configured VaultUri, a pre-configured SecretClient, or EnableDevelopmentInMemoryStub = true for testing environments.");

        var exKey = Assert.Throws<InvalidOperationException>(() => new AzureKeyVaultKeyStore(defaultOptions));
        exKey.Message.Should().Be("AzureKeyVaultKeyStore requires either a configured VaultUri, a pre-configured SecretClient, or EnableDevelopmentInMemoryStub = true for testing environments.");

        // When SecretClient is provided, does not throw
        var mockClient = Substitute.For<SecretClient>();
        var clientOptions = Options.Create(new AzureKeyVaultOptions { SecretClient = mockClient });
        using var clientKeyStore = new AzureKeyVaultKeyStore(clientOptions);
        var clientSecretStore = new AzureKeyVaultSecretStore(clientOptions);
        clientKeyStore.Should().NotBeNull();
        clientSecretStore.Should().NotBeNull();

        // When VaultUri is provided without custom credential (uses DefaultAzureCredential), does not throw
        var uriOptions = Options.Create(new AzureKeyVaultOptions { VaultUri = new Uri("https://testvault.vault.azure.net/") });
        using var uriKeyStore = new AzureKeyVaultKeyStore(uriOptions);
        var uriSecretStore = new AzureKeyVaultSecretStore(uriOptions);
        uriKeyStore.Should().NotBeNull();
        uriSecretStore.Should().NotBeNull();

        // When VaultUri is provided with custom credential, does not throw
        var credMock = Substitute.For<global::Azure.Core.TokenCredential>();
        var customCredOptions = Options.Create(new AzureKeyVaultOptions
        {
            VaultUri = new Uri("https://testvault.vault.azure.net/"),
            Credential = credMock
        });
        using var customKeyStore = new AzureKeyVaultKeyStore(customCredOptions);
        var customSecretStore = new AzureKeyVaultSecretStore(customCredOptions);
        customKeyStore.Should().NotBeNull();
        customSecretStore.Should().NotBeNull();
    }

    [Fact]
    public void AzureKeyVault_Constructors_NullArgumentChecks()
    {
        var stubOptions = CreateOptions();
        var liveOptions = Options.Create(new AzureKeyVaultOptions { SecretClient = Substitute.For<SecretClient>() });

        var exKeyOpt = Assert.Throws<ArgumentNullException>("options", () => new AzureKeyVaultKeyStore(null!, Microsoft.Extensions.Logging.Abstractions.NullLogger<AzureKeyVaultKeyStore>.Instance));
        exKeyOpt.ParamName.Should().Be("options");

        var exKeyLog1 = Assert.Throws<ArgumentNullException>("logger", () => new AzureKeyVaultKeyStore(stubOptions, null!));
        exKeyLog1.ParamName.Should().Be("logger");

        var exKeyLog2 = Assert.Throws<ArgumentNullException>("logger", () => new AzureKeyVaultKeyStore(liveOptions, null!));
        exKeyLog2.ParamName.Should().Be("logger");

        var exSecOpt = Assert.Throws<ArgumentNullException>("options", () => new AzureKeyVaultSecretStore(null!, Microsoft.Extensions.Logging.Abstractions.NullLogger<AzureKeyVaultSecretStore>.Instance));
        exSecOpt.ParamName.Should().Be("options");

        var exSecLog1 = Assert.Throws<ArgumentNullException>("logger", () => new AzureKeyVaultSecretStore(stubOptions, null!));
        exSecLog1.ParamName.Should().Be("logger");

        var exSecLog2 = Assert.Throws<ArgumentNullException>("logger", () => new AzureKeyVaultSecretStore(liveOptions, null!));
        exSecLog2.ParamName.Should().Be("logger");
    }

    [Fact]
    public void AddAzureKeyVaultSecurity_RegistersServicesAndValidatesNullArguments()
    {
        IServiceCollection nullServices = null!;
        var exNull1 = Assert.Throws<ArgumentNullException>("services", () => nullServices.AddAzureKeyVaultSecurity());
        exNull1.ParamName.Should().Be("services");

        var exNull2 = Assert.Throws<ArgumentNullException>("services", () => nullServices.AddAzureKeyVaultSecurity(_ => { }));
        exNull2.ParamName.Should().Be("services");
        exNull2.StackTrace.Should().NotContain("OptionsServiceCollectionExtensions");

        var exNull3 = Assert.Throws<ArgumentNullException>("configure", () => new ServiceCollection().AddAzureKeyVaultSecurity(null!));
        exNull3.ParamName.Should().Be("configure");

        var services = new ServiceCollection();
        services.AddSingleton(typeof(Microsoft.Extensions.Logging.ILogger<>), typeof(Microsoft.Extensions.Logging.Abstractions.NullLogger<>));
        services.AddAzureKeyVaultSecurity(o => o.EnableDevelopmentInMemoryStub = true);

        using var provider = services.BuildServiceProvider();
        var keyStore = provider.GetRequiredService<IKeyStore>();
        var secretStore = provider.GetRequiredService<ISecretStore>();

        keyStore.Should().NotBeNull().And.BeOfType<AzureKeyVaultKeyStore>();
        secretStore.Should().NotBeNull().And.BeOfType<AzureKeyVaultSecretStore>();

        var defaultServices = new ServiceCollection();
        defaultServices.AddSingleton(typeof(Microsoft.Extensions.Logging.ILogger<>), typeof(Microsoft.Extensions.Logging.Abstractions.NullLogger<>));
        defaultServices.AddAzureKeyVaultSecurity();
        using var defaultProvider = defaultServices.BuildServiceProvider();
        defaultProvider.GetRequiredService<IOptions<AzureKeyVaultOptions>>().Value.Should().NotBeNull();
    }

    [Fact]
    public async Task AzureKeyVault_Stores_Dispose_ClearsResources()
    {
        var options = CreateOptions();
        var keyStore = new AzureKeyVaultKeyStore(options);

        var keyId = KeyIdentifier.Prefixed("az-disp");
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
    public async Task AzureKeyVaultSecretStore_SetAndGetSecret_RoundtripsSuccessfully()
    {
        var options = CreateOptions(o => o.SecretPrefix = "test-");
        var secretStore = new AzureKeyVaultSecretStore(options);

        var setResult1 = await secretStore.SetSecretAsync("Database.Password:Master", "P@ssw0rdAzure2026!");
        setResult1.IsSuccess.Should().BeTrue();

        var setResult2 = await secretStore.SetSecretAsync("ApiKey:Secondary", "SecretKeyXYZ987!");
        setResult2.IsSuccess.Should().BeTrue();

        var getResult1 = await secretStore.GetSecretAsync("Database.Password:Master");
        getResult1.IsSuccess.Should().BeTrue();
        getResult1.Value.UnsafeValue.Should().Be("P@ssw0rdAzure2026!");
        getResult1.Value.ToString().Should().Be("[REDACTED]");

        var getResult2 = await secretStore.GetSecretAsync("ApiKey:Secondary");
        getResult2.IsSuccess.Should().BeTrue();
        getResult2.Value.UnsafeValue.Should().Be("SecretKeyXYZ987!");
    }

    [Fact]
    public async Task AzureKeyVaultSecretStore_InvalidAndMissingSecrets_ReturnFailure()
    {
        var options = CreateOptions();
        var secretStore = new AzureKeyVaultSecretStore(options);

        var emptyGet1 = await secretStore.GetSecretAsync("");
        emptyGet1.IsFailure.Should().BeTrue();
        emptyGet1.Error.Description.Should().Be("The secret 'Empty secret name.' was not found.");

        var emptyGet2 = await secretStore.GetSecretAsync("   ");
        emptyGet2.IsFailure.Should().BeTrue();
        emptyGet2.Error.Description.Should().Be("The secret 'Empty secret name.' was not found.");

        (await secretStore.GetSecretAsync("non_existent")).IsFailure.Should().BeTrue();

        var emptySet1 = await secretStore.SetSecretAsync("", "val");
        emptySet1.IsFailure.Should().BeTrue();
        emptySet1.Error.Description.Should().Be("The secret 'Empty secret name.' was not found.");

        var emptySet2 = await secretStore.SetSecretAsync("   ", "val");
        emptySet2.IsFailure.Should().BeTrue();
        emptySet2.Error.Description.Should().Be("The secret 'Empty secret name.' was not found.");
    }

    [Fact]
    public void AzureKeyVaultSecretStore_NullOptions_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => new AzureKeyVaultSecretStore(null!));
    }

    [Fact]
    public void AzureKeyVaultKeyStore_NullOptions_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => new AzureKeyVaultKeyStore(null!));
    }

    [Fact]
    public async Task AzureKeyVaultKeyStore_SaveAndRetrieveKey_RoundtripsSuccessfully()
    {
        var options = CreateOptions();
        var keyStore = new AzureKeyVaultKeyStore(options);

        var keyId = KeyIdentifier.Prefixed("azure");
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
        getResult.Value.Metadata.Status.Should().Be(KeyStatus.Active);

        // Get missing key
        var missingKeyId = KeyIdentifier.Prefixed("missing");
        var missingResult = await keyStore.GetKeyAsync(missingKeyId, KeyVersion.Initial);
        missingResult.IsFailure.Should().BeTrue();
        missingResult.Error.Description.Should().Contain(missingKeyId.ToString());
        missingResult.Error.Description.Should().Contain(KeyVersion.Initial.ToString());
    }

    [Fact]
    public async Task AzureKeyVaultKeyStore_ListMetadata_FiltersAndSortsCorrectly()
    {
        var options = CreateOptions();
        var keyStore = new AzureKeyVaultKeyStore(options);

        var keyId = KeyIdentifier.Prefixed("azure");
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
    public async Task AzureKeyVaultKeyStore_UpdateStatus_UpdatesCorrectlyAndSetsRevocationTime()
    {
        var options = CreateOptions();
        var keyStore = new AzureKeyVaultKeyStore(options);

        var keyId = KeyIdentifier.Prefixed("azure");
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
    public void AddAzureKeyVaultSecurity_RegistersServicesInContainer()
    {
        var services = new ServiceCollection();

        services.AddAzureKeyVaultSecurity(options =>
        {
            options.VaultUri = new Uri("https://test.vault.azure.net/");
            options.SecretPrefix = "app-";
            options.EnableDevelopmentInMemoryStub = true;
        });

        using var provider = services.BuildServiceProvider();

        provider.GetService<IKeyStore>().Should().NotBeNull();
        provider.GetService<ISecretStore>().Should().NotBeNull();
    }

    [Fact]
    public void AddAzureKeyVaultSecurity_NullArguments_ThrowsArgumentNullException()
    {
        var services = new ServiceCollection();
        Assert.Throws<ArgumentNullException>(() => ((IServiceCollection)null!).AddAzureKeyVaultSecurity(_ => { }));
        Assert.Throws<ArgumentNullException>(() => services.AddAzureKeyVaultSecurity(null!));
    }

    [Fact]
    public async Task AzureKeyVaultKeyStore_UpdateStatus_ToRetired_DoesNotSetRevocationTime()
    {
        var options = CreateOptions(o => o.VaultUri = new Uri("https://test.vault.azure.net/"));
        var keyStore = new AzureKeyVaultKeyStore(options);

        var keyId = KeyIdentifier.Prefixed("az");
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
    public async Task AzureKeyVaultSecretStore_OverwritingExistingSecret_UpdatesSuccessfully()
    {
        var options = CreateOptions(o => o.VaultUri = new Uri("https://test.vault.azure.net/"));
        var secretStore = new AzureKeyVaultSecretStore(options);

        await secretStore.SetSecretAsync("Token", "InitialValue");
        var first = await secretStore.GetSecretAsync("Token");
        first.Value.UnsafeValue.Should().Be("InitialValue");

        await secretStore.SetSecretAsync("Token", "UpdatedValue");
        var second = await secretStore.GetSecretAsync("Token");
        second.Value.UnsafeValue.Should().Be("UpdatedValue");
    }

    [Fact]
    public async Task AzureKeyVaultSecretStore_WithInjectedError_ReturnsFailure()
    {
        var options = CreateOptions();
        var secretStore = new AzureKeyVaultSecretStore(options);

        // Pre-save secret so it exists
        (await secretStore.SetSecretAsync("secret", "val")).IsSuccess.Should().BeTrue();

        secretStore.InjectedError = SecurityError.InvalidCiphertext("Azure Key Vault outage");

        var getResult = await secretStore.GetSecretAsync("secret");
        getResult.IsFailure.Should().BeTrue();
        getResult.Error.Description.Should().Be("Azure Key Vault outage");

        var setResult = await secretStore.SetSecretAsync("secret", "new-val");
        setResult.IsFailure.Should().BeTrue();
        setResult.Error.Description.Should().Be("Azure Key Vault outage");
    }

    [Fact]
    public async Task AzureKeyVaultKeyStore_WithInjectedError_ReturnsFailure()
    {
        var options = CreateOptions();
        var keyStore = new AzureKeyVaultKeyStore(options);

        var keyId = KeyIdentifier.Prefixed("az");
        var version = KeyVersion.Initial;
        var metadata = new KeyMetadata(keyId, version, KeyPurpose.Encryption, KeyStatus.Active, "AES-256", DateTimeOffset.UtcNow);
        var key = new CryptographicKey(metadata, SecretBuffer.CreateRandom(32));

        // Pre-save key so it exists in store
        (await keyStore.SaveKeyAsync(key)).IsSuccess.Should().BeTrue();

        keyStore.InjectedError = SecurityError.InvalidCiphertext("Azure KMS down");

        var saveResult = await keyStore.SaveKeyAsync(key);
        saveResult.IsFailure.Should().BeTrue();
        saveResult.Error.Description.Should().Be("Azure KMS down");

        var getResult = await keyStore.GetKeyAsync(keyId, version);
        getResult.IsFailure.Should().BeTrue();
        getResult.Error.Description.Should().Be("Azure KMS down");

        var listResult = await keyStore.ListMetadataAsync();
        listResult.IsFailure.Should().BeTrue();
        listResult.Error.Description.Should().Be("Azure KMS down");

        var updateResult = await keyStore.UpdateStatusAsync(keyId, version, KeyStatus.Revoked);
        updateResult.IsFailure.Should().BeTrue();
        updateResult.Error.Description.Should().Be("Azure KMS down");
    }

    [Fact]
    public async Task AzureKeyVault_CancelledToken_ThrowsOperationCanceledException()
    {
        var options = CreateOptions();
        var secretStore = new AzureKeyVaultSecretStore(options);
        var keyStore = new AzureKeyVaultKeyStore(options);

        using var cts = new CancellationTokenSource();
        cts.Cancel();

        var keyId = KeyIdentifier.Prefixed("az");
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
    public async Task AzureKeyVaultSecretStore_LiveClient_GetSecret_SuccessAndFailures()
    {
        var secretClient = Substitute.For<SecretClient>();
        var options = Options.Create(new AzureKeyVaultOptions
        {
            SecretPrefix = "app-",
            SecretClient = secretClient
        });
        var store = new AzureKeyVaultSecretStore(options);

        // Success with normalization
        var props = SecretModelFactory.SecretProperties(name: "app-db-password");
        var secret = SecretModelFactory.KeyVaultSecret(props, "db-pass-123");
        var response = Response.FromValue(secret, Substitute.For<Response>());

        secretClient.GetSecretAsync(Arg.Is<string>(s => s == "app-db-password"), Arg.Is<string?>(v => v == null), Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(response));

        var result = await store.GetSecretAsync("db.password");
        result.IsSuccess.Should().BeTrue();
        result.Value.UnsafeValue.Should().Be("db-pass-123");

        // 404 Not Found
        secretClient.GetSecretAsync(Arg.Is<string>(s => s == "app-missing"), Arg.Is<string?>(v => v == null), Arg.Any<CancellationToken>())
            .Throws(new RequestFailedException(404, "Not found"));

        var notFoundResult = await store.GetSecretAsync("missing");
        notFoundResult.IsFailure.Should().BeTrue();
        notFoundResult.Error.Code.Should().Be("Security.SecretNotFound");

        // 500 Server error
        secretClient.GetSecretAsync(Arg.Is<string>(s => s == "app-error"), Arg.Is<string?>(v => v == null), Arg.Any<CancellationToken>())
            .Throws(new RequestFailedException(500, "Internal Server Error"));

        var errorResult = await store.GetSecretAsync("error");
        errorResult.IsFailure.Should().BeTrue();
        errorResult.Error.Description.Should().Contain("Azure Key Vault request failed with status 500: Internal Server Error");
    }

    [Fact]
    public async Task AzureKeyVaultSecretStore_LiveClient_SetSecret_SuccessAndFailures()
    {
        var secretClient = Substitute.For<SecretClient>();
        var options = Options.Create(new AzureKeyVaultOptions
        {
            SecretPrefix = "app-",
            SecretClient = secretClient
        });
        var store = new AzureKeyVaultSecretStore(options);

        // Success
        var props = SecretModelFactory.SecretProperties(name: "app-new-secret");
        var secret = SecretModelFactory.KeyVaultSecret(props, "val123");
        var response = Response.FromValue(secret, Substitute.For<Response>());

        secretClient.SetSecretAsync("app-new-secret", "val123", Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(response));

        var result = await store.SetSecretAsync("new-secret", "val123");
        result.IsSuccess.Should().BeTrue();

        // 403 Forbidden
        secretClient.SetSecretAsync("app-fail", "val", Arg.Any<CancellationToken>())
            .Throws(new RequestFailedException(403, "Forbidden"));

        var failResult = await store.SetSecretAsync("fail", "val");
        failResult.IsFailure.Should().BeTrue();
        failResult.Error.Description.Should().Contain("Azure Key Vault request failed with status 403: Forbidden");
    }

    [Fact]
    public async Task AzureKeyVaultKeyStore_LiveClient_SaveKey_SuccessAndFailures()
    {
        var secretClient = Substitute.For<SecretClient>();
        var options = Options.Create(new AzureKeyVaultOptions
        {
            SecretPrefix = "sec-",
            SecretClient = secretClient
        });
        using var store = new AzureKeyVaultKeyStore(options);

        var keyId = KeyIdentifier.Prefixed("akv");
        var version = KeyVersion.Initial;
        var now = DateTimeOffset.UtcNow;
        var metadata = new KeyMetadata(keyId, version, KeyPurpose.Encryption, KeyStatus.Active, "AES-256-GCM", now, now.AddDays(10), now.AddDays(20));
        var key = new CryptographicKey(metadata, SecretBuffer.CreateRandom(32));

        KeyVaultSecret? capturedSecret = null;
        secretClient.SetSecretAsync(Arg.Do<KeyVaultSecret>(s => capturedSecret = s), Arg.Any<CancellationToken>())
            .Returns(callInfo =>
            {
                var s = callInfo.Arg<KeyVaultSecret>();
                return Task.FromResult(Response.FromValue(s, Substitute.For<Response>()));
            });

        var saveResult = await store.SaveKeyAsync(key);
        saveResult.IsSuccess.Should().BeTrue();
        capturedSecret.Should().NotBeNull();
        capturedSecret!.Properties.Tags["KeyId"].Should().Be(keyId.Value);
        capturedSecret.Properties.Tags["Version"].Should().Be("1");
        capturedSecret.Properties.Tags["Purpose"].Should().Be("Encryption");
        capturedSecret.Properties.Tags["Status"].Should().Be("Active");
        capturedSecret.Properties.Tags["AlgorithmId"].Should().Be("AES-256-GCM");
        capturedSecret.Properties.Tags["CreatedAtUtc"].Should().Contain("T").And.Contain("+00:00");
        capturedSecret.Properties.Tags["ExpiresAtUtc"].Should().Contain("T").And.Contain("+00:00");
        capturedSecret.Properties.Tags["RevokedAtUtc"].Should().Contain("T").And.Contain("+00:00");
        capturedSecret.Properties.Enabled.Should().BeTrue();
        capturedSecret.Properties.ExpiresOn.Should().Be(now.AddDays(10));

        // Save key without optional expires/revoked and with Retired status
        var retiredMeta = new KeyMetadata(keyId, new KeyVersion(2), KeyPurpose.Signing, KeyStatus.Retired, "HMAC-SHA256", now);
        var retiredKey = new CryptographicKey(retiredMeta, SecretBuffer.CreateRandom(32));
        KeyVaultSecret? capturedRetired = null;
        secretClient.SetSecretAsync(Arg.Do<KeyVaultSecret>(s => capturedRetired = s), Arg.Any<CancellationToken>())
            .Returns(callInfo => Task.FromResult(Response.FromValue(callInfo.Arg<KeyVaultSecret>(), Substitute.For<Response>())));

        var retiredResult = await store.SaveKeyAsync(retiredKey);
        retiredResult.IsSuccess.Should().BeTrue();
        capturedRetired.Should().NotBeNull();
        capturedRetired!.Properties.Enabled.Should().BeFalse();
        capturedRetired.Properties.Tags.ContainsKey("ExpiresAtUtc").Should().BeFalse();
        capturedRetired.Properties.Tags.ContainsKey("RevokedAtUtc").Should().BeFalse();

        // 500 Failure
        secretClient.SetSecretAsync(Arg.Is<KeyVaultSecret>(s => s.Name.Contains("fail")), Arg.Any<CancellationToken>())
            .Throws(new RequestFailedException(500, "Vault down"));

        var failKey = new CryptographicKey(new KeyMetadata(KeyIdentifier.Prefixed("fail"), KeyVersion.Initial, KeyPurpose.Encryption, KeyStatus.Active, "AES-256", now), SecretBuffer.CreateRandom(32));
        var failResult = await store.SaveKeyAsync(failKey);
        failResult.IsFailure.Should().BeTrue();
        failResult.Error.Description.Should().Contain("Azure Key Vault request failed with status 500: Vault down");
    }

    [Fact]
    public async Task AzureKeyVaultKeyStore_LiveClient_GetKey_SuccessAndFailures()
    {
        var secretClient = Substitute.For<SecretClient>();
        var options = Options.Create(new AzureKeyVaultOptions
        {
            SecretPrefix = "sec-",
            SecretClient = secretClient
        });
        using var store = new AzureKeyVaultKeyStore(options);

        var keyId = KeyIdentifier.Prefixed("ret");
        var version = KeyVersion.Initial;
        var rawKeyBytes = new byte[32];
        rawKeyBytes[0] = 99;

        var props = SecretModelFactory.SecretProperties(name: "sec-key-ret-v1");
        props.Enabled = true;
        props.Tags["KeyId"] = keyId.Value;
        props.Tags["Version"] = "1";
        props.Tags["Purpose"] = "Encryption";
        props.Tags["Status"] = "Active";
        props.Tags["AlgorithmId"] = "AES-256-GCM";

        var secret = SecretModelFactory.KeyVaultSecret(props, Convert.ToBase64String(rawKeyBytes));
        secretClient.GetSecretAsync(Arg.Is<string>(s => s.Contains("ret")), Arg.Is<string?>(v => v == null), Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(Response.FromValue(secret, Substitute.For<Response>())));

        var result = await store.GetKeyAsync(keyId, version);
        result.IsSuccess.Should().BeTrue();
        result.Value.GetKeyBytes()[0].Should().Be(99);

        // 404 KeyNotFound
        secretClient.GetSecretAsync(Arg.Is<string>(s => s.Contains("missing")), Arg.Is<string?>(v => v == null), Arg.Any<CancellationToken>())
            .Throws(new RequestFailedException(404, "Not found"));

        var missingId = KeyIdentifier.Prefixed("missing");
        var notFoundResult = await store.GetKeyAsync(missingId, version);
        notFoundResult.IsFailure.Should().BeTrue();
        notFoundResult.Error.Code.Should().Be("Security.KeyNotFound");
        notFoundResult.Error.Description.Should().Contain($"{missingId}:{version}");

        // 400 Bad Request
        secretClient.GetSecretAsync(Arg.Is<string>(s => s.Contains("bad")), Arg.Is<string?>(v => v == null), Arg.Any<CancellationToken>())
            .Throws(new RequestFailedException(400, "Bad request"));

        var badResult = await store.GetKeyAsync(KeyIdentifier.Prefixed("bad"), version);
        badResult.IsFailure.Should().BeTrue();
        badResult.Error.Description.Should().Contain("Azure Key Vault request failed with status 400: Bad request");
    }

    [Fact]
    public async Task AzureKeyVaultKeyStore_LiveClient_ListMetadata_SuccessAndFiltering()
    {
        var secretClient = Substitute.For<SecretClient>();
        var options = Options.Create(new AzureKeyVaultOptions
        {
            SecretClient = secretClient
        });
        using var store = new AzureKeyVaultKeyStore(options);

        var p1 = SecretModelFactory.SecretProperties(name: "key1");
        p1.Enabled = true;
        p1.Tags["KeyId"] = "k1";
        p1.Tags["Version"] = "1";
        p1.Tags["Purpose"] = "Encryption";

        var p2 = SecretModelFactory.SecretProperties(name: "key2");
        p2.Enabled = true;
        p2.Tags["KeyId"] = "k1";
        p2.Tags["Version"] = "2";
        p2.Tags["Purpose"] = "Signing";

        var p3 = SecretModelFactory.SecretProperties(name: "key3");
        p3.Enabled = true;
        p3.Tags["KeyId"] = "k1";
        p3.Tags["Version"] = "3";
        p3.Tags["Purpose"] = "Encryption";

        var p4 = SecretModelFactory.SecretProperties(name: "nonkey");
        p4.Enabled = true;
        p4.Tags["Other"] = "value";

        var p5OnlyKeyId = SecretModelFactory.SecretProperties(name: "keyIdOnly");
        p5OnlyKeyId.Enabled = true;
        p5OnlyKeyId.Tags["KeyId"] = "k1";

        var p6OnlyVersion = SecretModelFactory.SecretProperties(name: "versionOnly");
        p6OnlyVersion.Enabled = true;
        p6OnlyVersion.Tags["Version"] = "4";

        var page = Page<SecretProperties>.FromValues(new[] { p1, p2, p3, p4, p5OnlyKeyId, p6OnlyVersion }, null, Substitute.For<Response>());
        var asyncPageable = AsyncPageable<SecretProperties>.FromPages(new[] { page });

        secretClient.GetPropertiesOfSecretsAsync(Arg.Any<CancellationToken>())
            .Returns(asyncPageable);

        // Filter by purpose = Encryption: should return v3 then v1 (ordered descending)
        var filteredResult = await store.ListMetadataAsync(KeyPurpose.Encryption);
        filteredResult.IsSuccess.Should().BeTrue();
        filteredResult.Value.Count.Should().Be(2);
        filteredResult.Value[0].Version.Value.Should().Be(3);
        filteredResult.Value[1].Version.Value.Should().Be(1);

        // No filter: should return v3, v2, v1
        var allResult = await store.ListMetadataAsync();
        allResult.IsSuccess.Should().BeTrue();
        allResult.Value.Count.Should().Be(3);
        allResult.Value[0].Version.Value.Should().Be(3);
        allResult.Value[1].Version.Value.Should().Be(2);
        allResult.Value[2].Version.Value.Should().Be(1);

        // Failure
        secretClient.GetPropertiesOfSecretsAsync(Arg.Any<CancellationToken>())
            .Throws(new RequestFailedException(500, "List failed"));

        var failResult = await store.ListMetadataAsync();
        failResult.IsFailure.Should().BeTrue();
        failResult.Error.Description.Should().Contain("Azure Key Vault request failed with status 500: List failed");
    }

    [Fact]
    public async Task AzureKeyVaultKeyStore_LiveClient_UpdateStatus_SuccessAndFailures()
    {
        var secretClient = Substitute.For<SecretClient>();
        var options = Options.Create(new AzureKeyVaultOptions
        {
            SecretClient = secretClient
        });
        using var store = new AzureKeyVaultKeyStore(options);

        var keyId = KeyIdentifier.Prefixed("status");
        var version = KeyVersion.Initial;
        var rawKeyBytes = new byte[32];

        var props = SecretModelFactory.SecretProperties(name: "key-status-v1");
        props.Enabled = true;
        props.Tags["KeyId"] = keyId.Value;
        props.Tags["Version"] = "1";
        props.Tags["Status"] = "Active";

        var secret = SecretModelFactory.KeyVaultSecret(props, Convert.ToBase64String(rawKeyBytes));
        secretClient.GetSecretAsync(Arg.Any<string>(), Arg.Is<string?>(v => v == null), Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(Response.FromValue(secret, Substitute.For<Response>())));

        SecretProperties? updatedProps = null;
        secretClient.UpdateSecretPropertiesAsync(Arg.Do<SecretProperties>(p => updatedProps = p), Arg.Any<CancellationToken>())
            .Returns(callInfo => Task.FromResult(Response.FromValue(callInfo.Arg<SecretProperties>(), Substitute.For<Response>())));

        // Revoke
        var revokeResult = await store.UpdateStatusAsync(keyId, version, KeyStatus.Revoked);
        revokeResult.IsSuccess.Should().BeTrue();
        updatedProps.Should().NotBeNull();
        updatedProps!.Tags["Status"].Should().Be("Revoked");
        updatedProps.Tags.ContainsKey("RevokedAtUtc").Should().BeTrue();
        updatedProps.Tags["RevokedAtUtc"].Should().Contain("T").And.Contain("+00:00");
        updatedProps.Enabled.Should().BeFalse();

        // Active
        updatedProps = null;
        var activeResult = await store.UpdateStatusAsync(keyId, version, KeyStatus.Active);
        activeResult.IsSuccess.Should().BeTrue();
        updatedProps.Should().NotBeNull();
        updatedProps!.Tags["Status"].Should().Be("Active");
        updatedProps.Enabled.Should().BeTrue();

        // 404
        secretClient.GetSecretAsync(Arg.Is<string>(s => s.Contains("missing")), Arg.Is<string?>(v => v == null), Arg.Any<CancellationToken>())
            .Throws(new RequestFailedException(404, "Not found"));

        var missingId = KeyIdentifier.Prefixed("missing");
        var notFound = await store.UpdateStatusAsync(missingId, version, KeyStatus.Retired);
        notFound.IsFailure.Should().BeTrue();
        notFound.Error.Code.Should().Be("Security.KeyNotFound");
        notFound.Error.Description.Should().Contain($"{missingId}:{version}");

        // Update error
        secretClient.UpdateSecretPropertiesAsync(Arg.Any<SecretProperties>(), Arg.Any<CancellationToken>())
            .Throws(new RequestFailedException(500, "Update write failed"));

        var updateFail = await store.UpdateStatusAsync(keyId, version, KeyStatus.Retired);
        updateFail.IsFailure.Should().BeTrue();
        updateFail.Error.Description.Should().Contain("Azure Key Vault request failed with status 500: Update write failed");
    }
}
