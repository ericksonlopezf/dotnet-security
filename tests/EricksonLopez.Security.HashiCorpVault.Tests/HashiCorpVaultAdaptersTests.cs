// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.HashiCorpVault.Tests;

using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using AwesomeAssertions;
using EricksonLopez.Security.Abstractions.Errors;
using EricksonLopez.Security.Abstractions.KeyManagement;
using EricksonLopez.Security.Abstractions.Primitives;
using EricksonLopez.Security.Abstractions.Secrets;
using EricksonLopez.Security.HashiCorpVault;
using EricksonLopez.Security.Memory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Xunit;

public sealed class HashiCorpVaultAdaptersTests
{
    private static IOptions<HashiCorpVaultOptions> CreateOptions(Action<HashiCorpVaultOptions>? configure = null)
    {
        var options = new HashiCorpVaultOptions { EnableDevelopmentInMemoryStub = true };
        configure?.Invoke(options);
        return Options.Create(options);
    }

    [Fact]
    public void HashiCorpVaultOptions_PropertiesGetAndSet()
    {
        var options = new HashiCorpVaultOptions();
        options.VaultUrl.Should().BeNull();
        options.TransitMountPath.Should().Be("transit");
        options.KvMountPath.Should().Be("secret");
        options.SecretPathPrefix.Should().Be(string.Empty);
        options.EnableDevelopmentInMemoryStub.Should().BeFalse();
        options.Token.Should().BeNull();
        options.RoleId.Should().BeNull();
        options.SecretId.Should().BeNull();
        options.AppRoleMountPath.Should().Be("approle");
        options.Namespace.Should().BeNull();
        options.HttpClient.Should().BeNull();

        var url = new Uri("https://vault.custom:8200/");
        options.VaultUrl = url;
        options.TransitMountPath = "custom-transit";
        options.KvMountPath = "custom-secret";
        options.SecretPathPrefix = "app/";
        options.EnableDevelopmentInMemoryStub = true;
        options.Token = "s.token123";
        options.RoleId = "role-abc";
        options.SecretId = "secret-xyz";
        options.AppRoleMountPath = "custom-approle";
        options.Namespace = "ns-finance";

        options.VaultUrl.Should().Be(url);
        options.TransitMountPath.Should().Be("custom-transit");
        options.KvMountPath.Should().Be("custom-secret");
        options.SecretPathPrefix.Should().Be("app/");
        options.EnableDevelopmentInMemoryStub.Should().BeTrue();
        options.Token.Should().Be("s.token123");
        options.RoleId.Should().Be("role-abc");
        options.SecretId.Should().Be("secret-xyz");
        options.AppRoleMountPath.Should().Be("custom-approle");
        options.Namespace.Should().Be("ns-finance");
    }

    [Fact]
    public void HashiCorpVault_DefaultOptions_ThrowsInvalidOperationException_WhenStubNotEnabled()
    {
        var defaultOptions = Options.Create(new HashiCorpVaultOptions());
        var exSecret = Assert.Throws<InvalidOperationException>(() => new HashiCorpVaultSecretStore(defaultOptions));
        exSecret.Message.Should().Contain("HashiCorpVaultOptions.VaultUrl must be configured");

        var exKey = Assert.Throws<InvalidOperationException>(() => new HashiCorpVaultKeyStore(defaultOptions));
        exKey.Message.Should().Contain("HashiCorpVaultOptions.VaultUrl must be configured");
    }

    [Fact]
    public void HashiCorpVaultClient_ConstructorValidation()
    {
        Assert.Throws<ArgumentNullException>(() => new HashiCorpVaultClient(null!));

        var noUrl = new HashiCorpVaultOptions { VaultUrl = null };
        var exNoUrl = Assert.Throws<InvalidOperationException>(() => new HashiCorpVaultClient(noUrl));
        exNoUrl.Message.Should().Contain("HashiCorpVaultOptions.VaultUrl must be configured");

        var noAuth = new HashiCorpVaultOptions { VaultUrl = new Uri("http://127.0.0.1:8200"), Token = null, RoleId = null, SecretId = null };
        var exNoAuth = Assert.Throws<InvalidOperationException>(() => new HashiCorpVaultClient(noAuth));
        exNoAuth.Message.Should().Contain("HashiCorpVault authentication requires either a static Token or both RoleId and SecretId");
    }

    [Fact]
    public void HashiCorpVault_Constructors_NullArgumentChecks()
    {
        var options = CreateOptions();
        Assert.Throws<ArgumentNullException>(() => new HashiCorpVaultKeyStore(null!, Microsoft.Extensions.Logging.Abstractions.NullLogger<HashiCorpVaultKeyStore>.Instance));
        Assert.Throws<ArgumentNullException>(() => new HashiCorpVaultKeyStore(options, null!));

        Assert.Throws<ArgumentNullException>(() => new HashiCorpVaultSecretStore(null!, Microsoft.Extensions.Logging.Abstractions.NullLogger<HashiCorpVaultSecretStore>.Instance));
        Assert.Throws<ArgumentNullException>(() => new HashiCorpVaultSecretStore(options, null!));
    }

    [Fact]
    public void AddHashiCorpVaultSecurity_RegistersServicesAndValidatesNullArguments()
    {
        IServiceCollection nullServices = null!;
        Assert.Throws<ArgumentNullException>(() => nullServices.AddHashiCorpVaultSecurity());
        Assert.Throws<ArgumentNullException>(() => nullServices.AddHashiCorpVaultSecurity(_ => { }));
        Assert.Throws<ArgumentNullException>(() => new ServiceCollection().AddHashiCorpVaultSecurity(null!));

        var services = new ServiceCollection();
        services.AddSingleton(typeof(Microsoft.Extensions.Logging.ILogger<>), typeof(Microsoft.Extensions.Logging.Abstractions.NullLogger<>));
        services.AddHashiCorpVaultSecurity(o => o.EnableDevelopmentInMemoryStub = true);

        using var provider = services.BuildServiceProvider();
        var keyStore = provider.GetRequiredService<IKeyStore>();
        var secretStore = provider.GetRequiredService<ISecretStore>();

        keyStore.Should().NotBeNull().And.BeOfType<HashiCorpVaultKeyStore>();
        secretStore.Should().NotBeNull().And.BeOfType<HashiCorpVaultSecretStore>();

        var defaultServices = new ServiceCollection();
        defaultServices.AddSingleton(typeof(Microsoft.Extensions.Logging.ILogger<>), typeof(Microsoft.Extensions.Logging.Abstractions.NullLogger<>));
        defaultServices.AddHashiCorpVaultSecurity();
        using var defaultProvider = defaultServices.BuildServiceProvider();
        defaultProvider.GetRequiredService<IOptions<HashiCorpVaultOptions>>().Value.Should().NotBeNull();
    }

    [Fact]
    public async Task HashiCorpVault_Stores_Dispose_ClearsResources()
    {
        var options = CreateOptions();
        var keyStore = new HashiCorpVaultKeyStore(options);
        var secretStore = new HashiCorpVaultSecretStore(options);

        var keyId = KeyIdentifier.Prefixed("vault-disp");
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
    public async Task HashiCorpVaultSecretStore_SetAndGetSecret_RoundtripsSuccessfully()
    {
        var options = CreateOptions(o => o.SecretPathPrefix = "kv/data/");
        var secretStore = new HashiCorpVaultSecretStore(options);

        var setResult1 = await secretStore.SetSecretAsync("PaymentTokenKey", "vault-token-super-secret-999");
        setResult1.IsSuccess.Should().BeTrue();

        var setResult2 = await secretStore.SetSecretAsync("AuthSigningKey", "vault-jwt-signing-secret-888");
        setResult2.IsSuccess.Should().BeTrue();

        var getResult1 = await secretStore.GetSecretAsync("PaymentTokenKey");
        getResult1.IsSuccess.Should().BeTrue();
        getResult1.Value.UnsafeValue.Should().Be("vault-token-super-secret-999");
        getResult1.Value.ToString().Should().Be("[REDACTED]");

        var getResult2 = await secretStore.GetSecretAsync("AuthSigningKey");
        getResult2.IsSuccess.Should().BeTrue();
        getResult2.Value.UnsafeValue.Should().Be("vault-jwt-signing-secret-888");
    }

    [Fact]
    public async Task HashiCorpVaultSecretStore_InvalidAndMissingSecrets_ReturnFailure()
    {
        var options = CreateOptions();
        var secretStore = new HashiCorpVaultSecretStore(options);

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
    public void HashiCorpVaultSecretStore_NullOptions_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => new HashiCorpVaultSecretStore(null!));
    }

    [Fact]
    public void HashiCorpVaultKeyStore_NullOptions_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => new HashiCorpVaultKeyStore(null!));
    }

    [Fact]
    public async Task HashiCorpVaultKeyStore_SaveAndRetrieveKey_RoundtripsSuccessfully()
    {
        var options = CreateOptions(o =>
        {
            o.VaultUrl = new Uri("https://vault.corp:8200/");
            o.TransitMountPath = "transit";
        });
        var keyStore = new HashiCorpVaultKeyStore(options);

        var keyId = KeyIdentifier.Prefixed("vault");
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
    public async Task HashiCorpVaultKeyStore_ListMetadata_FiltersAndSortsCorrectly()
    {
        var options = CreateOptions();
        var keyStore = new HashiCorpVaultKeyStore(options);

        var keyId = KeyIdentifier.Prefixed("vault");
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
    public async Task HashiCorpVaultKeyStore_UpdateStatus_UpdatesCorrectlyAndSetsRevocationTime()
    {
        var options = CreateOptions();
        var keyStore = new HashiCorpVaultKeyStore(options);

        var keyId = KeyIdentifier.Prefixed("vault");
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
    public void AddHashiCorpVaultSecurity_RegistersServicesInContainer()
    {
        var services = new ServiceCollection();

        services.AddHashiCorpVaultSecurity(options =>
        {
            options.VaultUrl = new Uri("https://vault.internal:8200/");
            options.TransitMountPath = "transit";
            options.EnableDevelopmentInMemoryStub = true;
        });

        using var provider = services.BuildServiceProvider();

        provider.GetService<IKeyStore>().Should().NotBeNull();
        provider.GetService<ISecretStore>().Should().NotBeNull();
    }

    [Fact]
    public void AddHashiCorpVaultSecurity_NullArguments_ThrowsArgumentNullException()
    {
        var services = new ServiceCollection();
        Assert.Throws<ArgumentNullException>(() => ((IServiceCollection)null!).AddHashiCorpVaultSecurity(_ => { }));
        Assert.Throws<ArgumentNullException>(() => services.AddHashiCorpVaultSecurity(null!));
    }

    [Fact]
    public async Task HashiCorpVaultKeyStore_UpdateStatus_ToRetired_DoesNotSetRevocationTime()
    {
        var options = CreateOptions(o => o.VaultUrl = new Uri("https://vault.internal:8200/"));
        var keyStore = new HashiCorpVaultKeyStore(options);

        var keyId = KeyIdentifier.Prefixed("vault");
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
    public async Task HashiCorpVaultSecretStore_OverwritingExistingSecret_UpdatesSuccessfully()
    {
        var options = CreateOptions(o => o.VaultUrl = new Uri("https://vault.internal:8200/"));
        var secretStore = new HashiCorpVaultSecretStore(options);

        await secretStore.SetSecretAsync("Token", "InitialValue");
        var first = await secretStore.GetSecretAsync("Token");
        first.Value.UnsafeValue.Should().Be("InitialValue");

        await secretStore.SetSecretAsync("Token", "UpdatedValue");
        var second = await secretStore.GetSecretAsync("Token");
        second.Value.UnsafeValue.Should().Be("UpdatedValue");
    }

    [Fact]
    public async Task HashiCorpVaultSecretStore_WithInjectedError_ReturnsFailure()
    {
        var options = CreateOptions();
        var secretStore = new HashiCorpVaultSecretStore(options);

        // Pre-save secret so it exists
        (await secretStore.SetSecretAsync("secret", "val")).IsSuccess.Should().BeTrue();

        secretStore.InjectedError = SecurityError.InvalidCiphertext("HashiCorp Vault sealed");

        var getResult = await secretStore.GetSecretAsync("secret");
        getResult.IsFailure.Should().BeTrue();
        getResult.Error.Description.Should().Be("HashiCorp Vault sealed");

        var setResult = await secretStore.SetSecretAsync("secret", "new-val");
        setResult.IsFailure.Should().BeTrue();
        setResult.Error.Description.Should().Be("HashiCorp Vault sealed");
    }

    [Fact]
    public async Task HashiCorpVaultKeyStore_WithInjectedError_ReturnsFailure()
    {
        var options = CreateOptions();
        var keyStore = new HashiCorpVaultKeyStore(options);

        var keyId = KeyIdentifier.Prefixed("vault");
        var version = KeyVersion.Initial;
        var metadata = new KeyMetadata(keyId, version, KeyPurpose.Encryption, KeyStatus.Active, "AES-256", DateTimeOffset.UtcNow);
        var key = new CryptographicKey(metadata, SecretBuffer.CreateRandom(32));

        // Pre-save key so it exists in store
        (await keyStore.SaveKeyAsync(key)).IsSuccess.Should().BeTrue();

        keyStore.InjectedError = SecurityError.InvalidCiphertext("HashiCorp Vault transit engine sealed");

        var saveResult = await keyStore.SaveKeyAsync(key);
        saveResult.IsFailure.Should().BeTrue();
        saveResult.Error.Description.Should().Be("HashiCorp Vault transit engine sealed");

        var getResult = await keyStore.GetKeyAsync(keyId, version);
        getResult.IsFailure.Should().BeTrue();
        getResult.Error.Description.Should().Be("HashiCorp Vault transit engine sealed");

        var listResult = await keyStore.ListMetadataAsync();
        listResult.IsFailure.Should().BeTrue();
        listResult.Error.Description.Should().Be("HashiCorp Vault transit engine sealed");

        var updateResult = await keyStore.UpdateStatusAsync(keyId, version, KeyStatus.Revoked);
        updateResult.IsFailure.Should().BeTrue();
        updateResult.Error.Description.Should().Be("HashiCorp Vault transit engine sealed");
    }

    [Fact]
    public async Task HashiCorpVault_CancelledToken_ThrowsOperationCanceledException()
    {
        var options = CreateOptions();
        var secretStore = new HashiCorpVaultSecretStore(options);
        var keyStore = new HashiCorpVaultKeyStore(options);

        using var cts = new CancellationTokenSource();
        cts.Cancel();

        var keyId = KeyIdentifier.Prefixed("vault");
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
