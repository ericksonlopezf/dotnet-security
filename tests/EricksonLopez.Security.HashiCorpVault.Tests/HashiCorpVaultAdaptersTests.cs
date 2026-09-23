// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.HashiCorpVault.Tests;

using System;
using System.Linq;
using System.Net;
using System.Net.Http;
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
using System.Text.Json;
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

        var roleOnly = new HashiCorpVaultOptions { VaultUrl = new Uri("http://127.0.0.1:8200"), Token = null, RoleId = "my-role", SecretId = null };
        var exRoleOnly = Assert.Throws<InvalidOperationException>(() => new HashiCorpVaultClient(roleOnly));
        exRoleOnly.Message.Should().Contain("HashiCorpVault authentication requires either a static Token or both RoleId and SecretId");

        var secretOnly = new HashiCorpVaultOptions { VaultUrl = new Uri("http://127.0.0.1:8200"), Token = null, RoleId = null, SecretId = "my-secret" };
        var exSecretOnly = Assert.Throws<InvalidOperationException>(() => new HashiCorpVaultClient(secretOnly));
        exSecretOnly.Message.Should().Contain("HashiCorpVault authentication requires either a static Token or both RoleId and SecretId");

        using var clientDefaultHttp = new HashiCorpVaultClient(new HashiCorpVaultOptions
        {
            VaultUrl = new Uri("http://127.0.0.1:8200"),
            Token = "s.token",
            HttpClient = null
        });
        clientDefaultHttp.Should().NotBeNull();
    }

    [Fact]
    public void HashiCorpVault_Constructors_NullArgumentChecks()
    {
        var stubOptions = CreateOptions();
        var liveOptions = Options.Create(new HashiCorpVaultOptions
        {
            VaultUrl = new Uri("http://127.0.0.1:8200"),
            Token = "s.token",
            EnableDevelopmentInMemoryStub = false
        });

        // KeyStore
        var exKeyOpt = Assert.Throws<ArgumentNullException>(() => new HashiCorpVaultKeyStore(null!, Microsoft.Extensions.Logging.Abstractions.NullLogger<HashiCorpVaultKeyStore>.Instance));
        exKeyOpt.ParamName.Should().Be("options");

        var exKeyLogStub = Assert.Throws<ArgumentNullException>(() => new HashiCorpVaultKeyStore(stubOptions, null!));
        exKeyLogStub.ParamName.Should().Be("logger");
        exKeyLogStub.StackTrace.Should().NotContain("LoggerExtensions");

        var exKeyLogLive = Assert.Throws<ArgumentNullException>(() => new HashiCorpVaultKeyStore(liveOptions, null!));
        exKeyLogLive.ParamName.Should().Be("logger");

        // SecretStore
        var exSecOpt = Assert.Throws<ArgumentNullException>(() => new HashiCorpVaultSecretStore(null!, Microsoft.Extensions.Logging.Abstractions.NullLogger<HashiCorpVaultSecretStore>.Instance));
        exSecOpt.ParamName.Should().Be("options");

        var exSecLogStub = Assert.Throws<ArgumentNullException>(() => new HashiCorpVaultSecretStore(stubOptions, null!));
        exSecLogStub.ParamName.Should().Be("logger");
        exSecLogStub.StackTrace.Should().NotContain("LoggerExtensions");

        var exSecLogLive = Assert.Throws<ArgumentNullException>(() => new HashiCorpVaultSecretStore(liveOptions, null!));
        exSecLogLive.ParamName.Should().Be("logger");
    }

    [Fact]
    public void AddHashiCorpVaultSecurity_RegistersServicesAndValidatesNullArguments()
    {
        IServiceCollection nullServices = null!;
        var exNullServices1 = Assert.Throws<ArgumentNullException>(() => nullServices.AddHashiCorpVaultSecurity());
        exNullServices1.ParamName.Should().Be("services");

        var exServices = Assert.Throws<ArgumentNullException>(() => nullServices.AddHashiCorpVaultSecurity(_ => { }));
        exServices.ParamName.Should().Be("services");
        exServices.StackTrace.Should().NotContain("OptionsServiceCollectionExtensions");

        var exConfigure = Assert.Throws<ArgumentNullException>(() => new ServiceCollection().AddHashiCorpVaultSecurity(null!));
        exConfigure.ParamName.Should().Be("configure");
        exConfigure.StackTrace.Should().NotContain("OptionsServiceCollectionExtensions");

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

    private sealed class TestHttpMessageHandler : HttpMessageHandler
    {
        private readonly Func<HttpRequestMessage, Task<HttpResponseMessage>> _handler;

        public TestHttpMessageHandler(Func<HttpRequestMessage, Task<HttpResponseMessage>> handler)
        {
            _handler = handler;
        }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            => _handler(request);
    }

    private static HttpClient CreateMockHttpClient(Func<HttpRequestMessage, Task<HttpResponseMessage>> handler)
    {
        return new HttpClient(new TestHttpMessageHandler(handler))
        {
            BaseAddress = new Uri("http://127.0.0.1:8200/")
        };
    }

    [Fact]
    public async Task HashiCorpVaultClient_AppRoleAuth_TokenCaching_And_Namespace()
    {
        var loginCalls = 0;
        var secretCalls = 0;

        using var httpClient = CreateMockHttpClient(async req =>
        {
            var uri = req.RequestUri!.ToString();
            if (uri.Contains("v1/auth/approle/login", StringComparison.Ordinal))
            {
                loginCalls++;
                req.Headers.Contains("X-Vault-Namespace").Should().BeTrue();
                req.Headers.GetValues("X-Vault-Namespace").First().Should().Be("my-ns");

                var body = await req.Content!.ReadAsStringAsync();
                body.Should().Contain("test-role");
                body.Should().Contain("test-secret");

                var responseJson = "{\"auth\":{\"client_token\":\"s.mock-approle-token\",\"lease_duration\":3600}}";
                return new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(responseJson, System.Text.Encoding.UTF8, "application/json")
                };
            }

            if (uri.Contains("v1/secret/data/test-secret", StringComparison.Ordinal))
            {
                secretCalls++;
                req.Headers.Contains("X-Vault-Token").Should().BeTrue();
                req.Headers.GetValues("X-Vault-Token").First().Should().Be("s.mock-approle-token");
                req.Headers.Contains("X-Vault-Namespace").Should().BeTrue();
                req.Headers.GetValues("X-Vault-Namespace").First().Should().Be("my-ns");

                var secretJson = "{\"data\":{\"data\":{\"value\":\"hello-world\"}}}";
                return new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(secretJson, System.Text.Encoding.UTF8, "application/json")
                };
            }

            return new HttpResponseMessage(HttpStatusCode.NotFound);
        });

        var options = new HashiCorpVaultOptions
        {
            VaultUrl = new Uri("http://127.0.0.1:8200/"),
            RoleId = "test-role",
            SecretId = "test-secret",
            Namespace = "my-ns",
            HttpClient = httpClient,
            EnableDevelopmentInMemoryStub = false
        };

        using var client = new HashiCorpVaultClient(options);

        // First call logs in and retrieves secret
        var res1 = await client.ReadKvSecretAsync("test-secret", CancellationToken.None);
        res1.IsSuccess.Should().BeTrue();
        res1.Value.Should().Be("hello-world");
        loginCalls.Should().Be(1);
        secretCalls.Should().Be(1);

        // Second call should reuse the cached token without logging in again
        var res2 = await client.ReadKvSecretAsync("test-secret", CancellationToken.None);
        res2.IsSuccess.Should().BeTrue();
        res2.Value.Should().Be("hello-world");
        loginCalls.Should().Be(1);
        secretCalls.Should().Be(2);
    }

    [Fact]
    public async Task HashiCorpVaultClient_AppRoleAuth_Failures_ThrowExpectedExceptions()
    {
        // 401 Unauthorized
        using var client401 = new HashiCorpVaultClient(new HashiCorpVaultOptions
        {
            VaultUrl = new Uri("http://127.0.0.1:8200/"),
            RoleId = "bad-role",
            SecretId = "bad-secret",
            HttpClient = CreateMockHttpClient(_ => Task.FromResult(new HttpResponseMessage(HttpStatusCode.Unauthorized)
            {
                Content = new StringContent("{\"errors\":[\"invalid credentials\"]}")
            })),
            EnableDevelopmentInMemoryStub = false
        });

        var ex401 = await Assert.ThrowsAsync<InvalidOperationException>(() => client401.ReadKvSecretAsync("s", CancellationToken.None).AsTask());
        ex401.Message.Should().Contain("HashiCorp Vault AppRole login failed (Unauthorized)");

        // Missing 'auth' object
        using var clientNoAuth = new HashiCorpVaultClient(new HashiCorpVaultOptions
        {
            VaultUrl = new Uri("http://127.0.0.1:8200/"),
            RoleId = "r",
            SecretId = "s",
            HttpClient = CreateMockHttpClient(_ => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("{\"data\":{}}")
            })),
            EnableDevelopmentInMemoryStub = false
        });

        var exNoAuth = await Assert.ThrowsAsync<InvalidOperationException>(() => clientNoAuth.ReadKvSecretAsync("s", CancellationToken.None).AsTask());
        exNoAuth.Message.Should().Contain("lacked the 'auth' object");

        // Missing or empty client_token
        using var clientEmptyToken = new HashiCorpVaultClient(new HashiCorpVaultOptions
        {
            VaultUrl = new Uri("http://127.0.0.1:8200/"),
            RoleId = "r",
            SecretId = "s",
            HttpClient = CreateMockHttpClient(_ => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("{\"auth\":{\"client_token\":\"   \"}}")
            })),
            EnableDevelopmentInMemoryStub = false
        });

        var exEmptyToken = await Assert.ThrowsAsync<InvalidOperationException>(() => clientEmptyToken.ReadKvSecretAsync("s", CancellationToken.None).AsTask());
        exEmptyToken.Message.Should().Contain("valid client_token");
    }

    [Fact]
    public async Task HashiCorpVaultSecretStore_LiveClient_GetAndSetSecret_SuccessAndFailures()
    {
        var storedSecretValue = "original-secret";

        using var httpClient = CreateMockHttpClient(req =>
        {
            var uri = req.RequestUri!.ToString();
            if (req.Method == HttpMethod.Get && uri.Contains("v1/secret/data/my-secret", StringComparison.Ordinal))
            {
                var json = $"{{\"data\":{{\"data\":{{\"value\":\"{storedSecretValue}\"}}}}}}";
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(json)
                });
            }

            if (req.Method == HttpMethod.Get && uri.Contains("v1/secret/data/raw-secret", StringComparison.Ordinal))
            {
                var json = "{\"data\":{\"data\":{\"other\":\"custom-json\"}}}";
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(json)
                });
            }

            if (req.Method == HttpMethod.Get && uri.Contains("v1/secret/data/missing", StringComparison.Ordinal))
            {
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
            }

            if (req.Method == HttpMethod.Get && uri.Contains("v1/secret/data/error", StringComparison.Ordinal))
            {
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.InternalServerError)
                {
                    Content = new StringContent("KV engine error")
                });
            }

            if (req.Method == HttpMethod.Post && uri.Contains("v1/secret/data/my-secret", StringComparison.Ordinal))
            {
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK));
            }

            if (req.Method == HttpMethod.Post && uri.Contains("v1/secret/data/write-error", StringComparison.Ordinal))
            {
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.InternalServerError)
                {
                    Content = new StringContent("Write failed")
                });
            }

            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
        });

        var options = Options.Create(new HashiCorpVaultOptions
        {
            VaultUrl = new Uri("http://127.0.0.1:8200/"),
            Token = "s.static-token",
            HttpClient = httpClient,
            EnableDevelopmentInMemoryStub = false
        });

        using var store = new HashiCorpVaultSecretStore(options);

        // Get success with value prop
        var getRes = await store.GetSecretAsync("my-secret");
        getRes.IsSuccess.Should().BeTrue();
        getRes.Value.UnsafeValue.Should().Be("original-secret");

        // Get success with raw JSON
        var getRaw = await store.GetSecretAsync("raw-secret");
        getRaw.IsSuccess.Should().BeTrue();
        getRaw.Value.UnsafeValue.Should().Contain("custom-json");

        // Get 404
        var notFound = await store.GetSecretAsync("missing");
        notFound.IsFailure.Should().BeTrue();
        notFound.Error.Code.Should().Be("Security.SecretNotFound");

        // Get 500
        var getErr = await store.GetSecretAsync("error");
        getErr.IsFailure.Should().BeTrue();
        getErr.Error.Description.Should().Contain("Vault read failed with status InternalServerError");

        // Set success
        var setRes = await store.SetSecretAsync("my-secret", "new-val");
        setRes.IsSuccess.Should().BeTrue();

        // Set failure
        var setErr = await store.SetSecretAsync("write-error", "new-val");
        setErr.IsFailure.Should().BeTrue();
        setErr.Error.Description.Should().Contain("Vault write failed with status InternalServerError: Write failed");

        // Empty secret name validation
        (await store.GetSecretAsync("")).IsFailure.Should().BeTrue();
        (await store.SetSecretAsync("", "val")).IsFailure.Should().BeTrue();
    }

    [Fact]
    public async Task HashiCorpVaultKeyStore_LiveClient_SaveKey_GetKey_UpdateStatus_And_ListMetadata()
    {
        var rawKey = new byte[] { 10, 20, 30, 40, 50, 60, 70, 80, 11, 22, 33, 44, 55, 66, 77, 88, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
        string? storedKeyJson = null;

        using var httpClient = CreateMockHttpClient(async req =>
        {
            var uri = req.RequestUri!.ToString();

            if (req.Method == HttpMethod.Post && uri.Contains("keys/my-key", StringComparison.Ordinal) && uri.EndsWith("/v1", StringComparison.Ordinal))
            {
                var body = await req.Content!.ReadAsStringAsync();
                storedKeyJson = body;
                return new HttpResponseMessage(HttpStatusCode.OK);
            }

            if (req.Method == HttpMethod.Get && uri.Contains("keys/my-key", StringComparison.Ordinal) && uri.EndsWith("/v1", StringComparison.Ordinal))
            {
                if (storedKeyJson != null)
                {
                    return new HttpResponseMessage(HttpStatusCode.OK)
                    {
                        Content = new StringContent($"{{\"data\":{storedKeyJson}}}")
                    };
                }
                return new HttpResponseMessage(HttpStatusCode.NotFound);
            }

            if (req.Method == HttpMethod.Get && uri.Contains("keys/missing", StringComparison.Ordinal))
            {
                return new HttpResponseMessage(HttpStatusCode.NotFound);
            }

            if (req.Method == HttpMethod.Get && uri.Contains("keys/error", StringComparison.Ordinal))
            {
                return new HttpResponseMessage(HttpStatusCode.InternalServerError)
                {
                    Content = new StringContent("Transit error")
                };
            }

            if (req.Method == HttpMethod.Post && uri.Contains("keys/fail-write", StringComparison.Ordinal))
            {
                return new HttpResponseMessage(HttpStatusCode.InternalServerError)
                {
                    Content = new StringContent("Key write error")
                };
            }

            return new HttpResponseMessage(HttpStatusCode.NotFound);
        });

        var options = Options.Create(new HashiCorpVaultOptions
        {
            VaultUrl = new Uri("http://127.0.0.1:8200/"),
            Token = "s.key-token",
            HttpClient = httpClient,
            EnableDevelopmentInMemoryStub = false
        });

        using var store = new HashiCorpVaultKeyStore(options);

        // ListMetadata in live mode returns empty list
        var listRes = await store.ListMetadataAsync();
        listRes.IsSuccess.Should().BeTrue();
        listRes.Value.Should().BeEmpty();

        var keyId = KeyIdentifier.Prefixed("my-key");
        var version = KeyVersion.Initial;
        var metadata = new KeyMetadata(keyId, version, KeyPurpose.Encryption, KeyStatus.Active, "AES-256-GCM", DateTimeOffset.UtcNow);
        var key = new CryptographicKey(metadata, SecretBuffer.FromSpan(rawKey));

        // SaveKeyAsync success
        var saveRes = await store.SaveKeyAsync(key);
        saveRes.IsSuccess.Should().BeTrue();

        // SaveKeyAsync failure
        var failKey = new CryptographicKey(metadata with { KeyId = KeyIdentifier.Prefixed("fail-write") }, SecretBuffer.FromSpan(rawKey));
        var saveFail = await store.SaveKeyAsync(failKey);
        saveFail.IsFailure.Should().BeTrue();
        saveFail.Error.Description.Should().Contain("Vault key write failed with status InternalServerError: Key write error");

        // GetKeyAsync success
        var getRes = await store.GetKeyAsync(keyId, version);
        getRes.IsSuccess.Should().BeTrue();
        getRes.Value.Metadata.Purpose.Should().Be(KeyPurpose.Encryption);
        getRes.Value.GetKeyBytes()[0].Should().Be(10);

        // GetKeyAsync 404
        var missingId = KeyIdentifier.Prefixed("missing");
        var notFound = await store.GetKeyAsync(missingId, version);
        notFound.IsFailure.Should().BeTrue();
        notFound.Error.Code.Should().Be("Security.KeyNotFound");
        notFound.Error.Description.Should().Contain(missingId.Value).And.Contain(version.ToString());

        // GetKeyAsync 500
        var getErr = await store.GetKeyAsync(KeyIdentifier.Prefixed("error"), version);
        getErr.IsFailure.Should().BeTrue();
        getErr.Error.Description.Should().Contain("Vault key read failed with status InternalServerError: Transit error");

        // UpdateStatusAsync success to Retired (not Revoked, RevokedAtUtc should remain null)
        var retireRes = await store.UpdateStatusAsync(keyId, version, KeyStatus.Retired);
        retireRes.IsSuccess.Should().BeTrue();
        storedKeyJson.Should().Contain("\"status\":\"Retired\"");
        storedKeyJson.Should().NotContain("\"revoked_at\":");

        // UpdateStatusAsync success to Revoked
        var revokeRes = await store.UpdateStatusAsync(keyId, version, KeyStatus.Revoked);
        revokeRes.IsSuccess.Should().BeTrue();
        storedKeyJson.Should().Contain("\"status\":\"Revoked\"");
        storedKeyJson.Should().Contain("\"revoked_at\":");

        // UpdateStatusAsync success to Active
        var activeRes = await store.UpdateStatusAsync(keyId, version, KeyStatus.Active);
        activeRes.IsSuccess.Should().BeTrue();
        storedKeyJson.Should().Contain("\"status\":\"Active\"");

        // UpdateStatusAsync when key not found
        var updateNotFound = await store.UpdateStatusAsync(KeyIdentifier.Prefixed("missing"), version, KeyStatus.Retired);
        updateNotFound.IsFailure.Should().BeTrue();
        updateNotFound.Error.Code.Should().Be("Security.KeyNotFound");

        // UpdateStatusAsync when write fails
        var updateWriteFail = await store.UpdateStatusAsync(KeyIdentifier.Prefixed("fail-write"), version, KeyStatus.Retired);
        updateWriteFail.IsFailure.Should().BeTrue();
    }

    [Fact]
    public async Task HashiCorpVaultClient_Disposal_HandlesOwnsHttpClientAndCallingAfterDispose()
    {
        // Unowned HttpClient
        var unownedHandler = new TestHttpMessageHandler(_ => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)));
        var unownedHttp = new HttpClient(unownedHandler) { BaseAddress = new Uri("http://127.0.0.1:8200/") };
        var optionsUnowned = new HashiCorpVaultOptions
        {
            VaultUrl = new Uri("http://127.0.0.1:8200/"),
            Token = "s.token",
            HttpClient = unownedHttp
        };

        var clientUnowned = new HashiCorpVaultClient(optionsUnowned);
        clientUnowned.Dispose();
        clientUnowned.Dispose(); // idempotent

        var act = () => unownedHttp.CancelPendingRequests();
        act.Should().NotThrow();

        await Assert.ThrowsAsync<ObjectDisposedException>(() => clientUnowned.ReadKvSecretAsync("s", CancellationToken.None).AsTask());

        // Owned HttpClient
        var optionsOwned = new HashiCorpVaultOptions
        {
            VaultUrl = new Uri("http://127.0.0.1:8200/"),
            Token = "s.token",
            HttpClient = null
        };

        var clientOwned = new HashiCorpVaultClient(optionsOwned);
        clientOwned.Dispose();
        await Assert.ThrowsAsync<ObjectDisposedException>(() => clientOwned.ReadKvSecretAsync("s", CancellationToken.None).AsTask());
    }

    [Fact]
    public async Task HashiCorpVault_LiveStores_Dispose_DisposesInternalClient()
    {
        var options = Options.Create(new HashiCorpVaultOptions
        {
            VaultUrl = new Uri("http://127.0.0.1:8200/"),
            Token = "s.token",
            EnableDevelopmentInMemoryStub = false
        });

        var keyStore = new HashiCorpVaultKeyStore(options);
        var secretStore = new HashiCorpVaultSecretStore(options);

        keyStore.Dispose();
        secretStore.Dispose();

        await Assert.ThrowsAsync<ObjectDisposedException>(() => keyStore.GetKeyAsync(KeyIdentifier.Prefixed("k"), KeyVersion.Initial).AsTask());
        await Assert.ThrowsAsync<ObjectDisposedException>(() => secretStore.GetSecretAsync("sec").AsTask());
    }

    [Fact]
    public void HashiCorpVaultClient_Serializers_ProduceValidJson()
    {
        // 1. SerializeAppRoleLogin
        var appRoleBytes = HashiCorpVaultClient.SerializeAppRoleLogin("app-role-id", "app-secret-id");
        var appRoleJson = System.Text.Encoding.UTF8.GetString(appRoleBytes);
        using var appRoleDoc = JsonDocument.Parse(appRoleJson);
        appRoleDoc.RootElement.GetProperty("role_id").GetString().Should().Be("app-role-id");
        appRoleDoc.RootElement.GetProperty("secret_id").GetString().Should().Be("app-secret-id");

        // 2. SerializeKvSecretWrite
        var kvBytes = HashiCorpVaultClient.SerializeKvSecretWrite("my-secret-value");
        var kvJson = System.Text.Encoding.UTF8.GetString(kvBytes);
        using var kvDoc = JsonDocument.Parse(kvJson);
        kvDoc.RootElement.GetProperty("data").GetProperty("value").GetString().Should().Be("my-secret-value");

        // 3. SerializeKeyDataWrite with full metadata
        var keyId = KeyIdentifier.Prefixed("vault-key");
        var version = new KeyVersion(2);
        var now = DateTimeOffset.UtcNow;
        var expires = now.AddDays(30);
        var revoked = now.AddDays(15);
        var metaFull = new KeyMetadata(keyId, version, KeyPurpose.Signing, KeyStatus.Revoked, "HMAC-SHA256", now, expires, revoked);
        var rawKey = new byte[] { 1, 2, 3, 4, 5 };

        var fullBytes = HashiCorpVaultClient.SerializeKeyDataWrite(keyId, version, metaFull, rawKey);
        var fullJson = System.Text.Encoding.UTF8.GetString(fullBytes);
        using var fullDoc = JsonDocument.Parse(fullJson);
        var fullData = fullDoc.RootElement.GetProperty("data");
        fullData.GetProperty("key_bytes").GetString().Should().Be(Convert.ToBase64String(rawKey));
        fullData.GetProperty("key_id").GetString().Should().Be(keyId.Value);
        fullData.GetProperty("version").GetString().Should().Be("2");
        fullData.GetProperty("purpose").GetString().Should().Be("Signing");
        fullData.GetProperty("status").GetString().Should().Be("Revoked");
        fullData.GetProperty("algorithm").GetString().Should().Be("HMAC-SHA256");
        fullData.GetProperty("created_at").GetString().Should().Contain("T").And.Contain("+00:00");
        fullData.GetProperty("expires_at").GetString().Should().Contain("T").And.Contain("+00:00");
        fullData.GetProperty("revoked_at").GetString().Should().Contain("T").And.Contain("+00:00");

        // 4. SerializeKeyDataWrite without expires and revoked
        var metaMinimal = new KeyMetadata(keyId, KeyVersion.Initial, KeyPurpose.Encryption, KeyStatus.Active, "AES-256-GCM", now);
        var minBytes = HashiCorpVaultClient.SerializeKeyDataWrite(keyId, KeyVersion.Initial, metaMinimal, rawKey);
        var minJson = System.Text.Encoding.UTF8.GetString(minBytes);
        using var minDoc = JsonDocument.Parse(minJson);
        var minData = minDoc.RootElement.GetProperty("data");
        minData.TryGetProperty("expires_at", out _).Should().BeFalse();
        minData.TryGetProperty("revoked_at", out _).Should().BeFalse();
    }

    [Fact]
    public async Task HashiCorpVaultClient_AppRoleAuth_LeaseDurationBoundary_And_Expiration()
    {
        var loginCount = 0;

        using var httpClient = CreateMockHttpClient(req =>
        {
            var uri = req.RequestUri!.ToString();
            if (uri.Contains("login", StringComparison.Ordinal))
            {
                loginCount++;
                req.Content!.Headers.ContentType!.MediaType.Should().Be("application/json");
                req.Content!.Headers.ContentType!.CharSet.Should().Be("utf-8");

                // lease_duration 10 exercises Math.Max(30, leaseDuration - 30) => Math.Max(30, -20) == 30
                var json = "{\"auth\":{\"client_token\":\"s.boundary-token\",\"lease_duration\":10}}";
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(json, System.Text.Encoding.UTF8, "application/json")
                });
            }

            if (uri.Contains("secret/data/boundary-secret", StringComparison.Ordinal))
            {
                var secretJson = "{\"data\":{\"data\":{\"value\":\"boundary-val\"}}}";
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(secretJson, System.Text.Encoding.UTF8, "application/json")
                });
            }

            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
        });

        var options = new HashiCorpVaultOptions
        {
            VaultUrl = new Uri("http://127.0.0.1:8200/"),
            RoleId = "role",
            SecretId = "secret",
            HttpClient = httpClient,
            EnableDevelopmentInMemoryStub = false
        };

        using var client = new HashiCorpVaultClient(options);

        // First call logs in
        var res1 = await client.ReadKvSecretAsync("boundary-secret", CancellationToken.None);
        res1.IsSuccess.Should().BeTrue();
        loginCount.Should().Be(1);

        // Second call reuses cached token (Math.Max(30, -20) kept it valid for 30s)
        var res2 = await client.ReadKvSecretAsync("boundary-secret", CancellationToken.None);
        res2.IsSuccess.Should().BeTrue();
        loginCount.Should().Be(1);
    }

    [Fact]
    public async Task HashiCorpVaultClient_ReadKeyDataAsync_FallbacksAndMalformedJson()
    {
        var sampleKeyId = KeyIdentifier.Prefixed("fallback-key");
        var sampleVersion = new KeyVersion(3);

        using var httpClient = CreateMockHttpClient(req =>
        {
            var uri = req.RequestUri!.ToString();

            if (uri.Contains("keys/fallback-key", StringComparison.Ordinal))
            {
                // Root data with empty inner data
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent("{\"data\":{\"data\":{}}}")
                });
            }

            if (uri.Contains("keys/malformed-data", StringComparison.Ordinal))
            {
                // Non-string or invalid fields to test fallbacks
                var json = "{\"data\":{\"data\":{\"key_bytes\":\"AQID\",\"key_id\":\"\",\"version\":\"notnum\",\"purpose\":\"InvalidPurpose\",\"status\":\"InvalidStatus\",\"algorithm\":\"CHACHA20-POLY1305\",\"created_at\":\"2025-01-01T00:00:00Z\",\"expires_at\":\"2026-01-01T00:00:00Z\",\"revoked_at\":\"2025-06-01T00:00:00Z\"}}}";
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(json)
                });
            }

            if (uri.Contains("keys/non-string-bytes", StringComparison.Ordinal))
            {
                // key_bytes is a number instead of string
                var json = "{\"data\":{\"data\":{\"key_bytes\":12345,\"key_id\":999}}}";
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(json)
                });
            }

            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
        });

        var options = new HashiCorpVaultOptions
        {
            VaultUrl = new Uri("http://127.0.0.1:8200/"),
            Token = "s.token",
            HttpClient = httpClient,
            EnableDevelopmentInMemoryStub = false
        };

        using var client = new HashiCorpVaultClient(options);

        // 1. Empty data fallbacks
        var emptyRes = await client.ReadKeyDataAsync(sampleKeyId, sampleVersion, CancellationToken.None);
        emptyRes.IsSuccess.Should().BeTrue();
        var (emptyMeta, emptyBytes) = emptyRes.Value;
        emptyBytes.Should().BeEmpty();
        emptyMeta.KeyId.Should().Be(sampleKeyId);
        emptyMeta.Version.Should().Be(sampleVersion);
        emptyMeta.Purpose.Should().Be(KeyPurpose.Encryption);
        emptyMeta.Status.Should().Be(KeyStatus.Active);
        emptyMeta.AlgorithmId.Should().Be("AES-256-GCM");

        // 2. Malformed fields fallbacks
        var malformedKeyId = KeyIdentifier.Prefixed("malformed-data");
        var malformedRes2 = await client.ReadKeyDataAsync(malformedKeyId, sampleVersion, CancellationToken.None);
        malformedRes2.IsSuccess.Should().BeTrue();
        var (malformedMeta, malformedBytes) = malformedRes2.Value;
        malformedBytes.Should().Equal(new byte[] { 1, 2, 3 });
        malformedMeta.KeyId.Should().Be(malformedKeyId);
        malformedMeta.Version.Should().Be(sampleVersion);
        malformedMeta.Purpose.Should().Be(KeyPurpose.Encryption);
        malformedMeta.Status.Should().Be(KeyStatus.Active);
        malformedMeta.AlgorithmId.Should().Be("CHACHA20-POLY1305");
        malformedMeta.ExpiresAtUtc.Should().NotBeNull();
        malformedMeta.RevokedAtUtc.Should().NotBeNull();

        // 3. Non-string key_bytes
        var nonStringKeyId = KeyIdentifier.Prefixed("non-string-bytes");
        var nonStringRes = await client.ReadKeyDataAsync(nonStringKeyId, sampleVersion, CancellationToken.None);
        nonStringRes.IsSuccess.Should().BeTrue();
        nonStringRes.Value.KeyBytes.Should().BeEmpty();

        // 4. 404 Description check
        var notFoundKeyId = KeyIdentifier.Prefixed("not-found");
        var notFoundRes = await client.ReadKeyDataAsync(notFoundKeyId, sampleVersion, CancellationToken.None);
        notFoundRes.IsFailure.Should().BeTrue();
        notFoundRes.Error.Description.Should().Contain(notFoundKeyId.Value).And.Contain(sampleVersion.Value.ToString());
    }

    [Fact]
    public async Task HashiCorpVaultClient_DisposedOperations_ThrowObjectDisposedException()
    {
        var options = new HashiCorpVaultOptions
        {
            VaultUrl = new Uri("http://127.0.0.1:8200/"),
            Token = "s.token",
            HttpClient = CreateMockHttpClient(_ => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)))
        };

        var client = new HashiCorpVaultClient(options);
        client.Dispose();

        var keyId = KeyIdentifier.Prefixed("k");
        var version = KeyVersion.Initial;
        var meta = new KeyMetadata(keyId, version, KeyPurpose.Encryption, KeyStatus.Active, "AES-256", DateTimeOffset.UtcNow);

        await Assert.ThrowsAsync<ObjectDisposedException>(() => client.ReadKvSecretAsync("s", CancellationToken.None).AsTask());
        await Assert.ThrowsAsync<ObjectDisposedException>(() => client.WriteKvSecretAsync("s", "v", CancellationToken.None).AsTask());
        await Assert.ThrowsAsync<ObjectDisposedException>(() => client.ReadKeyDataAsync(keyId, version, CancellationToken.None).AsTask());
        await Assert.ThrowsAsync<ObjectDisposedException>(() => client.WriteKeyDataAsync(keyId, version, meta, new byte[] { 1 }, CancellationToken.None).AsTask());
        await Assert.ThrowsAsync<ObjectDisposedException>(() => client.UpdateKeyStatusAsync(keyId, version, KeyStatus.Revoked, CancellationToken.None).AsTask());
    }

    [Fact]
    public async Task HashiCorpVaultClient_EnsureTokenAsync_DoubleCheckedTokenCachingAndLeaseDuration()
    {
        var loginCount = 0;
        var httpClient = CreateMockHttpClient(req =>
        {
            var uri = req.RequestUri?.ToString() ?? string.Empty;
            if (uri.Contains("auth/approle/login", StringComparison.Ordinal))
            {
                Interlocked.Increment(ref loginCount);
                req.Content.Should().NotBeNull();
                req.Content!.Headers.ContentType!.MediaType.Should().Be("application/json");
                req.Content.Headers.ContentType.CharSet.Should().Be("utf-8");
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent("{\"auth\":{\"client_token\":\"test-approle-token\",\"lease_duration\":120}}")
                });
            }

            if (uri.Contains("secret/data/cache-test", StringComparison.Ordinal))
            {
                req.Headers.Contains("X-Vault-Token").Should().BeTrue();
                req.Headers.GetValues("X-Vault-Token").First().Should().Be("test-approle-token");
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent("{\"data\":{\"data\":{\"value\":\"cache-val\"}}}")
                });
            }

            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
        });

        var options = new HashiCorpVaultOptions
        {
            VaultUrl = new Uri("http://127.0.0.1:8200/"),
            RoleId = "test-role",
            SecretId = "test-secret",
            HttpClient = httpClient,
            EnableDevelopmentInMemoryStub = false
        };

        using var client = new HashiCorpVaultClient(options);

        // First call triggers login
        var res1 = await client.ReadKvSecretAsync("cache-test", CancellationToken.None);
        res1.IsSuccess.Should().BeTrue();
        res1.Value.Should().Be("cache-val");
        loginCount.Should().Be(1);
        client.ClientToken.Should().Be("test-approle-token");
        client.TokenExpiresAtUtc.Should().BeCloseTo(DateTimeOffset.UtcNow.AddSeconds(90), TimeSpan.FromSeconds(5));

        // Second call uses cached token without calling login again
        var res2 = await client.ReadKvSecretAsync("cache-test", CancellationToken.None);
        res2.IsSuccess.Should().BeTrue();
        loginCount.Should().Be(1);

        // Test with lease_duration = 10 (Math.Max(30, -20) => 30)
        var client10 = new HashiCorpVaultClient(new HashiCorpVaultOptions
        {
            VaultUrl = new Uri("http://127.0.0.1:8200/"),
            RoleId = "r",
            SecretId = "s",
            HttpClient = CreateMockHttpClient(_ => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("{\"auth\":{\"client_token\":\"tok10\",\"lease_duration\":10}}")
            })),
            EnableDevelopmentInMemoryStub = false
        });
        using (client10)
        {
            await client10.ReadKvSecretAsync("any", CancellationToken.None);
            client10.TokenExpiresAtUtc.Should().BeCloseTo(DateTimeOffset.UtcNow.AddSeconds(30), TimeSpan.FromSeconds(5));
        }

        // Test with omitted lease_duration (fallback to 3600 => 3570)
        var clientFallback = new HashiCorpVaultClient(new HashiCorpVaultOptions
        {
            VaultUrl = new Uri("http://127.0.0.1:8200/"),
            RoleId = "r",
            SecretId = "s",
            HttpClient = CreateMockHttpClient(_ => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("{\"auth\":{\"client_token\":\"tok-fallback\"}}")
            })),
            EnableDevelopmentInMemoryStub = false
        });
        using (clientFallback)
        {
            await clientFallback.ReadKvSecretAsync("any", CancellationToken.None);
            clientFallback.TokenExpiresAtUtc.Should().BeCloseTo(DateTimeOffset.UtcNow.AddSeconds(3570), TimeSpan.FromSeconds(5));
        }

        // Concurrent calls test (lock contention triggers inner double-check)
        var concurrentLoginCalls = 0;
        var concurrentClient = new HashiCorpVaultClient(new HashiCorpVaultOptions
        {
            VaultUrl = new Uri("http://127.0.0.1:8200/"),
            RoleId = "r",
            SecretId = "s",
            HttpClient = CreateMockHttpClient(async req =>
            {
                if (req.RequestUri?.ToString().Contains("auth/approle/login", StringComparison.Ordinal) == true)
                {
                    Interlocked.Increment(ref concurrentLoginCalls);
                    await Task.Delay(25);
                    return new HttpResponseMessage(HttpStatusCode.OK)
                    {
                        Content = new StringContent("{\"auth\":{\"client_token\":\"concurrent-tok\",\"lease_duration\":300}}")
                    };
                }
                return new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent("{\"data\":{\"data\":{\"value\":\"concurrent-val\"}}}")
                };
            }),
            EnableDevelopmentInMemoryStub = false
        });
        using (concurrentClient)
        {
            var taskA = concurrentClient.ReadKvSecretAsync("a", CancellationToken.None).AsTask();
            var taskB = concurrentClient.ReadKvSecretAsync("b", CancellationToken.None).AsTask();
            var results = await Task.WhenAll(taskA, taskB);
            results[0].IsSuccess.Should().BeTrue();
            results[1].IsSuccess.Should().BeTrue();
            concurrentLoginCalls.Should().Be(1);
        }
    }

    [Fact]
    public void HashiCorpVaultClient_SerializationMethods_VerifyJsonOutputs()
    {
        // 1. SerializeAppRoleLogin
        var loginBytes = HashiCorpVaultClient.SerializeAppRoleLogin("role-alpha", "secret-beta");
        using (var doc = JsonDocument.Parse(loginBytes))
        {
            var root = doc.RootElement;
            root.GetProperty("role_id").GetString().Should().Be("role-alpha");
            root.GetProperty("secret_id").GetString().Should().Be("secret-beta");
        }

        // 2. SerializeKvSecretWrite
        var kvBytes = HashiCorpVaultClient.SerializeKvSecretWrite("super-secret-password");
        using (var doc = JsonDocument.Parse(kvBytes))
        {
            var root = doc.RootElement;
            root.GetProperty("data").GetProperty("value").GetString().Should().Be("super-secret-password");
        }

        // 3. SerializeKeyDataWrite
        var keyId = KeyIdentifier.Prefixed("k-test");
        var version = new KeyVersion(3);
        var now = DateTimeOffset.UtcNow;
        var exp = now.AddDays(30);
        var rev = now.AddDays(5);
        var meta = new KeyMetadata(keyId, version, KeyPurpose.Signing, KeyStatus.Retired, "HMAC-SHA256", now, exp, rev);
        var rawKey = new byte[] { 10, 20, 30, 40 };

        var keyBytes = HashiCorpVaultClient.SerializeKeyDataWrite(keyId, version, meta, rawKey);
        using (var doc = JsonDocument.Parse(keyBytes))
        {
            var data = doc.RootElement.GetProperty("data");
            data.GetProperty("key_bytes").GetString().Should().Be(Convert.ToBase64String(rawKey));
            data.GetProperty("key_id").GetString().Should().Be(keyId.Value);
            data.GetProperty("version").GetString().Should().Be("3");
            data.GetProperty("purpose").GetString().Should().Be("Signing");
            data.GetProperty("status").GetString().Should().Be("Retired");
            data.GetProperty("algorithm").GetString().Should().Be("HMAC-SHA256");
            data.GetProperty("created_at").GetString().Should().Contain("T");
            data.GetProperty("expires_at").GetString().Should().Contain("T");
            data.GetProperty("revoked_at").GetString().Should().Contain("T");
        }
    }

    [Fact]
    public async Task HashiCorpVaultClient_ReadKeyDataAsync_ExplicitMetadata_ParsedCorrectly()
    {
        var fixedDate = new DateTimeOffset(2024, 6, 15, 10, 30, 0, TimeSpan.Zero);
        var expDate = fixedDate.AddDays(60);
        var revDate = fixedDate.AddDays(10);
        var rawKey = new byte[] { 1, 2, 3, 4, 5 };

        var httpClient = CreateMockHttpClient(_ =>
        {
            var json = JsonSerializer.Serialize(new
            {
                data = new
                {
                    data = new Dictionary<string, string>
                    {
                        ["key_bytes"] = Convert.ToBase64String(rawKey),
                        ["key_id"] = "explicit-vault-id",
                        ["version"] = "99",
                        ["purpose"] = "KeyWrapping",
                        ["status"] = "Destroyed",
                        ["algorithm"] = "CHACHA20-POLY1305",
                        ["created_at"] = fixedDate.ToString("O"),
                        ["expires_at"] = expDate.ToString("O"),
                        ["revoked_at"] = revDate.ToString("O")
                    }
                }
            });
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(json)
            });
        });

        var options = new HashiCorpVaultOptions
        {
            VaultUrl = new Uri("http://127.0.0.1:8200/"),
            Token = "s.token",
            HttpClient = httpClient,
            EnableDevelopmentInMemoryStub = false
        };

        using var client = new HashiCorpVaultClient(options);
        var result = await client.ReadKeyDataAsync(KeyIdentifier.Prefixed("fallback-key"), new KeyVersion(1), CancellationToken.None);

        result.IsSuccess.Should().BeTrue();
        var (metadata, keyBytes) = result.Value;
        keyBytes.Should().Equal(rawKey);
        metadata.KeyId.Value.Should().StartWith("explicit-vault-id-");
        metadata.Version.Value.Should().Be(99);
        metadata.Purpose.Should().Be(KeyPurpose.KeyWrapping);
        metadata.Status.Should().Be(KeyStatus.Destroyed);
        metadata.AlgorithmId.Should().Be("CHACHA20-POLY1305");
        metadata.CreatedAtUtc.Should().Be(fixedDate);
        metadata.ExpiresAtUtc.Should().Be(expDate);
        metadata.RevokedAtUtc.Should().Be(revDate);
    }

    [Fact]
    public async Task HashiCorpVaultKeyStore_UpdateStatusAsync_Behaviors()
    {
        // 1. In-memory stub behavior
        var stubOptions = Options.Create(new HashiCorpVaultOptions { EnableDevelopmentInMemoryStub = true });
        using var stubStore = new HashiCorpVaultKeyStore(stubOptions);

        var keyId = KeyIdentifier.Prefixed("stub-key");
        var version = KeyVersion.Initial;
        var meta = new KeyMetadata(keyId, version, KeyPurpose.Encryption, KeyStatus.Active, "AES-256-GCM", DateTimeOffset.UtcNow);
        var cryptoKey = new CryptographicKey(meta, SecretBuffer.FromSpan([1, 2, 3]));
        await stubStore.SaveKeyAsync(cryptoKey);

        // Update to Retired keeps RevokedAtUtc null
        var retRes = await stubStore.UpdateStatusAsync(keyId, version, KeyStatus.Retired);
        retRes.IsSuccess.Should().BeTrue();
        var keyRet = await stubStore.GetKeyAsync(keyId, version);
        keyRet.Value.Metadata.Status.Should().Be(KeyStatus.Retired);
        keyRet.Value.Metadata.RevokedAtUtc.Should().BeNull();

        // Update to Revoked sets RevokedAtUtc
        var revRes = await stubStore.UpdateStatusAsync(keyId, version, KeyStatus.Revoked);
        revRes.IsSuccess.Should().BeTrue();
        var keyRev = await stubStore.GetKeyAsync(keyId, version);
        keyRev.Value.Metadata.Status.Should().Be(KeyStatus.Revoked);
        keyRev.Value.Metadata.RevokedAtUtc.Should().NotBeNull();

        // Non-existent key in stub
        var missRes = await stubStore.UpdateStatusAsync(KeyIdentifier.Prefixed("missing"), version, KeyStatus.Retired);
        missRes.IsFailure.Should().BeTrue();
        missRes.Error.Code.Should().Be("Security.KeyNotFound");

        // 2. Live client behavior
        string? writtenJson = null;
        var httpClient = CreateMockHttpClient(async req =>
        {
            if (req.Method == HttpMethod.Get)
            {
                var json = JsonSerializer.Serialize(new
                {
                    data = new
                    {
                        data = new Dictionary<string, string>
                        {
                            ["key_bytes"] = Convert.ToBase64String(new byte[] { 10, 20 }),
                            ["key_id"] = "live-key",
                            ["version"] = "1",
                            ["purpose"] = "Encryption",
                            ["status"] = "Active",
                            ["algorithm"] = "AES-256-GCM",
                            ["created_at"] = DateTimeOffset.UtcNow.ToString("O")
                        }
                    }
                });
                return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(json) };
            }

            if (req.Method == HttpMethod.Post)
            {
                writtenJson = req.Content is not null ? await req.Content.ReadAsStringAsync() : null;
                return new HttpResponseMessage(HttpStatusCode.OK);
            }

            return new HttpResponseMessage(HttpStatusCode.NotFound);
        });

        var liveOptions = Options.Create(new HashiCorpVaultOptions
        {
            VaultUrl = new Uri("http://127.0.0.1:8200/"),
            Token = "s.token",
            HttpClient = httpClient,
            EnableDevelopmentInMemoryStub = false
        });

        using var liveStore = new HashiCorpVaultKeyStore(liveOptions);
        var liveId = KeyIdentifier.Prefixed("live-key");

        // Update to Retired: json does not contain revoked_at
        var liveRet = await liveStore.UpdateStatusAsync(liveId, version, KeyStatus.Retired);
        liveRet.IsSuccess.Should().BeTrue();
        writtenJson.Should().NotBeNull();
        writtenJson.Should().Contain("\"status\":\"Retired\"");
        writtenJson.Should().NotContain("\"revoked_at\"");

        // Update to Revoked: json contains revoked_at
        var liveRev = await liveStore.UpdateStatusAsync(liveId, version, KeyStatus.Revoked);
        liveRev.IsSuccess.Should().BeTrue();
        writtenJson.Should().Contain("\"status\":\"Revoked\"");
        writtenJson.Should().Contain("\"revoked_at\"");
    }

    [Fact]
    public void HashiCorpVault_StoresDispose_CleansUpProperly()
    {
        var options = Options.Create(new HashiCorpVaultOptions
        {
            VaultUrl = new Uri("http://127.0.0.1:8200/"),
            Token = "s.token",
            HttpClient = CreateMockHttpClient(_ => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK))),
            EnableDevelopmentInMemoryStub = false
        });

        var keyStore = new HashiCorpVaultKeyStore(options);
        var secretStore = new HashiCorpVaultSecretStore(options);

        // Disposing live stores triggers _vaultClient?.Dispose()
        keyStore.Dispose();
        secretStore.Dispose();

        // Stub stores disposal clears and zeroes memory
        var stubOpts = Options.Create(new HashiCorpVaultOptions { EnableDevelopmentInMemoryStub = true });
        var stubKeyStore = new HashiCorpVaultKeyStore(stubOpts);
        var stubSecretStore = new HashiCorpVaultSecretStore(stubOpts);
        stubKeyStore.Dispose();
        stubSecretStore.Dispose();
    }

    [Fact]
    public async Task HashiCorpVaultClient_ReadKvSecretAsync_WithNullValue_ReturnsEmptyString()
    {
        var httpClient = CreateMockHttpClient(_ =>
        {
            var json = "{\"data\":{\"data\":{\"value\":null}}}";
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(json)
            });
        });

        var options = new HashiCorpVaultOptions
        {
            VaultUrl = new Uri("http://127.0.0.1:8200/"),
            Token = "s.token",
            HttpClient = httpClient,
            EnableDevelopmentInMemoryStub = false
        };

        using var client = new HashiCorpVaultClient(options);
        var result = await client.ReadKvSecretAsync("null-sec", CancellationToken.None);

        result.IsSuccess.Should().BeTrue();
        result.Value.Should().Be(string.Empty);
    }

    [Fact]
    public async Task HashiCorpVaultClient_ReadKeyDataAsync_MissingDataInner_ReturnsKeyNotFoundWithKeyAndVersion()
    {
        var httpClient = CreateMockHttpClient(_ =>
        {
            var json = "{\"data\":{}}";
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(json)
            });
        });

        var options = new HashiCorpVaultOptions
        {
            VaultUrl = new Uri("http://127.0.0.1:8200/"),
            Token = "s.token",
            HttpClient = httpClient,
            EnableDevelopmentInMemoryStub = false
        };

        using var client = new HashiCorpVaultClient(options);
        var keyId = KeyIdentifier.Prefixed("k-missing");
        var version = new KeyVersion(2);
        var result = await client.ReadKeyDataAsync(keyId, version, CancellationToken.None);

        result.IsFailure.Should().BeTrue();
        result.Error.Code.Should().Be("Security.KeyNotFound");
        result.Error.Description.Should().Contain($"{keyId}:{version}");
    }

    [Fact]
    public async Task HashiCorpVaultClient_ReadKeyDataAsync_AlgorithmOmittedOrWhitespace_DefaultsToAes256Gcm()
    {
        var rawKey = new byte[] { 1, 2, 3, 4 };
        var httpClient = CreateMockHttpClient(_ =>
        {
            var json = JsonSerializer.Serialize(new
            {
                data = new
                {
                    data = new Dictionary<string, string>
                    {
                        ["key_bytes"] = Convert.ToBase64String(rawKey),
                        ["key_id"] = "k-algo-default",
                        ["version"] = "1",
                        ["algorithm"] = "   "
                    }
                }
            });
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(json)
            });
        });

        var options = new HashiCorpVaultOptions
        {
            VaultUrl = new Uri("http://127.0.0.1:8200/"),
            Token = "s.token",
            HttpClient = httpClient,
            EnableDevelopmentInMemoryStub = false
        };

        using var client = new HashiCorpVaultClient(options);
        var keyId = KeyIdentifier.Prefixed("k-algo-default");
        var result = await client.ReadKeyDataAsync(keyId, KeyVersion.Initial, CancellationToken.None);

        result.IsSuccess.Should().BeTrue();
        result.Value.Metadata.AlgorithmId.Should().Be("AES-256-GCM");
    }

    [Fact]
    public async Task HashiCorpVaultClient_AppRoleAuthentication_LogsInAndCachesTokenAcrossCalls()
    {
        var loginCalls = 0;
        string? capturedTokenHeader = null;

        var httpClient = CreateMockHttpClient(req =>
        {
            if (req.RequestUri?.ToString().Contains("auth/approle/login", StringComparison.Ordinal) == true)
            {
                loginCalls++;
                var response = new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent("{\"auth\":{\"client_token\":\"approle-token-abc\",\"lease_duration\":3600}}")
                };
                return Task.FromResult(response);
            }

            if (req.Headers.TryGetValues("X-Vault-Token", out var vals))
            {
                capturedTokenHeader = System.Linq.Enumerable.FirstOrDefault(vals);
            }

            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("{\"data\":{\"data\":{\"value\":\"cached-val\"}}}")
            });
        });

        var options = new HashiCorpVaultOptions
        {
            VaultUrl = new Uri("http://127.0.0.1:8200/"),
            RoleId = "approle-role-id",
            SecretId = "approle-secret-id",
            HttpClient = httpClient,
            EnableDevelopmentInMemoryStub = false
        };

        using var client = new HashiCorpVaultClient(options);

        // First call triggers AppRole login
        var res1 = await client.ReadKvSecretAsync("test-key", CancellationToken.None);
        res1.IsSuccess.Should().BeTrue();
        res1.Value.Should().Be("cached-val");
        capturedTokenHeader.Should().Be("approle-token-abc");
        loginCalls.Should().Be(1);

        // Second call should reuse cached token without logging in again
        var res2 = await client.ReadKvSecretAsync("test-key", CancellationToken.None);
        res2.IsSuccess.Should().BeTrue();
        res2.Value.Should().Be("cached-val");
        loginCalls.Should().Be(1);
    }
}
