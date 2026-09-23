// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Azure.Tests;

using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using global::Azure.Core;
using global::Azure.Security.KeyVault.Secrets;
using AwesomeAssertions;
using EricksonLopez.Security.Abstractions.KeyManagement;
using EricksonLopez.Security.Abstractions.Primitives;
using EricksonLopez.Security.Azure;
using Microsoft.Extensions.Options;
using Xunit;

public sealed class AzureKeyVaultKeyStoreMetadataParserTests
{
    private sealed class ThrowingTokenCredential : TokenCredential
    {
        public override AccessToken GetToken(TokenRequestContext requestContext, CancellationToken cancellationToken)
            => throw new InvalidOperationException("ThrowingTokenCredential invoked");

        public override ValueTask<AccessToken> GetTokenAsync(TokenRequestContext requestContext, CancellationToken cancellationToken)
            => throw new InvalidOperationException("ThrowingTokenCredential invoked");
    }

    [Fact]
    public async Task KeyStore_VaultUriConstructor_UsesConfiguredCredential()
    {
        var options = new AzureKeyVaultOptions
        {
            VaultUri = new Uri("https://custom-vault.vault.azure.net/"),
            Credential = new ThrowingTokenCredential()
        };

        using var store = new AzureKeyVaultKeyStore(Options.Create(options));
        var act = async () => await store.GetKeyAsync(KeyIdentifier.Prefixed("k1"), KeyVersion.Initial);
        await act.Should().ThrowAsync<InvalidOperationException>()
            .WithMessage("ThrowingTokenCredential invoked");
    }

    [Fact]
    public async Task SecretStore_VaultUriConstructor_UsesConfiguredCredential()
    {
        var options = new AzureKeyVaultOptions
        {
            VaultUri = new Uri("https://custom-vault.vault.azure.net/"),
            Credential = new ThrowingTokenCredential()
        };

        var store = new AzureKeyVaultSecretStore(Options.Create(options));
        var act = async () => await store.GetSecretAsync("s1");
        await act.Should().ThrowAsync<InvalidOperationException>()
            .WithMessage("ThrowingTokenCredential invoked");
    }

    [Fact]
    public void ParseMetadataFromProperties_AllTagsPresent_MapsPropertiesAccurately()
    {
        var props = SecretModelFactory.SecretProperties(name: "test-secret");
        var now = DateTimeOffset.UtcNow;
        props.Enabled = true;
        props.Tags["KeyId"] = "custom-key";
        props.Tags["Version"] = "42";
        props.Tags["Purpose"] = "Signing";
        props.Tags["Status"] = "Destroyed";
        props.Tags["AlgorithmId"] = "Ed25519";
        props.Tags["CreatedAtUtc"] = now.ToString("O");
        props.Tags["ExpiresAtUtc"] = now.AddDays(30).ToString("O");
        props.Tags["RevokedAtUtc"] = now.AddDays(1).ToString("O");

        var meta = AzureKeyVaultKeyStore.ParseMetadataFromProperties(props, null, null);

        meta.KeyId.Value.Should().StartWith("custom-key-");
        meta.Version.Value.Should().Be(42);
        meta.Purpose.Should().Be(KeyPurpose.Signing);
        meta.Status.Should().Be(KeyStatus.Destroyed);
        meta.AlgorithmId.Should().Be("Ed25519");
        meta.CreatedAtUtc.Should().BeCloseTo(now, TimeSpan.FromSeconds(1));
        meta.ExpiresAtUtc.Should().NotBeNull();
        meta.RevokedAtUtc.Should().NotBeNull();
    }

    [Fact]
    public void ParseMetadataFromProperties_KeyIdBranches()
    {
        // Missing KeyId with fallback
        var props1 = SecretModelFactory.SecretProperties(name: "s1");
        var fallbackId = KeyIdentifier.Prefixed("fallback-id");
        var meta1 = AzureKeyVaultKeyStore.ParseMetadataFromProperties(props1, fallbackId, null);
        meta1.KeyId.Should().Be(fallbackId);

        // Missing KeyId without fallback
        var meta2 = AzureKeyVaultKeyStore.ParseMetadataFromProperties(props1, null, null);
        meta2.KeyId.Value.Should().StartWith("unknown-");

        // Whitespace KeyId uses fallback
        var propsWhitespace = SecretModelFactory.SecretProperties(name: "sw");
        propsWhitespace.Tags["KeyId"] = "   ";
        var fallbackWs = KeyIdentifier.Prefixed("fallback-from-ws");
        var meta3 = AzureKeyVaultKeyStore.ParseMetadataFromProperties(propsWhitespace, fallbackWs, null);
        meta3.KeyId.Should().Be(fallbackWs);
    }

    [Fact]
    public void ParseMetadataFromProperties_StatusAndEnabledBranches()
    {
        // No status tag, Enabled = true -> Active
        var propsTrue = SecretModelFactory.SecretProperties(name: "st1");
        propsTrue.Enabled = true;
        var metaActive = AzureKeyVaultKeyStore.ParseMetadataFromProperties(propsTrue, null, null);
        metaActive.Status.Should().Be(KeyStatus.Active);

        // No status tag, Enabled = false -> Retired
        var propsFalse = SecretModelFactory.SecretProperties(name: "st2");
        propsFalse.Enabled = false;
        var metaRetired = AzureKeyVaultKeyStore.ParseMetadataFromProperties(propsFalse, null, null);
        metaRetired.Status.Should().Be(KeyStatus.Retired);

        // No status tag, Enabled = null -> Retired
        var propsNull = SecretModelFactory.SecretProperties(name: "st3");
        propsNull.Enabled = null;
        var metaNull = AzureKeyVaultKeyStore.ParseMetadataFromProperties(propsNull, null, null);
        metaNull.Status.Should().Be(KeyStatus.Retired);
    }

    [Fact]
    public void ParseMetadataFromProperties_AlgorithmBranches()
    {
        // Missing algorithm tag defaults to AES-256-GCM
        var propsDefault = SecretModelFactory.SecretProperties(name: "alg1");
        var metaDefault = AzureKeyVaultKeyStore.ParseMetadataFromProperties(propsDefault, null, null);
        metaDefault.AlgorithmId.Should().Be("AES-256-GCM");

        // Whitespace algorithm tag defaults to AES-256-GCM
        var propsWs = SecretModelFactory.SecretProperties(name: "alg2");
        propsWs.Tags["AlgorithmId"] = "  \t ";
        var metaWs = AzureKeyVaultKeyStore.ParseMetadataFromProperties(propsWs, null, null);
        metaWs.AlgorithmId.Should().Be("AES-256-GCM");

        // Custom algorithm tag respected
        var propsCustom = SecretModelFactory.SecretProperties(name: "alg3");
        propsCustom.Tags["AlgorithmId"] = "CHACHA20-POLY1305";
        var metaCustom = AzureKeyVaultKeyStore.ParseMetadataFromProperties(propsCustom, null, null);
        metaCustom.AlgorithmId.Should().Be("CHACHA20-POLY1305");
    }

    [Fact]
    public void ParseMetadataFromProperties_CreatedOnFallback()
    {
        var created = DateTimeOffset.UtcNow.AddDays(-10);
        var props = SecretModelFactory.SecretProperties(name: "c1", createdOn: created);

        var meta = AzureKeyVaultKeyStore.ParseMetadataFromProperties(props, null, null);
        meta.CreatedAtUtc.Should().Be(created);
    }
}
