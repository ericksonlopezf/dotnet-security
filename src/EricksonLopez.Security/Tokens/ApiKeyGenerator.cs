// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Tokens;

using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using EricksonLopez.Security.Abstractions.Primitives;
using EricksonLopez.Security.Abstractions.Tokens;
using EricksonLopez.Security.Randomness;

/// <summary>
/// Provides a generator implementation for issuing structured, cryptographically high-entropy API keys.
/// Formats keys as: <c>{prefix}_{idHex16}_{secretUrlSafe}</c>.
/// Persists only the hashed secret while returning the full plaintext key once upon issuance.
/// </summary>
public sealed class ApiKeyGenerator : IApiKeyGenerator
{
    private readonly ITokenHasher _tokenHasher;

    /// <summary>
    /// Initializes a new instance of the <see cref="ApiKeyGenerator"/> class with a specified token hasher.
    /// </summary>
    /// <param name="tokenHasher">The token hasher used to hash issued API key secrets.</param>
    /// <exception cref="ArgumentNullException"><paramref name="tokenHasher"/> is <see langword="null"/></exception>
    public ApiKeyGenerator(ITokenHasher tokenHasher)
    {
        _tokenHasher = tokenHasher ?? throw new ArgumentNullException(nameof(tokenHasher));
    }


    /// <inheritdoc />
    /// <remarks>
    /// <strong>Memory Note (APIKEY-05):</strong> The <see cref="ApiKeyIssuanceResult.PlaintextApiKey"/>
    /// property of the returned result is a managed <see langword="string"/> and cannot be explicitly zeroed.
    /// The plaintext API key will remain in the managed heap until garbage collected. If your security policy
    /// requires that the plaintext key be zeroed immediately after transmission to the client, use
    /// <see cref="GenerateApiKeySecretBuffer"/> instead, which returns the plaintext key in a
    /// <see cref="Memory.SecretBuffer"/> that is explicitly zeroed when disposed.
    /// </remarks>
    public ApiKeyIssuanceResult GenerateApiKey(
        string ownerId,
        string name,
        string prefix = "ek_live",
        TimeSpan? lifetime = null,
        IReadOnlySet<string>? scopes = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(ownerId);
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        ArgumentException.ThrowIfNullOrWhiteSpace(prefix);

        var cleanPrefix = prefix.Trim().TrimEnd('_');
        var keyIdPart = CryptographicRandom.Shared.GetHexString(8); // 16 hex chars
        // Deliberate constraint: '_' is replaced with '-' so that '_' functions as the unambiguous structural delimiter between prefix, keyId, and secret.
        var secretPart = CryptographicRandom.Shared.GetUrlSafeString(24).Replace('_', '-');

        var keyId = new ApiKeyId($"{cleanPrefix}_{keyIdPart}");
        var fullPlaintextApiKey = $"{keyId.Value}_{secretPart}";
        var displayPrefix = $"{keyId.Value}_****";

        var hashedSecret = _tokenHasher.HashToken(secretPart);

        var now = DateTimeOffset.UtcNow;
        var expiresAt = lifetime.HasValue ? now.Add(lifetime.Value) : (DateTimeOffset?)null;

        var apiKeyEntity = new ApiKey(
            Id: keyId,
            OwnerId: ownerId.Trim(),
            Name: name.Trim(),
            DisplayPrefix: displayPrefix,
            HashedSecret: hashedSecret,
            CreatedAtUtc: now,
            ExpiresAtUtc: expiresAt,
            Scopes: scopes);

        return new ApiKeyIssuanceResult(apiKeyEntity, fullPlaintextApiKey);
    }

    /// <summary>
    /// Issues a new structured API key and returns the full plaintext secret wrapped inside a zeroizable <see cref="Memory.SecretBuffer"/>,
    /// preventing long-term retention of sensitive credentials in the managed garbage collection heap.
    /// </summary>
    /// <param name="ownerId">The owner or tenant identifier.</param>
    /// <param name="name">The human-readable key name.</param>
    /// <param name="prefix">The key prefix.</param>
    /// <param name="lifetime">Optional key lifetime.</param>
    /// <param name="scopes">Optional authorized scopes.</param>
    /// <returns>A tuple containing the persisted <see cref="ApiKey"/> descriptor and the zeroizable <see cref="Memory.SecretBuffer"/> containing the UTF-8 plaintext key bytes.</returns>
    public (ApiKey Key, Memory.SecretBuffer SecretBuffer) GenerateApiKeySecretBuffer(
        string ownerId,
        string name,
        string prefix = "ek_live",
        TimeSpan? lifetime = null,
        IReadOnlySet<string>? scopes = null)
    {
        var result = GenerateApiKey(ownerId, name, prefix, lifetime, scopes);
        var secretBuffer = Memory.SecretBuffer.FromUtf8(result.PlaintextApiKey);
        return (result.Key, secretBuffer);
    }
}
