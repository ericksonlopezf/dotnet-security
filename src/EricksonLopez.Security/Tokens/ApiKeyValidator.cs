// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Tokens;

using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using EricksonLopez.Result;
using EricksonLopez.Security.Abstractions.Errors;
using EricksonLopez.Security.Abstractions.Primitives;
using EricksonLopez.Security.Abstractions.Tokens;
using EricksonLopez.Security.Diagnostics;

/// <summary>
/// Provides an implementation of <see cref="IApiKeyValidator"/> to authenticate incoming API keys using constant-time evaluation,
/// repository lookups, and lifecycle status validation.
/// </summary>
public sealed class ApiKeyValidator : IApiKeyValidator
{
    private readonly IApiKeyStore _apiKeyStore;
    private readonly ITokenHasher _tokenHasher;

    /// <summary>
    /// Initializes a new instance of the <see cref="ApiKeyValidator"/> class.
    /// </summary>
    /// <param name="apiKeyStore">The API key storage repository.</param>
    /// <param name="tokenHasher">The optional custom token hasher (defaults to secure keyed HMAC-SHA256 with an application-level pepper).</param>
    /// <exception cref="ArgumentNullException"><paramref name="apiKeyStore"/> is <see langword="null"/></exception>
    public ApiKeyValidator(IApiKeyStore apiKeyStore, ITokenHasher? tokenHasher = null)
    {
        _apiKeyStore = apiKeyStore ?? throw new ArgumentNullException(nameof(apiKeyStore));
        _tokenHasher = tokenHasher ?? new HmacSha256TokenHasher();
    }

    // SC-001 fix: The dummy hash must be exactly 64 lowercase hex characters — the same length as a real
    // HMAC-SHA256 or SHA-256 hex digest (32 bytes * 2 chars/byte = 64 chars). Using a shorter placeholder
    // caused FixedTimeEquals to return early on length mismatch, leaking whether a key ID exists via timing.
    private const string DummyTimingHash =
        "0000000000000000000000000000000000000000000000000000000000000000"; // 64 hex chars

    /// <inheritdoc />
    public async ValueTask<Result<ApiKey>> ValidateApiKeyAsync(
        string plaintextApiKey,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(plaintextApiKey))
        {
            SecurityMeter.ApiKeyValidationsTotal.Add(1, new KeyValuePair<string, object?>("security.result", "invalid"));
            return SecurityError.InvalidToken("API key is null or empty.");
        }

        // Format is {prefix}_{idPart}_{secretPart}
        // Example: ek_live_9f8a1234_abcdef1234567890
        int lastUnderscore = plaintextApiKey.LastIndexOf('_');
        if (lastUnderscore <= 0 || lastUnderscore >= plaintextApiKey.Length - 1)
        {
            SecurityMeter.ApiKeyValidationsTotal.Add(1, new KeyValuePair<string, object?>("security.result", "invalid"));
            return SecurityError.InvalidToken("API key format is invalid.");
        }

        var keyIdString = plaintextApiKey[..lastUnderscore];
        var keyId = new ApiKeyId(keyIdString);

        var lookupResult = await _apiKeyStore.GetByIdAsync(keyId, cancellationToken).ConfigureAwait(false);

        ReadOnlySpan<char> secretPart = plaintextApiKey.AsSpan(lastUnderscore + 1);
        if (lookupResult.IsFailure)
        {
            // SC-001 fix: execute dummy verification with a correctly-lengthed hash (64 hex chars)
            // so that FixedTimeEquals does NOT short-circuit on length mismatch, equalizing timing
            // between "key exists" and "key does not exist" branches to defeat timing oracles.
            _tokenHasher.VerifyToken(secretPart, DummyTimingHash);
            SecurityMeter.ApiKeyValidationsTotal.Add(1, new KeyValuePair<string, object?>("security.result", "invalid"));
            return SecurityError.InvalidToken("Invalid API key credentials.");
        }

        var apiKey = lookupResult.Value;

        // VULN-03 / SC-002 fix: Always authenticate secret proof-of-possession FIRST.
        // If the secret is invalid, return generic InvalidToken without revealing whether
        // the key is revoked or expired. This defeats the pre-verification status oracle.
        bool matches = _tokenHasher.VerifyToken(secretPart, apiKey.HashedSecret);
        if (!matches)
        {
            SecurityMeter.ApiKeyValidationsTotal.Add(1, new KeyValuePair<string, object?>("security.result", "invalid"));
            return SecurityError.InvalidToken("Invalid API key credentials.");
        }

        if (apiKey.IsRevoked)
        {
            SecurityMeter.ApiKeyValidationsTotal.Add(1, new KeyValuePair<string, object?>("security.result", "revoked"));
            return SecurityError.TokenRevoked("The presented API key has been revoked.");
        }

        if (!apiKey.IsActive())
        {
            SecurityMeter.ApiKeyValidationsTotal.Add(1, new KeyValuePair<string, object?>("security.result", "expired"));
            return SecurityError.TokenExpired("The presented API key has expired.");
        }

        SecurityMeter.ApiKeyValidationsTotal.Add(1, new KeyValuePair<string, object?>("security.result", "success"));
        return apiKey;
    }
}
