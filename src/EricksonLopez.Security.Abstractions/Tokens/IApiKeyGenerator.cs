// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Abstractions.Tokens;

using System;
using System.Collections.Generic;
using EricksonLopez.Security.Abstractions.Primitives;

/// <summary>
/// Defines a contract for issuing cryptographically secure API keys with display prefixes and hashed secrets.
/// </summary>
public interface IApiKeyGenerator
{
    /// <summary>
    /// Generates a new structured API key with the specified metadata and constraints.
    /// </summary>
    /// <param name="ownerId">The identifier of the owning entity or tenant</param>
    /// <param name="name">The descriptive name for the API key</param>
    /// <param name="prefix">The display prefix to prepend to the key</param>
    /// <param name="lifetime">The optional lifetime validity period</param>
    /// <param name="scopes">The optional set of authorized scopes</param>
    /// <returns>An <see cref="ApiKeyIssuanceResult"/> containing the created API key entity and the plaintext key.</returns>
    ApiKeyIssuanceResult GenerateApiKey(
        string ownerId,
        string name,
        string prefix = "ek_live",
        TimeSpan? lifetime = null,
        IReadOnlySet<string>? scopes = null);
}
