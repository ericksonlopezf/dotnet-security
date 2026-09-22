// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Abstractions.Tokens;

using EricksonLopez.Security.Abstractions.Primitives;

/// <summary>
/// Represents the result of issuing a new API key.
/// </summary>
/// <remarks>
/// Contains the persisted <see cref="ApiKey"/> descriptor (with hashed secret)
/// and the single-use plaintext secret string that must be returned once to the caller.
/// </remarks>
/// <param name="Key">The persisted API key entity.</param>
/// <param name="PlaintextApiKey">The full plaintext API key string (e.g., "ek_live_9f8a...").</param>
public sealed record ApiKeyIssuanceResult(ApiKey Key, string PlaintextApiKey);
