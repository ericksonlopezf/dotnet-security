// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Abstractions.Errors;

using EricksonLopez.Result;

/// <summary>
/// Provides standardized, strongly-typed error definitions for all security, cryptographic,
/// key management, token, and secret protection operations across the ecosystem.
/// </summary>
public static class SecurityError
{
    /// <summary>
    /// Creates an <see cref="Error"/> representing invalid, corrupted, or malformed ciphertext.
    /// </summary>
    /// <param name="details">The optional detailed description of the error.</param>
    /// <returns>An <see cref="Error"/> configured with the invalid ciphertext failure details.</returns>
    public static Error InvalidCiphertext(string? details = null) =>
        Error.Failure(
            code: "Security.InvalidCiphertext",
            description: details ?? "The provided ciphertext is invalid, corrupted, or has an unexpected format.");

    /// <summary>
    /// Creates an <see cref="Error"/> representing an AEAD authentication tag mismatch during decryption.
    /// </summary>
    /// <param name="details">The optional detailed description of the error.</param>
    /// <returns>An <see cref="Error"/> configured with the authentication tag mismatch validation details.</returns>
    public static Error AuthenticationTagMismatch(string? details = null) =>
        Error.Validation(
            code: "Security.AuthenticationTagMismatch",
            description: details ?? "Decryption failed: authentication tag verification failed (ciphertext or associated data was tampered with).");

    /// <summary>
    /// Creates an <see cref="Error"/> representing invalid or unsupported cryptographic key material.
    /// </summary>
    /// <param name="details">The optional detailed description of the error.</param>
    /// <returns>An <see cref="Error"/> configured with the invalid key validation details.</returns>
    public static Error InvalidKey(string? details = null) =>
        Error.Validation(
            code: "Security.InvalidKey",
            description: details ?? "The cryptographic key material is invalid or of an unsupported length.");

    /// <summary>
    /// Creates an <see cref="Error"/> representing a missing cryptographic key in the key ring or store.
    /// </summary>
    /// <param name="keyId">The identifier of the missing cryptographic key.</param>
    /// <param name="details">The optional detailed description of the error.</param>
    /// <returns>An <see cref="Error"/> configured with the key not found details.</returns>
    public static Error KeyNotFound(string keyId, string? details = null) =>
        Error.NotFound(
            code: "Security.KeyNotFound",
            description: details ?? $"The cryptographic key with identifier '{keyId}' was not found.");

    /// <summary>
    /// Creates an <see cref="Error"/> representing an expired cryptographic key.
    /// </summary>
    /// <param name="keyId">The identifier of the expired cryptographic key.</param>
    /// <param name="details">The optional detailed description of the error.</param>
    /// <returns>An <see cref="Error"/> configured with the key expired failure details.</returns>
    public static Error KeyExpired(string keyId, string? details = null) =>
        Error.Failure(
            code: "Security.KeyExpired",
            description: details ?? $"The cryptographic key with identifier '{keyId}' has expired.");

    /// <summary>
    /// Creates an <see cref="Error"/> representing a revoked cryptographic key.
    /// </summary>
    /// <param name="keyId">The identifier of the revoked cryptographic key.</param>
    /// <param name="details">The optional detailed description of the error.</param>
    /// <returns>An <see cref="Error"/> configured with the key revoked failure details.</returns>
    public static Error KeyRevoked(string keyId, string? details = null) =>
        Error.Failure(
            code: "Security.KeyRevoked",
            description: details ?? $"The cryptographic key with identifier '{keyId}' has been revoked.");

    /// <summary>
    /// Creates an <see cref="Error"/> representing a mismatch between a key's authorized purpose and requested operation.
    /// </summary>
    /// <param name="expectedPurpose">The cryptographic purpose required by the attempted operation.</param>
    /// <param name="actualPurpose">The authorized cryptographic purpose configured on the key.</param>
    /// <returns>An <see cref="Error"/> configured with the purpose mismatch validation details.</returns>
    public static Error KeyPurposeMismatch(string expectedPurpose, string actualPurpose) =>
        Error.Validation(
            code: "Security.KeyPurposeMismatch",
            description: $"Key purpose mismatch. Key is authorized for '{actualPurpose}', but operation requested '{expectedPurpose}'.");

    /// <summary>
    /// Creates an <see cref="Error"/> representing an invalid, malformed, or failed signature verification token.
    /// </summary>
    /// <param name="details">The optional detailed description of the error.</param>
    /// <returns>An <see cref="Error"/> configured with the invalid token validation details.</returns>
    public static Error InvalidToken(string? details = null) =>
        Error.Validation(
            code: "Security.InvalidToken",
            description: details ?? "The security token is invalid or malformed.");

    /// <summary>
    /// Creates an <see cref="Error"/> representing an expired security token.
    /// </summary>
    /// <param name="details">The optional detailed description of the error.</param>
    /// <returns>An <see cref="Error"/> configured with the token expired failure details.</returns>
    public static Error TokenExpired(string? details = null) =>
        Error.Failure(
            code: "Security.TokenExpired",
            description: details ?? "The security token has expired.");

    /// <summary>
    /// Creates an <see cref="Error"/> representing a revoked security token.
    /// </summary>
    /// <param name="details">The optional detailed description of the error.</param>
    /// <returns>An <see cref="Error"/> configured with the token revoked failure details.</returns>
    public static Error TokenRevoked(string? details = null) =>
        Error.Failure(
            code: "Security.TokenRevoked",
            description: details ?? "The security token has been revoked.");

    /// <summary>
    /// Creates an <see cref="Error"/> representing a password verification failure.
    /// </summary>
    /// <param name="details">The optional detailed description of the error.</param>
    /// <returns>An <see cref="Error"/> configured with the invalid password validation details.</returns>
    public static Error InvalidPassword(string? details = null) =>
        Error.Validation(
            code: "Security.InvalidPassword",
            description: details ?? "Password verification failed.");

    /// <summary>
    /// Creates an <see cref="Error"/> representing an unsupported cryptographic algorithm.
    /// </summary>
    /// <param name="algorithm">The name or identifier of the unsupported algorithm.</param>
    /// <param name="details">The optional detailed description of the error.</param>
    /// <returns>An <see cref="Error"/> configured with the unsupported algorithm failure details.</returns>
    public static Error UnsupportedAlgorithm(string algorithm, string? details = null) =>
        Error.Failure(
            code: "Security.UnsupportedAlgorithm",
            description: details ?? $"The cryptographic algorithm '{algorithm}' is not supported.");

    /// <summary>
    /// Creates an <see cref="Error"/> representing a security policy rule violation.
    /// </summary>
    /// <param name="policyName">The name of the violated security policy.</param>
    /// <param name="details">The specific rule failure details.</param>
    /// <returns>An <see cref="Error"/> configured with the policy violation validation details.</returns>
    public static Error SecurityPolicyViolation(string policyName, string details) =>
        Error.Validation(
            code: "Security.PolicyViolation",
            description: $"Security policy '{policyName}' violation: {details}");

    /// <summary>
    /// Creates an <see cref="Error"/> representing a missing secret in the secret store.
    /// </summary>
    /// <param name="secretName">The name or key of the secret that was not found.</param>
    /// <returns>An <see cref="Error"/> configured with the secret not found details.</returns>
    public static Error SecretNotFound(string secretName) =>
        Error.NotFound(
            code: "Security.SecretNotFound",
            description: $"The secret '{secretName}' was not found.");

    /// <summary>
    /// Creates an <see cref="Error"/> representing a cryptographic encryption failure.
    /// </summary>
    /// <param name="details">The specific cryptographic fault description.</param>
    /// <returns>An <see cref="Error"/> configured with the encryption failure details.</returns>
    public static Error EncryptionFailed(string details) =>
        Error.Failure(
            code: "Security.EncryptionFailed",
            description: $"Encryption operation failed: {details}");

    /// <summary>
    /// Creates an <see cref="Error"/> representing a cryptographic decryption failure.
    /// </summary>
    /// <param name="details">The specific cryptographic fault description.</param>
    /// <returns>An <see cref="Error"/> configured with the decryption failure details.</returns>
    public static Error DecryptionFailed(string details) =>
        Error.Failure(
            code: "Security.DecryptionFailed",
            description: $"Decryption operation failed: {details}");

    /// <summary>
    /// Creates an <see cref="Error"/> representing an invalid or unexpected cryptographic nonce.
    /// </summary>
    /// <param name="details">The optional detailed description of the error.</param>
    /// <returns>An <see cref="Error"/> configured with the invalid nonce validation details.</returns>
    public static Error InvalidNonce(string? details = null) =>
        Error.Validation(
            code: "Security.InvalidNonce",
            description: details ?? "The cryptographic nonce is invalid, of unsupported length, or reused.");

    /// <summary>
    /// Creates an <see cref="Error"/> representing an insufficient destination buffer length.
    /// </summary>
    /// <param name="details">The optional detailed description of the error.</param>
    /// <returns>An <see cref="Error"/> configured with the buffer too small validation details.</returns>
    public static Error BufferTooSmall(string? details = null) =>
        Error.Validation(
            code: "Security.BufferTooSmall",
            description: details ?? "The destination buffer is too small to receive the output data.");

    /// <summary>
    /// Creates an <see cref="Error"/> representing an audit or security event publication failure.
    /// </summary>
    /// <param name="details">The optional detailed description of the audit failure.</param>
    /// <returns>An <see cref="Error"/> configured with the audit failure details.</returns>
    public static Error AuditFailed(string? details = null) =>
        Error.Failure(
            code: "Security.AuditFailed",
            description: details ?? "Publishing mandatory security audit event failed.");

    /// <summary>
    /// Creates an <see cref="Error"/> representing an authenticated associated data (AAD) context mismatch.
    /// </summary>
    /// <param name="details">The optional detailed description of the error.</param>
    /// <returns>An <see cref="Error"/> configured with the AAD mismatch validation details.</returns>
    public static Error AssociatedDataMismatch(string? details = null) =>
        Error.Validation(
            code: "Security.AssociatedDataMismatch",
            description: details ?? "The authenticated associated data (AAD) provided does not match the authenticated context in the secret envelope.");

    /// <summary>
    /// Creates an <see cref="Error"/> representing a storage capacity limit breach.
    /// </summary>
    /// <param name="details">The optional detailed description of the error.</param>
    /// <returns>An <see cref="Error"/> configured with the storage capacity limit details.</returns>
    public static Error StoreCapacityExceeded(string? details = null) =>
        Error.Failure(
            code: "Security.StoreCapacityExceeded",
            description: details ?? "The key store capacity limit has been reached.");

    /// <summary>
    /// Creates an <see cref="Error"/> representing a payload size exceeding the maximum permitted limit.
    /// </summary>
    /// <param name="details">The optional detailed description of the error.</param>
    /// <returns>An <see cref="Error"/> configured with the payload size violation details.</returns>
    public static Error PayloadTooLarge(string? details = null) =>
        Error.Validation(
            code: "Security.PayloadTooLarge",
            description: details ?? "The payload size exceeds the maximum permitted limit.");
}

