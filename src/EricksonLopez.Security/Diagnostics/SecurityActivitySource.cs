// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Diagnostics;

using System.Diagnostics;

/// <summary>
/// Provides the central <see cref="System.Diagnostics.ActivitySource"/> for all EricksonLopez.Security telemetry.
/// Consumers opt in by subscribing to this source via an ActivityListener or via the optional
/// <c>EricksonLopez.Security.OpenTelemetry</c> satellite package.
/// </summary>
/// <remarks>
/// Per ADR-019, <see cref="SecurityActivitySource"/> resides in the core package and uses exclusively <c>System.Diagnostics</c>
/// from the BCL inbox assembly — no OTel SDK dependency is introduced here.
/// </remarks>
public static class SecurityActivitySource
{
    /// <summary>Specifies the canonical source name used when subscribing via <see cref="ActivityListener"/>.</summary>
    public const string SourceName = "EricksonLopez.Security";

    /// <summary>Specifies the semantic version of this instrumentation.</summary>
    public const string SourceVersion = "1.1.0";

    /// <summary>
    /// Provides the shared <see cref="ActivitySource"/> emitting all security operation spans.
    /// </summary>
    public static readonly ActivitySource Instance = new(SourceName, SourceVersion);

    // ── Activity Names ──────────────────────────────────────────────────────────

    /// <summary>Defines the AEAD encryption span name.</summary>
    public const string EncryptOperation = "security.encrypt";

    /// <summary>Defines the AEAD decryption span name.</summary>
    public const string DecryptOperation = "security.decrypt";

    /// <summary>Defines the secret protection (wrap) span name.</summary>
    public const string ProtectSecretOperation = "security.secret.protect";

    /// <summary>Defines the secret unprotection (unwrap) span name.</summary>
    public const string UnprotectSecretOperation = "security.secret.unprotect";

    /// <summary>Defines the password hashing span name.</summary>
    public const string HashPasswordOperation = "security.password.hash";

    /// <summary>Defines the password verification span name.</summary>
    public const string VerifyPasswordOperation = "security.password.verify";

    /// <summary>Defines the key wrap (KMS) span name.</summary>
    public const string WrapKeyOperation = "security.key.wrap";

    /// <summary>Defines the key unwrap (KMS) span name.</summary>
    public const string UnwrapKeyOperation = "security.key.unwrap";

    // ── Tag Keys ────────────────────────────────────────────────────────────────

    /// <summary>Defines the tag key for the AEAD algorithm name (e.g. "aes-256-gcm").</summary>
    public const string TagAlgorithm = "security.algorithm";

    /// <summary>Defines the tag key for the key version (e.g. "v2").</summary>
    public const string TagKeyVersion = "security.key.version";

    /// <summary>Defines the tag key for the password hashing algorithm (e.g. "argon2id", "pbkdf2-sha512").</summary>
    public const string TagHashAlgorithm = "security.hash.algorithm";

    /// <summary>Defines the tag key for the operation result: "success", "failure", "rehash_needed".</summary>
    public const string TagResult = "security.result";

    /// <summary>
    /// Defines the tag key for the error code when an operation fails (e.g. "KeyExpired", "DecryptionFailed").
    /// </summary>
    public const string TagErrorCode = "security.error.code";
}
