// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Diagnostics;

using System.Diagnostics.Metrics;

/// <summary>
/// Provides the central <see cref="System.Diagnostics.Metrics.Meter"/> for all EricksonLopez.Security metrics.
/// Consumers subscribe via <see cref="MeterListener"/> or via the optional
/// <c>EricksonLopez.Security.OpenTelemetry</c> satellite package which auto-registers this meter.
/// </summary>
/// <remarks>
/// Per ADR-019, uses only <c>System.Diagnostics.Metrics</c> from the BCL inbox assembly (.NET 6+).
/// No OTel SDK dependency. Fully Native AOT compatible.
/// </remarks>
public static class SecurityMeter
{
    /// <summary>Specifies the canonical meter name used when subscribing via <see cref="MeterListener"/>.</summary>
    public const string MeterName = "EricksonLopez.Security";

    /// <summary>Provides the shared <see cref="Meter"/> instance.</summary>
    public static readonly Meter Instance = new(MeterName, "1.1.0");

    // ── Counters ────────────────────────────────────────────────────────────────

    /// <summary>
    /// Gets a counter for the total number of successful AEAD encrypt operations.
    /// Tags: <c>security.algorithm</c> (e.g. "aes-256-gcm").
    /// </summary>
    public static readonly Counter<long> EncryptTotal =
        Instance.CreateCounter<long>(
            "security.encrypt.total",
            unit: "{operations}",
            description: "Total number of AEAD encryption operations.");

    /// <summary>
    /// Gets a counter for the total number of successful AEAD decrypt operations.
    /// Tags: <c>security.algorithm</c>, <c>security.key.version</c>.
    /// </summary>
    public static readonly Counter<long> DecryptTotal =
        Instance.CreateCounter<long>(
            "security.decrypt.total",
            unit: "{operations}",
            description: "Total number of AEAD decryption operations.");

    /// <summary>
    /// Gets a counter for the total number of key rotation events.
    /// Tags: <c>security.key.version</c> (the new version).
    /// </summary>
    public static readonly Counter<long> KeyRotationsTotal =
        Instance.CreateCounter<long>(
            "security.key.rotations_total",
            unit: "{rotations}",
            description: "Total number of cryptographic key rotation events.");

    /// <summary>
    /// Gets a counter for the total number of key revocation events.
    /// Tags: <c>security.key.version</c>, <c>security.result</c> (e.g. "success", "already_revoked").
    /// </summary>
    public static readonly Counter<long> KeyRevocationsTotal =
        Instance.CreateCounter<long>(
            "security.key.revocations_total",
            unit: "{revocations}",
            description: "Total number of cryptographic key revocation events.");

    /// <summary>
    /// Gets a counter for the total number of permanent key destruction events.
    /// Tags: <c>security.key.version</c>, <c>security.result</c> (e.g. "success", "failed").
    /// </summary>
    public static readonly Counter<long> KeyDestructionsTotal =
        Instance.CreateCounter<long>(
            "security.key.destructions_total",
            unit: "{destructions}",
            description: "Total number of permanent cryptographic key destruction events.");

    /// <summary>
    /// Gets a counter for the total number of API key validation attempts.
    /// Tags: <c>security.result</c> = "success" | "invalid" | "expired" | "revoked".
    /// </summary>
    public static readonly Counter<long> ApiKeyValidationsTotal =
        Instance.CreateCounter<long>(
            "security.apikey.validations_total",
            unit: "{validations}",
            description: "Total number of API key validation attempts.");

    /// <summary>
    /// Gets a counter for the total number of password verification attempts.
    /// Tags: <c>security.result</c> = "success" | "rehash_needed" | "failure".
    ///       <c>security.hash.algorithm</c> = "argon2id" | "pbkdf2-sha512".
    /// </summary>
    public static readonly Counter<long> PasswordVerificationsTotal =
        Instance.CreateCounter<long>(
            "security.password.verifications_total",
            unit: "{verifications}",
            description: "Total number of password verification attempts.");

    // ── Histograms ──────────────────────────────────────────────────────────────

    /// <summary>
    /// Gets a histogram measuring the duration of <c>LegacyPbkdf2PasswordHasher</c> password hashing operations in milliseconds.
    /// This is the primary latency signal for password security tuning.
    /// </summary>
    /// <remarks>
    /// <strong>v1.x substrate</strong>: <c>LegacyPbkdf2PasswordHasher</c> uses PBKDF2-HMAC-SHA512
    /// internally (effective iterations = <c>time_cost × 70,000</c>). Latency values measured
    /// by this histogram reflect PBKDF2 execution time, not RFC 9106 Argon2id memory-hard hashing.
    /// Use this data to tune <c>LegacyPbkdf2PasswordHasher(iterations)</c> to achieve your target
    /// hash duration (300–500 ms recommended). See ADR-024.
    /// </remarks>
    public static readonly Histogram<double> LegacyPbkdf2HashingDurationMs =
        Instance.CreateHistogram<double>(
            "security.legacypbkdf2.hashing_duration_ms",
            unit: "ms",
            description: "Duration of LegacyPbkdf2PasswordHasher hashing operations in milliseconds. v1.x substrate: PBKDF2-HMAC-SHA512.");


    /// <summary>
    /// Gets a histogram measuring the duration of PBKDF2 password hashing operations in milliseconds.
    /// </summary>
    public static readonly Histogram<double> Pbkdf2HashingDurationMs =
        Instance.CreateHistogram<double>(
            "security.pbkdf2.hashing_duration_ms",
            unit: "ms",
            description: "Duration of PBKDF2 password hashing operations in milliseconds.");
}
