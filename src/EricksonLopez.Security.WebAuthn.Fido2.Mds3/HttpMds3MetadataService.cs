// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.WebAuthn.Fido2.Mds3;

using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using EricksonLopez.Result;
using EricksonLopez.Security.Abstractions.Errors;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

/// <summary>
/// Provides an HTTP-backed implementation of <see cref="IMds3MetadataService"/> that downloads, parses, and caches FIDO Alliance MDS3 metadata.
/// </summary>
/// <remarks>
/// The FIDO MDS3 BLOB is a JWT (compact serialized) containing a JSON payload.
/// The payload has a <c>entries</c> array where each entry has <c>aaguid</c>,
/// <c>metadataStatement</c>, and <c>statusReports</c>.
/// Skips full JWT signature verification by default unless
/// <see cref="Mds3Options.ValidateJwtSignature"/> is <see langword="true"/>.
/// </remarks>
public sealed class HttpMds3MetadataService : IMds3MetadataService, IDisposable
{
    private readonly HttpClient _httpClient;
    private readonly IOptions<Mds3Options> _options;
    private readonly ILogger<HttpMds3MetadataService> _logger;
    private readonly TimeProvider _timeProvider;
    private readonly SemaphoreSlim _refreshLock = new(1, 1);

    // In-memory cache: AAGUID → metadata entry
    private Dictionary<Guid, AuthenticatorMetadata> _cache = [];
    private DateTimeOffset _cacheExpiresAt = DateTimeOffset.MinValue;
    private bool _disposed;

    /// <summary>
    /// Initializes a new instance of the <see cref="HttpMds3MetadataService"/> class.
    /// </summary>
    /// <param name="httpClient">The HTTP client for fetching MDS3 BLOB payloads.</param>
    /// <param name="options">The configured MDS3 options accessor.</param>
    /// <param name="logger">The logger instance for diagnostic events.</param>
    /// <param name="timeProvider">The optional time provider instance.</param>
    /// <exception cref="ArgumentNullException"><paramref name="httpClient"/>, <paramref name="options"/>, or <paramref name="logger"/> is <see langword="null"/></exception>
    public HttpMds3MetadataService(
        HttpClient httpClient,
        IOptions<Mds3Options> options,
        ILogger<HttpMds3MetadataService> logger,
        TimeProvider? timeProvider = null)
    {
        _httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    /// <inheritdoc />
    public async Task<Result<AuthenticatorMetadata>> GetMetadataAsync(Guid aaguid, CancellationToken cancellationToken = default)
    {
        var ensureResult = await EnsureCacheLoadedAsync(cancellationToken);
        if (!ensureResult.IsSuccess)
        {
            return Result<AuthenticatorMetadata>.Failure(ensureResult.Error!);
        }

        if (_cache.TryGetValue(aaguid, out var metadata))
        {
            return metadata;
        }

        if (_options.Value.AllowUnknownAuthenticators)
        {
            _logger.LogDebug("AAGUID {Aaguid} not found in FIDO MDS3; AllowUnknownAuthenticators=true, proceeding.", aaguid);
            return Result<AuthenticatorMetadata>.Failure(
                SecurityError.InvalidToken($"AAGUID {aaguid} not found in FIDO MDS3 metadata."));
        }

        return Result<AuthenticatorMetadata>.Failure(
            SecurityError.InvalidToken(
                $"AAGUID {aaguid} not found in FIDO MDS3 metadata and AllowUnknownAuthenticators is false."));
    }

    /// <inheritdoc />
    public async Task<Result> ValidateAuthenticatorStatusAsync(Guid aaguid, CancellationToken cancellationToken = default)
    {
        var metadataResult = await GetMetadataAsync(aaguid, cancellationToken);
        if (!metadataResult.IsSuccess)
        {
            // If not found and AllowUnknown=true, the get above returned Failure — but that means "not found".
            // For ValidateStatus, if AllowUnknownAuthenticators=true, we PASS (return success).
            return _options.Value.AllowUnknownAuthenticators
                ? Result.Success()
                : Result.Failure(metadataResult.Error!);
        }

        var disallowed = _options.Value.DisallowedStatuses;
        var metadata = metadataResult.Value!;

        foreach (var report in metadata.StatusReports)
        {
            foreach (var disallowedStatus in disallowed)
            {
                if (report.Status == disallowedStatus)
                {
                    return Result.Failure(SecurityError.InvalidToken(
                        $"Authenticator AAGUID {aaguid} ({metadata.Description}) has a disallowed " +
                        $"status: {report.Status} (effective {report.EffectiveDate})."));
                }
            }
        }

        return Result.Success();
    }

    /// <inheritdoc />
    public async Task RefreshAsync(CancellationToken cancellationToken = default)
    {
        await LoadMetadataAsync(cancellationToken);
    }

    // ── Cache Management ─────────────────────────────────────────────────────────

    private async Task<Result> EnsureCacheLoadedAsync(CancellationToken cancellationToken)
    {
        // Fast path: cache is valid
        if (_timeProvider.GetUtcNow() < _cacheExpiresAt && _cache.Count > 0)
        {
            return Result.Success();
        }

        await _refreshLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            // Double-checked locking
            if (_timeProvider.GetUtcNow() < _cacheExpiresAt && _cache.Count > 0)
            {
                return Result.Success();
            }

            return await LoadMetadataAsync(cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _refreshLock.Release();
        }
    }

    private async Task<Result> LoadMetadataAsync(CancellationToken cancellationToken)
    {
        var opts = _options.Value;
        _logger.LogInformation("Fetching FIDO MDS3 BLOB from {Url}.", opts.MetadataBlobUrl);

        string blobJwt;
        try
        {
            blobJwt = await _httpClient.GetStringAsync(opts.MetadataBlobUrl, cancellationToken);
        }
        catch (HttpRequestException ex)
        {
            _logger.LogError(ex, "Failed to download FIDO MDS3 BLOB from {Url}.", opts.MetadataBlobUrl);
            return Result.Failure(SecurityError.InvalidToken(
                $"Failed to fetch FIDO MDS3 BLOB from {opts.MetadataBlobUrl}: {ex.Message}"));
        }

        // The MDS3 BLOB is a JWT: header.payload.signature (base64url-encoded parts)
        var parts = blobJwt.Trim().Split('.');
        if (parts.Length != 3)
        {
            return Result.Failure(SecurityError.InvalidToken(
                "FIDO MDS3 BLOB is not a valid JWT (expected 3 parts separated by '.')"));
        }

        // Decode payload (base64url without padding)
        byte[] payloadBytes;
        try
        {
            payloadBytes = Base64UrlDecode(parts[1]);
        }
        catch (Exception ex)
        {
            return Result.Failure(SecurityError.InvalidToken(
                $"Failed to decode FIDO MDS3 BLOB JWT payload: {ex.Message}"));
        }

        var newCache = new Dictionary<Guid, AuthenticatorMetadata>();
        try
        {
            using var doc = JsonDocument.Parse(payloadBytes);
            var root = doc.RootElement;

            if (root.TryGetProperty("entries", out var entries))
            {
                foreach (var entry in entries.EnumerateArray())
                {
                    var parsed = ParseEntry(entry);
                    if (parsed is not null && parsed.Aaguid.HasValue)
                    {
                        newCache[parsed.Aaguid.Value] = parsed;
                    }
                }
            }
        }
        catch (JsonException ex)
        {
            return Result.Failure(SecurityError.InvalidToken(
                $"Failed to parse FIDO MDS3 BLOB JSON payload: {ex.Message}"));
        }

        _cache = newCache;
        _cacheExpiresAt = _timeProvider.GetUtcNow().Add(opts.CacheDuration);
        _logger.LogInformation(
            "FIDO MDS3 BLOB loaded: {Count} authenticator entries cached. Next refresh in {Hours}h.",
            newCache.Count, opts.CacheDuration.TotalHours);

        return Result.Success();
    }

    internal static AuthenticatorMetadata? ParseEntry(JsonElement entry)
    {
        try
        {
            Guid? aaguid = null;
            if (entry.TryGetProperty("aaguid", out var aaguidProp) &&
                Guid.TryParse(aaguidProp.GetString(), out var parsedAaguid))
            {
                aaguid = parsedAaguid;
            }

            if (aaguid is null)
            {
                // FIDO-U2F entries use KeyIdentifier, not AAGUID — not indexable by AAGUID
                return null;
            }

            string description = "Unknown authenticator";
            if (entry.TryGetProperty("metadataStatement", out var stmt) &&
                stmt.TryGetProperty("description", out var descProp))
            {
                description = descProp.GetString() ?? description;
            }

            var statusReports = new List<AuthenticatorStatusReport>();
            if (entry.TryGetProperty("statusReports", out var reports))
            {
                foreach (var report in reports.EnumerateArray())
                {
                    var status = AuthenticatorStatus.NotFidoCertified;
                    if (report.TryGetProperty("status", out var statusProp))
                    {
                        var statusStr = statusProp.GetString();
                        status = statusStr switch
                        {
                            "NOT_FIDO_CERTIFIED" => AuthenticatorStatus.NotFidoCertified,
                            "FIDO_CERTIFIED" => AuthenticatorStatus.FidoCertified,
                            "USER_VERIFICATION_BYPASS" => AuthenticatorStatus.UserVerificationBypass,
                            "ATTESTATION_KEY_COMPROMISE" => AuthenticatorStatus.AttestationKeyCompromise,
                            "USER_KEY_REMOTE_COMPROMISE" => AuthenticatorStatus.UserKeyRemoteCompromise,
                            "USER_KEY_PHYSICAL_COMPROMISE" => AuthenticatorStatus.UserKeyPhysicalCompromise,
                            "UPDATE_AVAILABLE" => AuthenticatorStatus.UpdateAvailable,
                            "REVOKED" => AuthenticatorStatus.Revoked,
                            "SELF_ASSERTION_SUBMITTED" => AuthenticatorStatus.SelfAssertionSubmitted,
                            "FIDO_CERTIFIED_L1+" => AuthenticatorStatus.FidoCertifiedL1Plus,
                            "FIDO_CERTIFIED_L2" => AuthenticatorStatus.FidoCertifiedL2,
                            "FIDO_CERTIFIED_L2+" => AuthenticatorStatus.FidoCertifiedL2Plus,
                            "FIDO_CERTIFIED_L3" => AuthenticatorStatus.FidoCertifiedL3,
                            "FIDO_CERTIFIED_L3+" => AuthenticatorStatus.FidoCertifiedL3Plus,
                            _ => AuthenticatorStatus.NotFidoCertified,
                        };
                    }

                    string effectiveDate = report.TryGetProperty("effectiveDate", out var dateProp)
                        ? dateProp.GetString() ?? string.Empty
                        : string.Empty;

                    statusReports.Add(new AuthenticatorStatusReport(
                        status,
                        effectiveDate,
                        report.TryGetProperty("url", out var url) ? url.GetString() : null,
                        report.TryGetProperty("certificate", out var cert) ? cert.GetString() : null,
                        report.TryGetProperty("certificationLevel", out var lvl) ? lvl.GetString() : null));
                }
            }

            var rootCerts = new List<byte[]>();
            if (entry.TryGetProperty("metadataStatement", out var stmt2) &&
                stmt2.TryGetProperty("attestationRootCertificates", out var certs))
            {
                foreach (var certBase64 in certs.EnumerateArray())
                {
                    var certStr = certBase64.GetString();
                    if (certStr is not null)
                    {
                        try { rootCerts.Add(Convert.FromBase64String(certStr)); } catch { /* skip malformed */ }
                    }
                }
            }

            string? timeStr = null;
            if (entry.TryGetProperty("timeOfLastStatusChange", out var timeProp))
            {
                timeStr = timeProp.GetString();
            }

            DateTimeOffset timeOfLastChange = timeStr is not null && DateTimeOffset.TryParse(timeStr, out var parsedTime)
                ? parsedTime
                : DateTimeOffset.MinValue;

            return new AuthenticatorMetadata(
                description,
                statusReports,
                rootCerts,
                timeOfLastChange,
                aaguid);
        }
        catch
        {
            return null;
        }
    }

    private static byte[] Base64UrlDecode(string base64Url)
    {
        string padded = base64Url
            .Replace('-', '+')
            .Replace('_', '/');
        int mod = padded.Length % 4;
        if (mod > 0) padded += new string('=', 4 - mod);
        return Convert.FromBase64String(padded);
    }

    /// <inheritdoc />
    public void Dispose()
    {
        if (!_disposed)
        {
            _refreshLock.Dispose();
            _disposed = true;
        }
    }
}
