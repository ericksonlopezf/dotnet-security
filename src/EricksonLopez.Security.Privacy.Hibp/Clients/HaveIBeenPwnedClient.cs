// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Privacy.Hibp.Clients;

using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using EricksonLopez.Result;
using EricksonLopez.Security.Abstractions.Errors;
using EricksonLopez.Security.Privacy.Hibp.Abstractions;
using EricksonLopez.Security.Privacy.Hibp.Models;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

/// <summary>
/// Provides a Have I Been Pwned API client enforcing privacy-preserving k-Anonymity and anti-traffic analysis padding.
/// </summary>
public sealed class HaveIBeenPwnedClient : IHaveIBeenPwnedClient
{
    private readonly HttpClient _httpClient;
    private readonly HibpOptions _options;
    private readonly ILogger<HaveIBeenPwnedClient> _logger;

    /// <summary>
    /// Initializes a new instance of the <see cref="HaveIBeenPwnedClient"/> class.
    /// </summary>
    /// <param name="httpClient">The HTTP client for communicating with the Have I Been Pwned range API.</param>
    /// <param name="options">The configured HIBP integration options accessor.</param>
    /// <param name="logger">Optional logger instance for diagnostic events.</param>
    /// <exception cref="ArgumentNullException"><paramref name="httpClient"/> or <paramref name="options"/> is <see langword="null"/></exception>
    public HaveIBeenPwnedClient(
        HttpClient httpClient,
        IOptions<HibpOptions> options,
        ILogger<HaveIBeenPwnedClient>? logger = null)
    {
        _httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
        _options = options?.Value ?? throw new ArgumentNullException(nameof(options));
        _logger = logger ?? NullLogger<HaveIBeenPwnedClient>.Instance;
    }

    /// <inheritdoc />
    [SuppressMessage("Security", "CA5350:Do Not Use Weak Cryptographic Algorithms", Justification = "SHA-1 is mandated by the Have I Been Pwned k-Anonymity range API.")]
    public async Task<Result<PwnedPasswordCheckResult>> CheckPasswordAsync(string password, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(password))
        {
            return Result<PwnedPasswordCheckResult>.Success(new PwnedPasswordCheckResult("00000", 0));
        }

        int maxByteCount = Encoding.UTF8.GetMaxByteCount(password.Length);
        byte[]? rented = null;
        Span<byte> utf8Bytes = maxByteCount <= 256
            ? stackalloc byte[maxByteCount]
            : (rented = ArrayPool<byte>.Shared.Rent(maxByteCount));

        Span<byte> hashBytes = stackalloc byte[20];
        string fullHexHash;
        try
        {
            int actualBytes = Encoding.UTF8.GetBytes(password.AsSpan(), utf8Bytes);
            SHA1.HashData(utf8Bytes[..actualBytes], hashBytes);
            fullHexHash = Convert.ToHexString(hashBytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(utf8Bytes);
            CryptographicOperations.ZeroMemory(hashBytes);
            if (rented is not null)
            {
                ArrayPool<byte>.Shared.Return(rented);
            }
        }

        var prefix = fullHexHash[..5];
        var suffix = fullHexHash[5..];

        var rangeResult = await GetRangeAsync(prefix, cancellationToken).ConfigureAwait(false);
        if (rangeResult.IsFailure)
        {
            return Result<PwnedPasswordCheckResult>.Failure(rangeResult.Error);
        }

        long breachCount = 0;
        foreach (var entry in rangeResult.Value)
        {
            if (string.Equals(entry.Suffix, suffix, StringComparison.OrdinalIgnoreCase))
            {
                breachCount = entry.BreachCount;
                break;
            }
        }

        return Result<PwnedPasswordCheckResult>.Success(new PwnedPasswordCheckResult(prefix, breachCount));
    }

    /// <inheritdoc />
    public async Task<Result<IReadOnlyList<PwnedPasswordEntry>>> GetRangeAsync(string hashPrefix, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(hashPrefix);

        if (hashPrefix.Length != 5)
        {
            return Result<IReadOnlyList<PwnedPasswordEntry>>.Failure(
                SecurityError.InvalidKey("HIBP range search requires an exact 5-character hexadecimal SHA-1 prefix."));
        }

        var requestUrl = $"range/{hashPrefix.ToUpperInvariant()}";
        using var request = new HttpRequestMessage(HttpMethod.Get, requestUrl);

        if (!string.IsNullOrEmpty(_options.UserAgent))
        {
            request.Headers.UserAgent.ParseAdd(_options.UserAgent);
        }

        if (_options.AddPadding)
        {
            request.Headers.TryAddWithoutValidation("Add-Padding", "true");
        }

        try
        {
            using var response = await _httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false);

            if (!response.IsSuccessStatusCode)
            {
                _logger.LogWarning("HIBP range query for prefix '{Prefix}' failed with status code {StatusCode}.", hashPrefix, response.StatusCode);
                return Result<IReadOnlyList<PwnedPasswordEntry>>.Failure(
                    Error.Failure("Security.ServiceUnavailable", $"HIBP API returned HTTP {(int)response.StatusCode}: {response.ReasonPhrase}."));
            }

            var contentStream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
            using var reader = new StreamReader(contentStream, Encoding.UTF8);

            var entries = new List<PwnedPasswordEntry>();
            string? line;
            while ((line = await reader.ReadLineAsync(cancellationToken).ConfigureAwait(false)) is not null)
            {
                var colonIndex = line.IndexOf(':');
                if (colonIndex > 0)
                {
                    var suffix = line[..colonIndex].Trim();
                    var countSpan = line[(colonIndex + 1)..].Trim();

                    if (long.TryParse(countSpan, out var count))
                    {
                        entries.Add(new PwnedPasswordEntry(suffix, count));
                    }
                }
            }

            return Result<IReadOnlyList<PwnedPasswordEntry>>.Success(entries);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Exception while querying HIBP range API for prefix '{Prefix}'.", hashPrefix);
            return Result<IReadOnlyList<PwnedPasswordEntry>>.Failure(
                Error.Failure("Security.ServiceUnavailable", $"HIBP API communication failed: {ex.Message}"));
        }
    }
}
