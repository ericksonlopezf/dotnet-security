// Copyright © Erickson Lopez. MIT License.
using System;
using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

namespace EricksonLopez.Security.Mfa;

/// <summary>
/// Provides RFC 6238 Time-Based One-Time Password (TOTP) generation and constant-time verification services.
/// </summary>
/// <remarks>
/// <para>
/// <strong>⚠️ SEC-001 — Multi-node deployment limitation (replay protection).</strong>
/// </para>
/// <para>
/// This implementation stores consumed TOTP codes in an in-process <see cref="System.Collections.Concurrent.ConcurrentDictionary{TKey,TValue}"/>.
/// This provides correct replay protection <em>only on a single-node deployment</em>. In a
/// horizontally-scaled environment (Kubernetes pods, Azure App Service with multiple instances,
/// behind a load balancer, or any multi-process setup), each process maintains its own independent
/// in-memory store. A TOTP code verified on Node A can be immediately replayed against Node B,
/// Node C, etc., because they have no shared state.
/// </para>
/// <para>
/// <strong>For multi-node deployments</strong>, you must implement a distributed replay cache using
/// a shared backend such as Redis (<c>IDistributedCache</c>), a database, or any other
/// cross-process store. The recommended pattern is:
/// <list type="number">
///   <item>Use a time-bounded distributed cache key: <c>{sha256(secretKey)}:{timeStep}</c></item>
///   <item>Use <c>SET NX EX</c> (Redis) or equivalent atomic set-if-not-exists for thread-safety.</item>
///   <item>Set the TTL to <c>(AllowedDriftSteps + 2) × PeriodSeconds</c> seconds.</item>
/// </list>
/// </para>
/// <para>
/// <strong>Single-node deployments</strong>: Provides out-of-the-box replay protection for single-instance applications. The in-memory cache
/// is thread-safe, rate-limited to prevent DoS, and handles clock drift correctly per RFC 6238.
/// </para>
/// </remarks>
public sealed class TotpService : ITotpService
{
    private readonly TimeProvider _timeProvider;
    private readonly ITotpReplayStore? _replayStore;
    private readonly ConcurrentDictionary<string, DateTimeOffset> _consumedCodes = new(StringComparer.Ordinal);
    private long _lastPruneTicks;

    internal ConcurrentDictionary<string, DateTimeOffset> ConsumedCodes => _consumedCodes;
    internal int ConsumedCodesCount => _consumedCodes.Count;
    internal int MaxConsumedCodesCapacity { get; set; } = DefaultMaxConsumedCodesCapacity;
    internal int RoutinePruneThreshold { get; set; } = 1000;
    internal const int MaxCapacity = DefaultMaxConsumedCodesCapacity;
    private const int DefaultMaxConsumedCodesCapacity = 50_000;

    /// <summary>
    /// Initializes a new instance of the <see cref="TotpService"/> class.
    /// </summary>
    /// <param name="timeProvider">Optional time provider for testing time drift.</param>
    /// <param name="replayStore">Optional distributed or custom replay store for multi-node deployments.</param>
    public TotpService(TimeProvider? timeProvider = null, ITotpReplayStore? replayStore = null)
    {
        _timeProvider = timeProvider ?? TimeProvider.System;
        _replayStore = replayStore;
    }

    /// <inheritdoc />
    public byte[] GenerateSecretKey(int byteLength = 20)
    {
        if (byteLength < 16)
        {
            throw new ArgumentOutOfRangeException(nameof(byteLength), "Secret key length must be at least 16 bytes (128 bits).");
        }

        var keyBytes = new byte[byteLength];
        RandomNumberGenerator.Fill(keyBytes);
        return keyBytes;
    }

    /// <inheritdoc />
    public TotpSetupInfo GenerateSetupInfo(
        string issuer,
        string accountName,
        string? secretKey = null,
        TotpOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(issuer);
        ArgumentNullException.ThrowIfNull(accountName);

        var key = secretKey ?? Base32Encoding.ToBase32String(GenerateSecretKey());
        var opt = options ?? new TotpOptions();

        var sb = new StringBuilder();
        for (var i = 0; i < key.Length; i++)
        {
            if (i > 0 && i % 4 == 0)
            {
                sb.Append(' ');
            }
            sb.Append(key[i]);
        }
        var formattedKey = sb.ToString();

        var uri = $"otpauth://totp/{Uri.EscapeDataString(issuer)}:{Uri.EscapeDataString(accountName)}" +
                  $"?secret={key}" +
                  $"&issuer={Uri.EscapeDataString(issuer)}" +
                  $"&algorithm={opt.Algorithm.ToString().ToUpperInvariant()}" +
                  $"&digits={opt.Digits}" +
                  $"&period={opt.PeriodSeconds}";

        return new TotpSetupInfo(key, formattedKey, uri);
    }

    /// <inheritdoc />
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Security", "CA5350:Do Not Use Weak Cryptographic Algorithms", Justification = "HMAC-SHA1 is mandated by RFC 6238 Section 1.2 for standard TOTP interoperability.")]
    public string ComputeCode(string secretKey, DateTimeOffset timestamp, TotpOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(secretKey);

        var opt = options ?? new TotpOptions();
        var keyBytes = Base32Encoding.FromBase32String(secretKey);
        if (keyBytes.Length == 0)
        {
            throw new ArgumentException("Secret key cannot be empty or zero bytes.", nameof(secretKey));
        }

        try
        {
            return ComputeCodeCore(keyBytes, timestamp, opt);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(keyBytes);
        }
    }

    [System.Diagnostics.CodeAnalysis.SuppressMessage("Security", "CA5350:Do Not Use Weak Cryptographic Algorithms", Justification = "HMAC-SHA1 is mandated by RFC 6238 Section 1.2 for standard TOTP interoperability.")]
    private static string ComputeCodeCore(ReadOnlySpan<byte> keyBytes, DateTimeOffset timestamp, TotpOptions opt)
    {
        var timeStep = timestamp.ToUnixTimeSeconds() / opt.PeriodSeconds;

        Span<byte> timeStepBytes = stackalloc byte[8];
        BinaryPrimitives.WriteInt64BigEndian(timeStepBytes, timeStep);

        Span<byte> hash = stackalloc byte[64];
        int hashLength = opt.Algorithm switch
        {
            TotpHashAlgorithm.Sha256 => HMACSHA256.HashData(keyBytes, timeStepBytes, hash),
            TotpHashAlgorithm.Sha512 => HMACSHA512.HashData(keyBytes, timeStepBytes, hash),
            _ => HMACSHA1.HashData(keyBytes, timeStepBytes, hash)
        };
        var hashSpan = hash[..hashLength];

        // Dynamic truncation (RFC 4226 Section 5.4)
        var offset = hashSpan[^1] & 0x0F;
        var binaryCode =
            ((hashSpan[offset] & 0x7F) << 24) |
            ((hashSpan[offset + 1] & 0xFF) << 16) |
            ((hashSpan[offset + 2] & 0xFF) << 8) |
            (hashSpan[offset + 3] & 0xFF);

        var modulo = (int)Math.Pow(10, opt.Digits);
        var codeNumber = binaryCode % modulo;

        return codeNumber.ToString("D" + opt.Digits, System.Globalization.CultureInfo.InvariantCulture);
    }

    /// <inheritdoc />
    public bool VerifyCode(
        string secretKey,
        string code,
        DateTimeOffset? timestamp = null,
        TotpOptions? options = null)
    {
        if (string.IsNullOrWhiteSpace(secretKey) || string.IsNullOrWhiteSpace(code))
        {
            return false;
        }

        byte[] secretBytes;
        try
        {
            secretBytes = Base32Encoding.FromBase32String(secretKey);
        }
        catch (FormatException)
        {
            return false;
        }

        if (secretBytes.Length == 0)
        {
            return false;
        }

        try
        {
            var opt = options ?? new TotpOptions();
            var cleanCode = code.Trim();

            if (cleanCode.Length != opt.Digits)
            {
                return false;
            }

            var checkTime = timestamp ?? _timeProvider.GetUtcNow();
            Span<byte> codeBytes = stackalloc byte[16];
            int codeByteCount = Encoding.UTF8.GetBytes(cleanCode, codeBytes);
            var codeSlice = codeBytes[..codeByteCount];

            Span<byte> expectedBytesBuffer = stackalloc byte[16];
            bool matched = false;
            long matchedStepIndex = 0;

            for (var step = -opt.AllowedDriftSteps; step <= opt.AllowedDriftSteps; step++)
            {
                var stepTime = checkTime.AddSeconds(step * opt.PeriodSeconds);
                var expectedCode = ComputeCodeCore(secretBytes, stepTime, opt);
                int expectedByteCount = Encoding.UTF8.GetBytes(expectedCode, expectedBytesBuffer);
                var expectedSlice = expectedBytesBuffer[..expectedByteCount];

                bool isStepMatch = CryptographicOperations.FixedTimeEquals(codeSlice, expectedSlice);
                if (isStepMatch && !matched)
                {
                    matched = true;
                    matchedStepIndex = stepTime.ToUnixTimeSeconds() / opt.PeriodSeconds;
                }
            }

            if (!matched)
            {
                return false;
            }

            if (opt.PreventReplay)
            {
                // SEC-001 Mitigation: Compute replay hash using canonical decoded secret bytes
                // to prevent replay attacks using lowercase, padded, or whitespace-mutated Base32 strings.
                var keyHash = Convert.ToHexString(SHA256.HashData(secretBytes));
                string replayKey = $"{keyHash}:{matchedStepIndex}";
                var expiry = checkTime.AddSeconds((opt.AllowedDriftSteps + 2) * opt.PeriodSeconds);

                if (_replayStore != null)
                {
                    if (!_replayStore.TryAdd(replayKey, expiry))
                    {
                        return false;
                    }
                }
                else
                {
                    // FINDING-NEW-04: If replay cache has reached capacity, prune first
                    if (_consumedCodes.Count >= MaxConsumedCodesCapacity)
                    {
                        PruneExpiredCodes(checkTime);
                        if (_consumedCodes.Count >= MaxConsumedCodesCapacity)
                        {
                            // Saturated cache cannot safely track replay without evicting active tokens.
                            // Fail-closed to prevent replay attacks during DoS/memory flooding.
                            return false;
                        }
                    }

                    if (!_consumedCodes.TryAdd(replayKey, expiry))
                    {
                        // Token already used for this time step window (RFC 6238 replay protection)
                        return false;
                    }

                    if (_consumedCodes.Count > RoutinePruneThreshold)
                    {
                        PruneExpiredCodes(checkTime);
                    }
                }
            }

            return true;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(secretBytes);
        }
    }

    /// <summary>
    /// Asynchronously determines whether the provided code matches the secret key within the allowable time drift window,
    /// supporting distributed replay stores.
    /// </summary>
    /// <param name="secretKey">The Base32 encoded secret key.</param>
    /// <param name="code">The code entered by the user.</param>
    /// <param name="timestamp">Optional timestamp to verify against (default is current time).</param>
    /// <param name="options">Optional TOTP options.</param>
    /// <param name="cancellationToken">A token to monitor for cancellation requests.</param>
    /// <returns><see langword="true"/> if the code is valid; otherwise, <see langword="false"/>.</returns>
    public async System.Threading.Tasks.ValueTask<bool> VerifyCodeAsync(
        string secretKey,
        string code,
        DateTimeOffset? timestamp = null,
        TotpOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(secretKey) || string.IsNullOrWhiteSpace(code))
        {
            return false;
        }

        byte[] secretBytes;
        try
        {
            secretBytes = Base32Encoding.FromBase32String(secretKey);
        }
        catch (FormatException)
        {
            return false;
        }

        if (secretBytes.Length == 0)
        {
            return false;
        }

        try
        {
            var opt = options ?? new TotpOptions();
            var cleanCode = code.Trim();

            if (cleanCode.Length != opt.Digits)
            {
                return false;
            }

            var checkTime = timestamp ?? _timeProvider.GetUtcNow();
            Span<byte> codeBytes = stackalloc byte[16];
            int codeByteCount = Encoding.UTF8.GetBytes(cleanCode, codeBytes);
            var codeSlice = codeBytes[..codeByteCount];

            Span<byte> expectedBytesBuffer = stackalloc byte[16];

            for (var step = -opt.AllowedDriftSteps; step <= opt.AllowedDriftSteps; step++)
            {
                var stepTime = checkTime.AddSeconds(step * opt.PeriodSeconds);
                var expectedCode = ComputeCodeCore(secretBytes, stepTime, opt);
                int expectedByteCount = Encoding.UTF8.GetBytes(expectedCode, expectedBytesBuffer);
                var expectedSlice = expectedBytesBuffer[..expectedByteCount];

                if (CryptographicOperations.FixedTimeEquals(codeSlice, expectedSlice))
                {
                    if (opt.PreventReplay)
                    {
                        long stepIndex = stepTime.ToUnixTimeSeconds() / opt.PeriodSeconds;
                        var keyHash = Convert.ToHexString(SHA256.HashData(secretBytes));
                        string replayKey = $"{keyHash}:{stepIndex}";
                        var expiry = checkTime.AddSeconds((opt.AllowedDriftSteps + 2) * opt.PeriodSeconds);

                        if (_replayStore != null)
                        {
                            if (!await _replayStore.TryAddAsync(replayKey, expiry, cancellationToken).ConfigureAwait(false))
                            {
                                return false;
                            }
                        }
                        else
                        {
                            if (_consumedCodes.Count >= MaxConsumedCodesCapacity)
                            {
                                PruneExpiredCodes(checkTime);
                                if (_consumedCodes.Count >= MaxConsumedCodesCapacity)
                                {
                                    return false;
                                }
                            }

                            if (!_consumedCodes.TryAdd(replayKey, expiry))
                            {
                                return false;
                            }

                            if (_consumedCodes.Count > RoutinePruneThreshold)
                            {
                                PruneExpiredCodes(checkTime);
                            }
                        }
                    }

                    return true;
                }
            }

            return false;
        }
        finally
        {
            // Stryker disable once Statement : Defense-in-depth wiping of ephemeral secret in memory
            CryptographicOperations.ZeroMemory(secretBytes);
        }
    }


    private void PruneExpiredCodes(DateTimeOffset now)
    {
        long nowTicks = now.UtcTicks;
        long lastTicks = Volatile.Read(ref _lastPruneTicks);

        // Rate-limit routine pruning under load to avoid unnecessary full dictionary scans
        if (nowTicks - lastTicks < TimeSpan.FromSeconds(1).Ticks && _consumedCodes.Count < MaxConsumedCodesCapacity)
        {
            return;
        }

        if (Interlocked.CompareExchange(ref _lastPruneTicks, nowTicks, lastTicks) != lastTicks)
        {
            // Stryker disable once Statement : Concurrency optimization where losing race thread safely exits early
            return;
        }

        foreach (var kvp in _consumedCodes)
        {
            if (kvp.Value < now)
            {
                _consumedCodes.TryRemove(kvp.Key, out _);
            }
        }

        // Bounded capacity mitigation without replay bypass:
        // NEVER call _consumedCodes.Clear()! Clearing active tokens allows an attacker to replay valid tokens.
        // If still over capacity after removing expired entries, we CANNOT evict valid entries.
        // Fail-closed protection is enforced at the entry point in VerifyCode.
    }
}
