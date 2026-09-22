// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.KeyManagement;

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using EricksonLopez.Result;
using EricksonLopez.Security.Abstractions.Errors;
using EricksonLopez.Security.Abstractions.Events;
using EricksonLopez.Security.Abstractions.KeyManagement;
using EricksonLopez.Security.Abstractions.Primitives;
using EricksonLopez.Security.Diagnostics;
using EricksonLopez.Security.Memory;

/// <summary>
/// Orchestrates cryptographic key generation, rotation, retirement, and revocation workflows.
/// </summary>
public sealed class KeyLifecycleManager : IKeyLifecycleManager, IDisposable
{
    private readonly IKeyStore _keyStore;
    private readonly Action<ISecurityEvent>? _eventPublisher;
    private readonly bool _failOnAuditFailure;
    private readonly IKeyRevocationNotifier? _revocationNotifier;
    private readonly ConcurrentDictionary<KeyPurpose, SemaphoreSlim> _purposeSemaphores = new();

    /// <summary>
    /// Initializes a new instance of the <see cref="KeyLifecycleManager"/> class.
    /// </summary>
    /// <param name="keyStore">The key storage repository.</param>
    /// <param name="eventPublisher">Optional security event dispatcher delegate.</param>
    /// <param name="failOnAuditFailure">
    /// Indicates whether event publisher exceptions should fail the operation (<see langword="true"/>, fail-stop for regulated environments)
    /// or be handled in degraded mode with diagnostic activity logging (<see langword="false"/>, default).
    /// </param>
    /// <exception cref="ArgumentNullException"><paramref name="keyStore"/> is <see langword="null"/></exception>
    public KeyLifecycleManager(
        IKeyStore keyStore,
        Action<ISecurityEvent>? eventPublisher = null,
        bool failOnAuditFailure = false) : this(keyStore, eventPublisher, failOnAuditFailure, null)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="KeyLifecycleManager"/> class with a revocation notifier.
    /// </summary>
    /// <param name="keyStore">The key storage repository.</param>
    /// <param name="eventPublisher">Optional security event dispatcher delegate.</param>
    /// <param name="failOnAuditFailure">
    /// Indicates whether event publisher exceptions should fail the operation (<see langword="true"/>, fail-stop for regulated environments)
    /// or be handled in degraded mode with diagnostic activity logging (<see langword="false"/>, default).
    /// </param>
    /// <param name="revocationNotifier">Optional key revocation notifier for real-time cache invalidation.</param>
    /// <exception cref="ArgumentNullException"><paramref name="keyStore"/> is <see langword="null"/></exception>
    public KeyLifecycleManager(
        IKeyStore keyStore,
        Action<ISecurityEvent>? eventPublisher,
        bool failOnAuditFailure,
        IKeyRevocationNotifier? revocationNotifier)
    {
        _keyStore = keyStore ?? throw new ArgumentNullException(nameof(keyStore));
        _eventPublisher = eventPublisher;
        _failOnAuditFailure = failOnAuditFailure;
        _revocationNotifier = revocationNotifier;
    }

    /// <inheritdoc />
    public async ValueTask<Result<CryptographicKey>> GenerateAndActivateKeyAsync(
        KeyPurpose purpose,
        string algorithmId = "AES-256-GCM",
        TimeSpan? validityPeriod = null,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var semaphore = _purposeSemaphores.GetOrAdd(purpose, _ => new SemaphoreSlim(1, 1));
        await semaphore.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var keyId = KeyIdentifier.Prefixed(purpose.ToString().ToLowerInvariant());
            var now = DateTimeOffset.UtcNow;
            var expiresAt = validityPeriod.HasValue ? now.Add(validityPeriod.Value) : (DateTimeOffset?)null;

            // KM-006 (resolved): always derive the new version from the highest existing version for this
            // purpose so that re-generating after a revocation does not collide with KeyVersion.Initial.
            var allKeysResult = await _keyStore.ListMetadataAsync(purpose, cancellationToken).ConfigureAwait(false);
            KeyVersion version;
            if (allKeysResult.IsSuccess && allKeysResult.Value.Count > 0)
            {
                var highest = allKeysResult.Value
                    .Where(k => k.Purpose == purpose)
                    .MaxBy(k => k.Version.Value);
                version = highest is not null ? highest.Version.Next() : KeyVersion.Initial;
            }
            else
            {
                version = KeyVersion.Initial;
            }

            var metadata = new KeyMetadata(
                KeyId: keyId,
                Version: version,
                Purpose: purpose,
                Status: KeyStatus.Active,
                AlgorithmId: algorithmId,
                CreatedAtUtc: now,
                ExpiresAtUtc: expiresAt);

            var keyBuffer = SecretBuffer.CreateRandom(32);
            var key = new CryptographicKey(metadata, keyBuffer);

            var saveResult = await _keyStore.SaveKeyAsync(key, cancellationToken).ConfigureAwait(false);
            if (saveResult.IsFailure)
            {
                key.Dispose();
                return saveResult.Error;
            }

            return key;
        }
        finally
        {
            semaphore.Release();
        }
    }

    /// <inheritdoc />
    public async ValueTask<Result<CryptographicKey>> RotateKeyAsync(
        KeyPurpose purpose,
        TimeSpan? validityPeriod = null,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var semaphore = _purposeSemaphores.GetOrAdd(purpose, _ => new SemaphoreSlim(1, 1));
        await semaphore.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var metadataListResult = await _keyStore.ListMetadataAsync(purpose, cancellationToken).ConfigureAwait(false);
            if (metadataListResult.IsFailure)
            {
                return metadataListResult.Error;
            }

            var activeKeys = new List<KeyMetadata>();
            foreach (var m in metadataListResult.Value)
            {
                if (m.Purpose == purpose && m.Status == KeyStatus.Active)
                {
                    activeKeys.Add(m);
                }
            }

            activeKeys.Sort((a, b) => b.Version.Value.CompareTo(a.Version.Value));

            KeyIdentifier keyId;
            KeyVersion previousVersion;
            KeyVersion newVersion;
            string algorithmId = "AES-256-GCM";

            if (activeKeys.Count > 0)
            {
                var currentActive = activeKeys[0];
                keyId = currentActive.KeyId;
                previousVersion = currentActive.Version;
                newVersion = previousVersion.Next();
                algorithmId = currentActive.AlgorithmId;
            }
            else
            {
                keyId = KeyIdentifier.Prefixed(purpose.ToString().ToLowerInvariant());
                previousVersion = KeyVersion.Initial;
                newVersion = KeyVersion.Initial;
            }

            var now = DateTimeOffset.UtcNow;
            var expiresAt = validityPeriod.HasValue ? now.Add(validityPeriod.Value) : (DateTimeOffset?)null;

            var newMetadata = new KeyMetadata(
                KeyId: keyId,
                Version: newVersion,
                Purpose: purpose,
                Status: KeyStatus.Active,
                AlgorithmId: algorithmId,
                CreatedAtUtc: now,
                ExpiresAtUtc: expiresAt);

            var keyBuffer = SecretBuffer.CreateRandom(32);
            var newKey = new CryptographicKey(newMetadata, keyBuffer);

            var saveResult = await _keyStore.SaveKeyAsync(newKey, cancellationToken).ConfigureAwait(false);
            if (saveResult.IsFailure)
            {
                newKey.Dispose();
                return saveResult.Error;
            }

            // KLM-03 (resolved): Retire ALL active keys for this purpose, not just the highest-version one.
            // Prior partial rotations may have left multiple Active keys. Retiring only the highest-version key
            // would leave stale Active keys that could be returned by GetActiveKeyAsync under load.
            // We retire all active keys atomically before activating the new one. If any retirement fails,
            // the new key is rolled back to Revoked to prevent split-brain dual-active state.
            if (activeKeys.Count > 0)
            {
                foreach (var activeKey in activeKeys)
                {
                    var updateStatusResult = await _keyStore.UpdateStatusAsync(
                        activeKey.KeyId, activeKey.Version, KeyStatus.Retired, cancellationToken).ConfigureAwait(false);

                    if (updateStatusResult.IsFailure)
                    {
                        // SEC-008: Transactional rollback — revoke the new key so no dual-active state persists.
                        await _keyStore.UpdateStatusAsync(keyId, newVersion, KeyStatus.Revoked, cancellationToken).ConfigureAwait(false);
                        newKey.Dispose();
                        return updateStatusResult.Error;
                    }
                }
            }

            try
            {
                _eventPublisher?.Invoke(KeyRotatedEvent.Create(keyId, previousVersion, newVersion, purpose));
            }
            catch (Exception ex)
            {
                using var activity = SecurityActivitySource.Instance.StartActivity("KeyLifecycleEventFailed");
                activity?.SetStatus(System.Diagnostics.ActivityStatusCode.Error, ex.Message);
                if (_failOnAuditFailure)
                {
                    // FINDING-NEW-07 + KLM-03: Transactional rollback on audit publication failure.
                    // Restore ALL previously active keys (not just the highest-version one) to Active,
                    // consistent with the retire-all semantics introduced by KLM-03.
                    if (activeKeys.Count > 0)
                    {
                        foreach (var activeKey in activeKeys)
                        {
                            await _keyStore.UpdateStatusAsync(activeKey.KeyId, activeKey.Version, KeyStatus.Active, cancellationToken).ConfigureAwait(false);
                        }
                    }

                    await _keyStore.UpdateStatusAsync(keyId, newVersion, KeyStatus.Revoked, cancellationToken).ConfigureAwait(false);
                    newKey.Dispose();
                    return SecurityError.AuditFailed($"Audit event publication failed: {ex.Message}");
                }
            }

            SecurityMeter.KeyRotationsTotal.Add(
                1,
                new KeyValuePair<string, object?>("security.key.version", newVersion.Value));

            return newKey;
        }
        finally
        {
            semaphore.Release();
        }
    }

    /// <inheritdoc />
    public async ValueTask<Result> RevokeKeyAsync(
        KeyIdentifier keyId,
        KeyVersion version,
        string reason,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentException.ThrowIfNullOrWhiteSpace(reason);

        var keyResult = await _keyStore.GetKeyAsync(keyId, version, cancellationToken).ConfigureAwait(false);
        var previousStatus = KeyStatus.Active;
        var purpose = KeyPurpose.Encryption;
        if (keyResult.IsSuccess)
        {
            using (keyResult.Value)
            {
                previousStatus = keyResult.Value.Metadata.Status;
                purpose = keyResult.Value.Metadata.Purpose;
            }
        }

        var updateResult = await _keyStore.UpdateStatusAsync(keyId, version, KeyStatus.Revoked, cancellationToken).ConfigureAwait(false);
        if (updateResult.IsFailure)
        {
            SecurityMeter.KeyRevocationsTotal.Add(
                1,
                new KeyValuePair<string, object?>("security.key.version", version.Value),
                new KeyValuePair<string, object?>("security.result", "failed"));
            return updateResult;
        }

        try
        {
            _eventPublisher?.Invoke(KeyRevokedEvent.Create(keyId, version, purpose, reason));
        }
        catch (Exception ex)
        {
            using var activity = SecurityActivitySource.Instance.StartActivity("KeyLifecycleEventFailed");
            activity?.SetStatus(System.Diagnostics.ActivityStatusCode.Error, ex.Message);
            if (_failOnAuditFailure)
            {
                // FINDING-NEW-07: Transactional rollback of status update
                await _keyStore.UpdateStatusAsync(keyId, version, previousStatus, cancellationToken).ConfigureAwait(false);
                return SecurityError.AuditFailed($"Audit event publication failed: {ex.Message}");
            }
        }

        if (_revocationNotifier != null)
        {
            await _revocationNotifier.NotifyRevokedAsync(keyId, version, purpose, cancellationToken).ConfigureAwait(false);
        }

        SecurityMeter.KeyRevocationsTotal.Add(
            1,
            new KeyValuePair<string, object?>("security.key.version", version.Value),
            new KeyValuePair<string, object?>("security.result", "success"));

        return Result.Success();
    }

    /// <inheritdoc />
    public void Dispose()
    {
        foreach (var semaphore in _purposeSemaphores.Values)
        {
            semaphore.Dispose();
        }
        _purposeSemaphores.Clear();
        GC.SuppressFinalize(this);
    }
}
