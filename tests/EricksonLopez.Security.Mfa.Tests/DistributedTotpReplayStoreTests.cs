// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Mfa.Tests;

using System;
using System.Collections.Concurrent;
using System.Threading;
using System.Threading.Tasks;
using AwesomeAssertions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Time.Testing;
using Xunit;

/// <summary>
/// Regression and verification tests for SEC-LOW-002:
/// Multi-node distributed TOTP replay prevention via DelegateTotpReplayStore.
/// </summary>
public sealed class DistributedTotpReplayStoreTests
{
    private readonly FakeTimeProvider _timeProvider = new(new DateTimeOffset(2050, 8, 30, 12, 0, 0, TimeSpan.Zero));
    private const string Secret = "JBSWY3DPEHPK3PXP";

    [Fact]
    public async Task DistributedReplayStore_BlocksCrossNodeReplay()
    {
        // Arrange: Shared cluster storage simulated via ConcurrentDictionary
        var clusterStorage = new ConcurrentDictionary<string, DateTimeOffset>(StringComparer.Ordinal);
        var distributedStore = new DelegateTotpReplayStore(
            asyncHandler: (key, expiry, ct) => ValueTask.FromResult(clusterStorage.TryAdd(key, expiry)),
            syncHandler: (key, expiry) => clusterStorage.TryAdd(key, expiry));

        // Node A and Node B represent separate server instances in a distributed cluster
        var nodeA = new TotpService(_timeProvider, distributedStore);
        var nodeB = new TotpService(_timeProvider, distributedStore);

        var options = new TotpOptions { PreventReplay = true };
        var code = nodeA.ComputeCode(Secret, _timeProvider.GetUtcNow(), options);

        // Act: Verify on Node A
        var nodeAVerified = await nodeA.VerifyCodeAsync(Secret, code, _timeProvider.GetUtcNow(), options);
        nodeAVerified.Should().BeTrue(because: "first presentation of the token on Node A must succeed");

        // Act: Attacker attempts to replay the token on Node B within the same time window
        var nodeBReplay = await nodeB.VerifyCodeAsync(Secret, code, _timeProvider.GetUtcNow(), options);

        // Assert: Replay on Node B must fail closed
        nodeBReplay.Should().BeFalse(because: "token was already consumed on Node A and recorded in distributed replay store");
    }

    [Fact]
    public void DistributedReplayStore_SynchronousVerification_BlocksCrossNodeReplay()
    {
        var clusterStorage = new ConcurrentDictionary<string, DateTimeOffset>(StringComparer.Ordinal);
        var distributedStore = new DelegateTotpReplayStore(
            asyncHandler: (key, expiry, ct) => ValueTask.FromResult(clusterStorage.TryAdd(key, expiry)),
            syncHandler: (key, expiry) => clusterStorage.TryAdd(key, expiry));

        var nodeA = new TotpService(_timeProvider, distributedStore);
        var nodeB = new TotpService(_timeProvider, distributedStore);

        var options = new TotpOptions { PreventReplay = true };
        var code = nodeA.ComputeCode(Secret, _timeProvider.GetUtcNow(), options);

        var nodeAResult = nodeA.VerifyCode(Secret, code, _timeProvider.GetUtcNow(), options);
        nodeAResult.Should().BeTrue();

        var nodeBResult = nodeB.VerifyCode(Secret, code, _timeProvider.GetUtcNow(), options);
        nodeBResult.Should().BeFalse(because: "synchronous replay must also check the distributed replay store");
    }

    [Fact]
    public void AddDistributedTotpReplayStore_RegistersServiceCorrectly()
    {
        var services = new ServiceCollection();
        services.AddSecurityMfa();
        services.AddDistributedTotpReplayStore((key, expiry, ct) => ValueTask.FromResult(true));

        using var provider = services.BuildServiceProvider();
        var store = provider.GetService<ITotpReplayStore>();

        store.Should().NotBeNull();
        store.Should().BeOfType<DelegateTotpReplayStore>();
    }
}
