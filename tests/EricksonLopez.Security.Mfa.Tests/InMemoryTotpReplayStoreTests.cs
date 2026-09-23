// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Mfa.Tests;

using System;
using System.Threading;
using System.Threading.Tasks;
using AwesomeAssertions;
using Xunit;

public sealed class InMemoryTotpReplayStoreTests
{
    [Fact]
    public void Constructor_InvalidArguments_ThrowsArgumentOutOfRangeException()
    {
        var ex1 = Assert.Throws<ArgumentOutOfRangeException>(() => new InMemoryTotpReplayStore(maxCapacity: 0));
        ex1.Message.Should().Contain("Maximum capacity must be greater than zero.");
        Assert.Throws<ArgumentOutOfRangeException>(() => new InMemoryTotpReplayStore(maxCapacity: -1));
        var ex2 = Assert.Throws<ArgumentOutOfRangeException>(() => new InMemoryTotpReplayStore(maxCapacity: 10, pruneThreshold: 0));
        ex2.Message.Should().Contain("Prune threshold must be greater than zero.");
        Assert.Throws<ArgumentOutOfRangeException>(() => new InMemoryTotpReplayStore(maxCapacity: 10, pruneThreshold: -1));
    }

    [Fact]
    public void TryAdd_DuplicateKey_ReturnsFalse()
    {
        var store = new InMemoryTotpReplayStore();
        var expiresAt = DateTimeOffset.UtcNow.AddMinutes(5);

        store.TryAdd("key-1", expiresAt).Should().BeTrue();
        store.TryAdd("key-1", expiresAt).Should().BeFalse();
    }

    [Fact]
    public void TryAdd_AtMaxCapacity_WhenUnexpired_ReturnsFalse()
    {
        // Max capacity 2
        var store = new InMemoryTotpReplayStore(maxCapacity: 2, pruneThreshold: 1);
        var unexpired = DateTimeOffset.UtcNow.AddMinutes(5);

        store.TryAdd("key-1", unexpired).Should().BeTrue();
        store.TryAdd("key-2", unexpired).Should().BeTrue();

        // 3rd item should hit saturation, attempt prune, fail because unexpired, and return false
        store.TryAdd("key-3", unexpired).Should().BeFalse();
        store.ConsumedCodesCount.Should().Be(2);
    }

    [Fact]
    public void TryAdd_AtMaxCapacity_WhenExpiredPresent_PrunesAndAcceptsNew()
    {
        var store = new InMemoryTotpReplayStore(maxCapacity: 2, pruneThreshold: 1);
        var expired = DateTimeOffset.UtcNow.AddMinutes(-5);
        var unexpired = DateTimeOffset.UtcNow.AddMinutes(5);

        store.TryAdd("key-old", expired).Should().BeTrue();
        store.TryAdd("key-active", unexpired).Should().BeTrue();

        // Adding key-new hits saturation (count 2 == maxCapacity 2), triggers prune, key-old is removed, key-new is added
        store.TryAdd("key-new", unexpired).Should().BeTrue();
        store.ConsumedCodes.ContainsKey("key-old").Should().BeFalse();
        store.ConsumedCodes.ContainsKey("key-new").Should().BeTrue();
    }

    [Fact]
    public void TryAdd_ExceedsPruneThreshold_PrunesExpiredCodes()
    {
        var store = new InMemoryTotpReplayStore(maxCapacity: 100, pruneThreshold: 2);
        var expired = DateTimeOffset.UtcNow.AddMinutes(-1);
        var unexpired = DateTimeOffset.UtcNow.AddMinutes(5);

        store.TryAdd("expired-1", expired).Should().BeTrue();
        store.TryAdd("unexpired-2", unexpired).Should().BeTrue();
        // 3rd entry exceeds pruneThreshold (2)
        store.TryAdd("unexpired-3", unexpired).Should().BeTrue();

        store.ConsumedCodes.ContainsKey("expired-1").Should().BeFalse();
        store.ConsumedCodes.ContainsKey("unexpired-2").Should().BeTrue();
        store.ConsumedCodes.ContainsKey("unexpired-3").Should().BeTrue();
    }

    [Fact]
    public async Task TryAddAsync_CancelledToken_ReturnsCanceledTask()
    {
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        var store = new InMemoryTotpReplayStore();

        var task = store.TryAddAsync("key-1", DateTimeOffset.UtcNow.AddMinutes(5), cts.Token);
        task.IsCanceled.Should().BeTrue();
    }

    [Fact]
    public async Task TryAddAsync_ValidToken_CallsTryAdd()
    {
        var store = new InMemoryTotpReplayStore();
        var result = await store.TryAddAsync("key-async", DateTimeOffset.UtcNow.AddMinutes(5));
        result.Should().BeTrue();

        var duplicate = await store.TryAddAsync("key-async", DateTimeOffset.UtcNow.AddMinutes(5));
        duplicate.Should().BeFalse();
    }

    [Fact]
    public void TryAdd_ExactlyAtPruneThreshold_DoesNotPrune()
    {
        var store = new InMemoryTotpReplayStore(maxCapacity: 100, pruneThreshold: 2);
        var expired = DateTimeOffset.UtcNow.AddMinutes(-1);
        var unexpired = DateTimeOffset.UtcNow.AddMinutes(5);

        store.TryAdd("expired-1", expired).Should().BeTrue();
        store.TryAdd("unexpired-2", unexpired).Should().BeTrue();

        // Exactly at prune threshold (2), Count > pruneThreshold is false, expired-1 should NOT be pruned yet
        store.ConsumedCodes.ContainsKey("expired-1").Should().BeTrue();
    }

    [Fact]
    public void PruneExpiredCodes_ThrottlesWhenUnderCapacityWithinOneSecond()
    {
        var store = new InMemoryTotpReplayStore(maxCapacity: 10, pruneThreshold: 5);
        var now = DateTimeOffset.UtcNow;

        // Initial prune to set lastTicks
        store.PruneExpiredCodes(now);

        // Add expired entry
        store.TryAdd("key-exp", now.AddSeconds(-10)).Should().BeTrue();

        // Call prune within 500ms when Count < maxCapacity -> throttled (returns immediately)
        store.PruneExpiredCodes(now.AddMilliseconds(500));
        store.ConsumedCodes.ContainsKey("key-exp").Should().BeTrue();

        // Call prune after 1.1s -> throttle elapsed, pruned!
        store.PruneExpiredCodes(now.AddSeconds(1.1));
        store.ConsumedCodes.ContainsKey("key-exp").Should().BeFalse();
    }

    [Fact]
    public void PruneExpiredCodes_BypassesThrottleWhenAtMaxCapacity()
    {
        var store = new InMemoryTotpReplayStore(maxCapacity: 2, pruneThreshold: 1);
        var now = DateTimeOffset.UtcNow;

        store.PruneExpiredCodes(now);

        // Fill to max capacity with 1 expired and 1 unexpired
        store.TryAdd("key-exp", now.AddSeconds(-10)).Should().BeTrue();
        store.TryAdd("key-act", now.AddMinutes(5)).Should().BeTrue();

        // Even within 100ms, because Count == maxCapacity, throttle is bypassed and prune runs!
        store.PruneExpiredCodes(now.AddMilliseconds(100));
        store.ConsumedCodes.ContainsKey("key-exp").Should().BeFalse();
        store.ConsumedCodes.ContainsKey("key-act").Should().BeTrue();
    }

    [Fact]
    public void PruneExpiredCodes_ExactExpiryTimestamp_IsNotPruned()
    {
        var store = new InMemoryTotpReplayStore(maxCapacity: 10, pruneThreshold: 5);
        var now = DateTimeOffset.UtcNow;

        store.TryAdd("key-exact", now).Should().BeTrue();
        store.TryAdd("key-strictly-past", now.AddTicks(-1)).Should().BeTrue();

        store.PruneExpiredCodes(now);

        // key-exact expiresAt == now, so kvp.Value < now is false -> NOT pruned
        store.ConsumedCodes.ContainsKey("key-exact").Should().BeTrue();
        // key-strictly-past expiresAt < now -> pruned
        store.ConsumedCodes.ContainsKey("key-strictly-past").Should().BeFalse();
    }
}
