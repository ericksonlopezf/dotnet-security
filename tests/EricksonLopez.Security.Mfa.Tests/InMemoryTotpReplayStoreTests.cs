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
        Assert.Throws<ArgumentOutOfRangeException>(() => new InMemoryTotpReplayStore(maxCapacity: 0));
        Assert.Throws<ArgumentOutOfRangeException>(() => new InMemoryTotpReplayStore(maxCapacity: -1));
        Assert.Throws<ArgumentOutOfRangeException>(() => new InMemoryTotpReplayStore(maxCapacity: 10, pruneThreshold: 0));
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
}
