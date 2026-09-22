// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Tests.KeyManagement;

using System;
using System.Threading;
using System.Threading.Tasks;
using AwesomeAssertions;
using EricksonLopez.Security.Abstractions.KeyManagement;
using EricksonLopez.Security.Abstractions.Primitives;
using EricksonLopez.Security.KeyManagement;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

public sealed class DelegateKeyRevocationNotifierTests
{
    [Fact]
    public async Task NotifyRevokedAsync_InvokesPublishDelegate_AndNotifiesLocalSubscribers()
    {
        // Arrange
        var publishedKeyId = default(KeyIdentifier);
        var publishedVersion = default(KeyVersion);
        var publishedPurpose = default(KeyPurpose);
        var delegateInvoked = false;

        var notifier = new DelegateKeyRevocationNotifier((keyId, version, purpose, _) =>
        {
            publishedKeyId = keyId;
            publishedVersion = version;
            publishedPurpose = purpose;
            delegateInvoked = true;
            return ValueTask.CompletedTask;
        });

        var localReceived = false;
        using var subscription = notifier.Subscribe((k, v, p) =>
        {
            localReceived = true;
        });

        var testKeyId = new KeyIdentifier("key-distributed-test");
        var testVersion = new KeyVersion(1);
        var testPurpose = KeyPurpose.Encryption;

        // Act
        await notifier.NotifyRevokedAsync(testKeyId, testVersion, testPurpose);

        // Assert
        delegateInvoked.Should().BeTrue();
        publishedKeyId.Should().Be(testKeyId);
        publishedVersion.Should().Be(testVersion);
        publishedPurpose.Should().Be(testPurpose);
        localReceived.Should().BeTrue();
    }

    [Fact]
    public async Task ReceiveRemoteRevocationAsync_NotifiesLocalSubscribers_WithoutCallingPublishDelegate()
    {
        // Arrange
        var delegateCalled = false;
        var notifier = new DelegateKeyRevocationNotifier((_, _, _, _) =>
        {
            delegateCalled = true;
            return ValueTask.CompletedTask;
        });

        var localKeyId = default(KeyIdentifier);
        var localReceived = false;
        using var subscription = notifier.Subscribe((k, _, _) =>
        {
            localKeyId = k;
            localReceived = true;
        });

        var testKeyId = new KeyIdentifier("key-remote-received");
        var testVersion = new KeyVersion(2);
        var testPurpose = KeyPurpose.Signing;

        // Act: Simulated message arriving from Redis or RabbitMQ
        await notifier.ReceiveRemoteRevocationAsync(testKeyId, testVersion, testPurpose);

        // Assert: Local subscriber informed, but outbound publish NOT called (prevent loop)
        localReceived.Should().BeTrue();
        localKeyId.Should().Be(testKeyId);
        delegateCalled.Should().BeFalse();
    }

    [Fact]
    public void Constructor_WithNullHandler_ThrowsArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => new DelegateKeyRevocationNotifier(null!));
    }

    [Fact]
    public void Subscribe_WithNullHandler_ThrowsArgumentNullException()
    {
        // Arrange
        var notifier = new DelegateKeyRevocationNotifier((_, _, _, _) => ValueTask.CompletedTask);

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => notifier.Subscribe(null!));
    }

    [Fact]
    public async Task Unsubscribe_DisposesCorrectly_AndStopsReceivingEvents()
    {
        // Arrange
        var notifier = new DelegateKeyRevocationNotifier((_, _, _, _) => ValueTask.CompletedTask);
        var eventCount = 0;

        var sub = notifier.Subscribe((_, _, _) => eventCount++);

        await notifier.ReceiveRemoteRevocationAsync(new KeyIdentifier("k1"), new KeyVersion(1), KeyPurpose.Encryption);
        eventCount.Should().Be(1);

        // Unsubscribe
        sub.Dispose();

        await notifier.ReceiveRemoteRevocationAsync(new KeyIdentifier("k2"), new KeyVersion(1), KeyPurpose.Encryption);
        eventCount.Should().Be(1);
    }

    [Fact]
    public async Task AddDistributedKeyRevocationNotifier_RegistersServiceCorrectlyInContainer()
    {
        // Arrange
        var services = new ServiceCollection();
        var wasPublished = false;

        services.AddKeyManagement();
        services.AddDistributedKeyRevocationNotifier((_, _, _, _) =>
        {
            wasPublished = true;
            return ValueTask.CompletedTask;
        });

        var sp = services.BuildServiceProvider();

        // Act
        var notifier = sp.GetRequiredService<IKeyRevocationNotifier>();
        var delegateNotifier = sp.GetRequiredService<DelegateKeyRevocationNotifier>();

        notifier.Should().BeSameAs(delegateNotifier);

        await notifier.NotifyRevokedAsync(new KeyIdentifier("key-di-test"), new KeyVersion(1), KeyPurpose.TokenProtection);

        // Assert
        wasPublished.Should().BeTrue();
    }
}
