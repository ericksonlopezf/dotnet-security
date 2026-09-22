// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Testing.Tests;

using System;
using AwesomeAssertions;
using EricksonLopez.Security.Testing.Logging;
using Microsoft.Extensions.Logging;
using Xunit;

public sealed class FakeLoggerTests
{
    private sealed class DummyService { }

    [Fact]
    public void Log_CapturesMessages_AndSupportsFilterHelpers()
    {
        var logger = new FakeLogger<DummyService>();

        logger.IsEnabled(LogLevel.Information).Should().BeTrue();
        logger.BeginScope("state").Should().BeNull();

        logger.LogInformation("Service started successfully.");
        logger.LogWarning("Potential latency issue detected.");
        logger.LogError(new InvalidOperationException("Fatal error"), "Operation failed.");

        logger.Count.Should().Be(3);
        logger.Messages.Should().HaveCount(3);
        logger.Entries.Should().HaveCount(3);

        logger.HasMessage("started").Should().BeTrue();
        logger.HasMessage("non-existent").Should().BeFalse();

        logger.HasWarning("latency").Should().BeTrue();
        logger.HasWarning("started").Should().BeFalse();

        logger.HasError("Operation failed").Should().BeTrue();
        logger.HasError("latency").Should().BeFalse();

        logger.HasMessage(LogLevel.Information, "started").Should().BeTrue();
        logger.HasMessage(LogLevel.Error, "started").Should().BeFalse();

        var errorEntry = logger.Entries[2];
        errorEntry.LogLevel.Should().Be(LogLevel.Error);
        errorEntry.Exception.Should().BeOfType<InvalidOperationException>();

        logger.Clear();
        logger.Count.Should().Be(0);
        logger.Messages.Should().BeEmpty();
    }

    [Fact]
    public void Log_RespectsMinimumLogLevel()
    {
        var logger = new FakeLogger<DummyService>(minLevel: LogLevel.Warning);

        logger.IsEnabled(LogLevel.Information).Should().BeFalse();
        logger.IsEnabled(LogLevel.Warning).Should().BeTrue();

        logger.LogInformation("This should be ignored.");
        logger.LogWarning("This should be captured.");

        logger.Count.Should().Be(1);
        logger.HasWarning("captured").Should().BeTrue();
        logger.HasMessage("ignored").Should().BeFalse();
    }

    [Fact]
    public void Validation_ThrowsOnNullArguments()
    {
        var logger = new FakeLogger<DummyService>();

        var act1 = () => logger.HasMessage(null!);
        act1.Should().Throw<ArgumentNullException>();

        var act2 = () => logger.HasMessage(LogLevel.Information, null!);
        act2.Should().Throw<ArgumentNullException>();

        var act3 = () => logger.Log(LogLevel.Information, default, "state", null, null!);
        act3.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void FakeLogRecord_ExposesAllProperties()
    {
        var ex = new InvalidOperationException("Test fault");
        var eventId = new EventId(101, "SecurityAudit");
        var record = new FakeLogRecord(LogLevel.Warning, eventId, "CustomState", ex, "Audit message");

        record.LogLevel.Should().Be(LogLevel.Warning);
        record.EventId.Should().Be(eventId);
        record.EventId.Id.Should().Be(101);
        record.EventId.Name.Should().Be("SecurityAudit");
        record.State.Should().Be("CustomState");
        record.Exception.Should().BeSameAs(ex);
        record.Message.Should().Be("Audit message");

        var copy = record with { Message = "Modified" };
        copy.Message.Should().Be("Modified");
        copy.LogLevel.Should().Be(LogLevel.Warning);
    }
}
