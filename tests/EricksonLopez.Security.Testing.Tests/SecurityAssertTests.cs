// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Testing.Tests;

using System;
using AwesomeAssertions;
using EricksonLopez.Security.Memory;
using EricksonLopez.Security.Testing.Assertions;
using Xunit;

public sealed class SecurityAssertTests
{
    private sealed class RedactedDummy
    {
        public override string ToString() => "[REDACTED]";
    }

    private sealed class CustomRedactedDummy
    {
        public override string ToString() => "***SECRET***";
    }

    private sealed class LeakingDummy
    {
        public override string ToString() => "plaintext_password_123";
    }

    private sealed class NullToStringDummy
    {
        public override string? ToString() => null;
    }

    [Fact]
    public void IsRedacted_WhenRedacted_DoesNotThrow()
    {
        var dummy = new RedactedDummy();
        var act = () => SecurityAssert.IsRedacted(dummy);
        act.Should().NotThrow();
    }

    [Fact]
    public void IsRedacted_WithCustomMask_DoesNotThrow()
    {
        var dummy = new CustomRedactedDummy();
        var act = () => SecurityAssert.IsRedacted(dummy, "***SECRET***");
        act.Should().NotThrow();
    }

    [Fact]
    public void IsRedacted_WhenLeaking_ThrowsInvalidOperationException()
    {
        var dummy = new LeakingDummy();
        var act = () => SecurityAssert.IsRedacted(dummy);
        act.Should().Throw<InvalidOperationException>()
            .WithMessage("*failed redaction check*");
    }

    [Fact]
    public void IsRedacted_WhenNullToString_ThrowsInvalidOperationException()
    {
        var dummy = new NullToStringDummy();
        var act = () => SecurityAssert.IsRedacted(dummy);
        act.Should().Throw<InvalidOperationException>();
    }

    [Fact]
    public void IsRedacted_WhenObjectIsNull_ThrowsArgumentNullException()
    {
        var act = () => SecurityAssert.IsRedacted(null!);
        act.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void AreConstantTimeEqual_WhenEqual_DoesNotThrow()
    {
        byte[] a = [1, 2, 3, 4];
        byte[] b = [1, 2, 3, 4];

        var act = () => SecurityAssert.AreConstantTimeEqual(a, b);
        act.Should().NotThrow();
    }

    [Fact]
    public void AreConstantTimeEqual_WhenDifferent_ThrowsInvalidOperationException()
    {
        byte[] a = [1, 2, 3, 4];
        byte[] b = [1, 2, 3, 5];

        var act = () => SecurityAssert.AreConstantTimeEqual(a, b);
        act.Should().Throw<InvalidOperationException>()
            .WithMessage("*constant-time*");
    }

    [Fact]
    public void AreConstantTimeEqual_WhenDifferentLengths_ThrowsInvalidOperationException()
    {
        byte[] a = [1, 2, 3];
        byte[] b = [1, 2, 3, 4];

        var act = () => SecurityAssert.AreConstantTimeEqual(a, b);
        act.Should().Throw<InvalidOperationException>();
    }

    [Fact]
    public void IsDisposed_WhenDisposed_DoesNotThrow()
    {
        var buffer = new SecretBuffer(16);
        buffer.Dispose();

        var act = () => SecurityAssert.IsDisposed(buffer);
        act.Should().NotThrow();
    }

    [Fact]
    public void IsDisposed_WhenNotDisposed_ThrowsInvalidOperationException()
    {
        using var buffer = new SecretBuffer(16);

        var act = () => SecurityAssert.IsDisposed(buffer);
        act.Should().Throw<InvalidOperationException>()
            .WithMessage("*disposed*");
    }

    [Fact]
    public void IsDisposed_WhenBufferIsNull_ThrowsArgumentNullException()
    {
        var act = () => SecurityAssert.IsDisposed(null!);
        act.Should().Throw<ArgumentNullException>();
    }
}
