// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Tests.Memory;

using System;
using AwesomeAssertions;
using EricksonLopez.Security.Memory;
using EricksonLopez.Security.Testing.Assertions;
using Xunit;

public sealed class SecretBufferTests
{
    [Fact]
    public void SecretBuffer_Constructor_ValidatesArguments()
    {
        var actZero = () => new SecretBuffer(0);
        actZero.Should().Throw<ArgumentOutOfRangeException>()
            .WithParameterName("length")
            .WithMessage("*Secret buffer length must be greater than zero*");

        var actNegative = () => new SecretBuffer(-5);
        actNegative.Should().Throw<ArgumentOutOfRangeException>()
            .WithParameterName("length")
            .WithMessage("*Secret buffer length must be greater than zero*");

        // Pollute array pool buffer before renting to verify that Constructor executes ZeroMemory
        var dirtyBuffer = System.Buffers.ArrayPool<byte>.Shared.Rent(64);
        Array.Fill(dirtyBuffer, (byte)0xEE);
        System.Buffers.ArrayPool<byte>.Shared.Return(dirtyBuffer);

        using var sanitizedBuffer = new SecretBuffer(64);
        sanitizedBuffer.Span.ToArray().Should().AllSatisfy(b => b.Should().Be(0));

        // Verify newly constructed buffer is clean/zeroed out
        var cleanBuffer = new SecretBuffer(16);
        cleanBuffer.Length.Should().Be(16);
        cleanBuffer.Span.SequenceEqual(new byte[16]).Should().BeTrue();
        cleanBuffer.Dispose();
        cleanBuffer.IsDisposed.Should().BeTrue();
    }

    [Fact]
    public void SecretBuffer_FromSpan_ValidatesAndCopiesContent()
    {
        var actEmpty = () => SecretBuffer.FromSpan(ReadOnlySpan<byte>.Empty);
        actEmpty.Should().Throw<ArgumentException>()
            .WithParameterName("source")
            .WithMessage("*Source span cannot be empty*");

        byte[] expected = [1, 2, 3, 4, 5, 6, 7, 8];
        using var buffer = SecretBuffer.FromSpan(expected);

        buffer.Length.Should().Be(expected.Length);
        buffer.Span.SequenceEqual(expected).Should().BeTrue();
        buffer.IsDisposed.Should().BeFalse();
    }

    [Fact]
    public void SecretBuffer_CreateRandom_GeneratesNonZeroBytes()
    {
        using var buffer = SecretBuffer.CreateRandom(32);

        buffer.Length.Should().Be(32);
        buffer.Span.SequenceEqual(new byte[32]).Should().BeFalse();
    }

    [Fact]
    public void SecretBuffer_GetWritableSpan_AllowsModification()
    {
        using var buffer = new SecretBuffer(4);
        var span = buffer.GetWritableSpan();
        span[0] = 0xAA;
        span[1] = 0xBB;
        span[2] = 0xCC;
        span[3] = 0xDD;

        buffer.Span.SequenceEqual(new byte[] { 0xAA, 0xBB, 0xCC, 0xDD }).Should().BeTrue();
    }

    [Fact]
    public void SecretBuffer_FixedTimeEquals_MatchesExpected()
    {
        byte[] data = [10, 20, 30, 40];
        byte[] other = [10, 20, 30, 40];
        byte[] differentSameLength = [10, 20, 30, 41];
        byte[] differentLength = [10, 20, 30];

        using var buffer = SecretBuffer.FromSpan(data);

        buffer.FixedTimeEquals(other).Should().BeTrue();
        buffer.FixedTimeEquals(differentSameLength).Should().BeFalse();
        buffer.FixedTimeEquals(differentLength).Should().BeFalse();
    }

    [Fact]
    public void SecretBuffer_Dispose_WipesMemoryAndThrowsOnSubsequentAccess()
    {
        var buffer = SecretBuffer.CreateRandom(16);
        buffer.IsDisposed.Should().BeFalse();

        // Capture underlying rented buffer via internal diagnostic property before dispose to verify memory scrubbing
        var rawArray = buffer.DangerousRentedBufferForTesting;
        rawArray.Should().NotBeNull();
        rawArray.Should().Contain(b => b != 0);

        buffer.Dispose();
        SecurityAssert.IsDisposed(buffer);

        // Verify that CryptographicOperations.ZeroMemory was executed on the array
        rawArray.Should().AllSatisfy(b => b.Should().Be(0));

        // Idempotent dispose
        buffer.Dispose();
        SecurityAssert.IsDisposed(buffer);

        Action actLength = () => _ = buffer.Length;
        actLength.Should().Throw<ObjectDisposedException>();

        Action actSpan = () => _ = buffer.Span;
        actSpan.Should().Throw<ObjectDisposedException>();

        Action actWritableSpan = () => _ = buffer.GetWritableSpan();
        actWritableSpan.Should().Throw<ObjectDisposedException>();

        Action actFixedTimeEquals = () => buffer.FixedTimeEquals([1, 2, 3]);
        var exFixedTime = actFixedTimeEquals.Should().Throw<ObjectDisposedException>().Which;
        exFixedTime.StackTrace.Should().NotContain("get_Span");
    }

    [Fact]
    public void SecretBuffer_ToString_RedactsContent()
    {
        using var buffer = SecretBuffer.FromSpan(new byte[] { 1, 2, 3 });
        buffer.ToString().Should().Be("[REDACTED SECRET BUFFER]");
        SecurityAssert.IsRedacted(buffer);
    }

    [Fact]
    public async Task SecretBuffer_ConcurrentDisposeAndSpanAccess_NeverThrowsNullReferenceException()
    {
        // FINDING-NEW-04: Concurrent disposal must only throw ObjectDisposedException, never NullReferenceException
        for (int run = 0; run < 100; run++)
        {
            var buffer = SecretBuffer.CreateRandom(64);
            var exceptions = new System.Collections.Concurrent.ConcurrentBag<Exception>();

            var barrier = new System.Threading.Barrier(2);

            var readTask = Task.Run(() =>
            {
                barrier.SignalAndWait();
                try
                {
                    for (int i = 0; i < 500; i++)
                    {
                        var span = buffer.Span;
                        _ = span.Length;
                    }
                }
                catch (Exception ex)
                {
                    exceptions.Add(ex);
                }
            });

            var disposeTask = Task.Run(() =>
            {
                barrier.SignalAndWait();
                try
                {
                    buffer.Dispose();
                }
                catch (Exception ex)
                {
                    exceptions.Add(ex);
                }
            });

            await Task.WhenAll(readTask, disposeTask);

            foreach (var ex in exceptions)
            {
                ex.Should().BeOfType<ObjectDisposedException>("Concurrent access should only throw ObjectDisposedException");
            }
        }
    }

    [Fact]
    public void SecretBuffer_FromUtf8_ValidatesAndEncodesCorrectly()
    {
        var actEmpty = () => SecretBuffer.FromUtf8(ReadOnlySpan<char>.Empty);
        actEmpty.Should().Throw<ArgumentException>()
            .WithParameterName("chars")
            .WithMessage("*Source characters cannot be empty*");

        using var buffer = SecretBuffer.FromUtf8("SensitiveSecret123".AsSpan());
        buffer.Length.Should().Be(18);
        System.Text.Encoding.UTF8.GetString(buffer.Span).Should().Be("SensitiveSecret123");
    }
}

