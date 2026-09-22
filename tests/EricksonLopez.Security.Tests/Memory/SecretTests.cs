// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Tests.Memory;

using System;
using EricksonLopez.Security.Memory;
using EricksonLopez.Security.Testing.Assertions;
using Xunit;

public sealed class SecretTests
{
    private sealed class TrackingDisposable : IDisposable
    {
        public int DisposeCount { get; private set; }

        public void Dispose()
        {
            DisposeCount++;
            if (DisposeCount > 1)
            {
                throw new InvalidOperationException("Double dispose detected!");
            }
        }
    }

    [Fact]
    public void Secret_NullValue_ThrowsArgumentNullException()
    {
        var ex = Assert.Throws<ArgumentNullException>(() => new Secret<string>(null!));
        Assert.Equal("value", ex.ParamName);
    }

    [Fact]
    public void Secret_StringValue_ProvidesAccessAndRedactsToString()
    {
        var password = "super-secret-123";
        using var secret = new Secret<string>(password);

        Assert.Equal(password, secret.Value);
        Assert.Equal(password.Length, secret.Length);
        Assert.False(secret.IsDisposed);
        Assert.Equal("[REDACTED SECRET]", secret.ToString());
        SecurityAssert.IsRedacted(secret);
    }

    [Fact]
    public void Secret_LengthEvaluation_HandlesAllTypes()
    {
        // String
        using var secStr = new Secret<string>("hello");
        Assert.Equal(5, secStr.Length);

        // Byte array
        using var secBytes = new Secret<byte[]>([1, 2, 3, 4]);
        Assert.Equal(4, secBytes.Length);

        // ISecret (nested)
        using var innerBuffer = SecretBuffer.FromSpan([10, 20, 30]);
        using var secNested = new Secret<SecretBuffer>(innerBuffer);
        Assert.Equal(3, secNested.Length);

        // Value type / other objects
        using var secInt = new Secret<int>(42);
        Assert.Equal(1, secInt.Length);

        using var secObj = new Secret<object>(new object());
        Assert.Equal(1, secObj.Length);
    }

    [Fact]
    public void Secret_Dispose_ClearsValueAndSetsIsDisposed()
    {
        var secret = new Secret<string>("secret-to-dispose");

        secret.Dispose();

        Assert.True(secret.IsDisposed);
        Assert.Throws<ObjectDisposedException>(() => _ = secret.Value);
        Assert.Throws<ObjectDisposedException>(() => _ = secret.Length);

        // Idempotent dispose
        secret.Dispose();
        Assert.True(secret.IsDisposed);
    }

    [Fact]
    public void Secret_ByteArray_ZeroesMemoryOnDispose()
    {
        byte[] sensitiveBytes = [0xFF, 0xEE, 0xDD, 0xCC];
        var secret = new Secret<byte[]>(sensitiveBytes);

        secret.Dispose();

        Assert.True(sensitiveBytes.AsSpan().SequenceEqual(new byte[4]));
        Assert.True(secret.IsDisposed);
    }

    [Fact]
    public void Secret_DisposableInnerValue_CallsDisposeOnce()
    {
        var tracking = new TrackingDisposable();
        var secret = new Secret<TrackingDisposable>(tracking);

        secret.Dispose();
        Assert.True(secret.IsDisposed);
        Assert.Equal(1, tracking.DisposeCount);

        // Second dispose should be a no-op and not invoke inner dispose again
        secret.Dispose();
        Assert.True(secret.IsDisposed);
        Assert.Equal(1, tracking.DisposeCount);
    }

    [Fact]
    public void Secret_DisposeCore_FinalizerAndExplicitDispose_ScrubsMemory()
    {
        byte[] bytes = [1, 2, 3, 4];
        var secret = new Secret<byte[]>(bytes);
        secret.DisposeCore();
        Assert.True(secret.IsDisposed);
        Assert.All(bytes, b => Assert.Equal(0, b));

        // Calling DisposeCore when already disposed returns immediately
        secret.DisposeCore();
        Assert.True(secret.IsDisposed);
    }

    [Fact]
    public void Secret_CharArray_ZeroesMemoryOnDispose()
    {
        char[] sensitiveChars = ['s', 'e', 'c', 'r', 'e', 't'];
        var secret = new Secret<char[]>(sensitiveChars);

        secret.Dispose();

        Assert.All(sensitiveChars, c => Assert.Equal('\0', c));
        Assert.True(secret.IsDisposed);
    }
}
