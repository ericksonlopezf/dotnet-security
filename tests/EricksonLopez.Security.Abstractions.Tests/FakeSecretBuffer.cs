// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Abstractions.Tests;

using System;
using EricksonLopez.Security.Abstractions.Primitives;

public sealed class FakeSecretBuffer : ISecretBuffer
{
    private readonly byte[] _buffer;
    private bool _isDisposed;
    public int DisposeCount { get; private set; }
    public bool ThrowOnAccessAfterDispose { get; set; } = true;

    public FakeSecretBuffer(byte[] buffer)
    {
        _buffer = (byte[])buffer.Clone();
    }

    public int Length => _buffer.Length;

    public bool IsDisposed => _isDisposed;

    public ReadOnlySpan<byte> Span
    {
        get
        {
            ObjectDisposedException.ThrowIf(_isDisposed && ThrowOnAccessAfterDispose, this);
            return _buffer;
        }
    }

    public ReadOnlyMemory<byte> Memory
    {
        get
        {
            ObjectDisposedException.ThrowIf(_isDisposed && ThrowOnAccessAfterDispose, this);
            return _buffer;
        }
    }

    public void Dispose()
    {
        DisposeCount++;
        if (!_isDisposed)
        {
            Array.Clear(_buffer, 0, _buffer.Length);
            _isDisposed = true;
        }
    }
}
