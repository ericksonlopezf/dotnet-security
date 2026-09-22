// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Testing.Assertions;

using System;
using System.Security.Cryptography;
using EricksonLopez.Security.Abstractions.Primitives;

/// <summary>
/// Provides security verification assertions for testing cryptographic boundaries, redaction, and memory wiping.
/// </summary>
public static class SecurityAssert
{
    /// <summary>
    /// Verifies that a sensitive object correctly redacts its value in <see cref="object.ToString"/>.
    /// </summary>
    /// <param name="sensitiveObject">The sensitive object to evaluate.</param>
    /// <param name="expectedMask">The expected redaction substring (defaults to "REDACTED").</param>
    /// <exception cref="ArgumentNullException"><paramref name="sensitiveObject"/> is <see langword="null"/></exception>
    /// <exception cref="InvalidOperationException"><paramref name="sensitiveObject"/> failed the redaction check</exception>
    public static void IsRedacted(object sensitiveObject, string expectedMask = "REDACTED")
    {
        ArgumentNullException.ThrowIfNull(sensitiveObject);

        var stringRep = sensitiveObject.ToString();
        if (string.IsNullOrEmpty(stringRep) || !stringRep.Contains(expectedMask, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException($"Object '{sensitiveObject.GetType().Name}' failed redaction check. Output was: '{stringRep}'.");
        }
    }

    /// <summary>
    /// Verifies that two byte spans are equal in constant time.
    /// </summary>
    /// <param name="expected">The expected byte span.</param>
    /// <param name="actual">The actual byte span.</param>
    /// <exception cref="InvalidOperationException">The byte spans are not equal in constant-time comparison</exception>
    public static void AreConstantTimeEqual(ReadOnlySpan<byte> expected, ReadOnlySpan<byte> actual)
    {
        if (!CryptographicOperations.FixedTimeEquals(expected, actual))
        {
            throw new InvalidOperationException("Byte buffers do not match in constant-time comparison.");
        }
    }

    /// <summary>
    /// Verifies that an <see cref="ISecretBuffer"/> is wiped and disposed.
    /// </summary>
    /// <param name="buffer">The secret buffer to verify.</param>
    /// <exception cref="ArgumentNullException"><paramref name="buffer"/> is <see langword="null"/></exception>
    /// <exception cref="InvalidOperationException"><paramref name="buffer"/> has not been disposed</exception>
    public static void IsDisposed(ISecretBuffer buffer)
    {
        ArgumentNullException.ThrowIfNull(buffer);

        if (!buffer.IsDisposed)
        {
            throw new InvalidOperationException("Expected secret buffer to be disposed.");
        }
    }
}
