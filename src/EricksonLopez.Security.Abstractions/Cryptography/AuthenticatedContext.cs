// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Abstractions.Cryptography;

using System;
using System.Security.Cryptography;

/// <summary>
/// Provides a strongly-typed cryptographic context used as Authenticated Associated Data (AAD)
/// in Authenticated Encryption with Associated Data (AEAD) schemes.
/// </summary>
public readonly struct AuthenticatedContext : IEquatable<AuthenticatedContext>
{
    private readonly byte[]? _bytes;

    private AuthenticatedContext(byte[] bytes)
    {
        _bytes = bytes;
    }

    /// <summary>
    /// Gets an empty authenticated context.
    /// </summary>
    public static AuthenticatedContext Empty => default;

    /// <summary>
    /// Creates an authenticated context bound to a specific tenant identifier.
    /// </summary>
    /// <param name="tenantId">The unique identifier of the tenant.</param>
    /// <returns>A strongly-typed authenticated context.</returns>
    /// <exception cref="ArgumentException"><paramref name="tenantId"/> is <see langword="null"/> or whitespace</exception>
    public static AuthenticatedContext ForTenant(string tenantId)
    {
        if (string.IsNullOrWhiteSpace(tenantId))
        {
            throw new ArgumentException("Tenant ID cannot be null or whitespace.", nameof(tenantId));
        }

        return new AuthenticatedContext(System.Text.Encoding.UTF8.GetBytes($"tenant:{tenantId}"));
    }

    /// <summary>
    /// Creates an authenticated context from a raw byte span.
    /// </summary>
    /// <param name="contextBytes">The raw bytes comprising the context.</param>
    /// <returns>A strongly-typed authenticated context.</returns>
    public static AuthenticatedContext FromBytes(ReadOnlySpan<byte> contextBytes)
    {
        if (contextBytes.IsEmpty)
        {
            return Empty;
        }

        return new AuthenticatedContext(contextBytes.ToArray());
    }

    /// <summary>
    /// Gets the read-only span representation of the authenticated context bytes.
    /// </summary>
    public ReadOnlySpan<byte> Span => _bytes ?? ReadOnlySpan<byte>.Empty;

    /// <summary>
    /// Gets a value indicating whether the authenticated context is empty.
    /// </summary>
    public bool IsEmpty => _bytes == null || _bytes.Length == 0;

    /// <inheritdoc/>
    public bool Equals(AuthenticatedContext other)
    {
        if (IsEmpty && other.IsEmpty)
        {
            return true;
        }

        return CryptographicOperations.FixedTimeEquals(Span, other.Span);
    }

    /// <inheritdoc/>
    public override bool Equals(object? obj) => obj is AuthenticatedContext other && Equals(other);

    /// <inheritdoc/>
    public override int GetHashCode()
    {
        if (IsEmpty)
        {
            return 0;
        }

        var hash = new HashCode();
        hash.AddBytes(Span);
        return hash.ToHashCode();
    }

    /// <summary>
    /// Determines whether two <see cref="AuthenticatedContext"/> instances are equal.
    /// </summary>
    /// <param name="left">The first context to compare.</param>
    /// <param name="right">The second context to compare.</param>
    /// <returns><see langword="true"/> if both instances are equal; otherwise, <see langword="false"/>.</returns>
    public static bool operator ==(AuthenticatedContext left, AuthenticatedContext right) => left.Equals(right);

    /// <summary>
    /// Determines whether two <see cref="AuthenticatedContext"/> instances are not equal.
    /// </summary>
    /// <param name="left">The first context to compare.</param>
    /// <param name="right">The second context to compare.</param>
    /// <returns><see langword="true"/> if instances are not equal; otherwise, <see langword="false"/>.</returns>
    public static bool operator !=(AuthenticatedContext left, AuthenticatedContext right) => !(left == right);
}
