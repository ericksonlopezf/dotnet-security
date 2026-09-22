// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Abstractions.Primitives;

using System;

/// <summary>
/// Defines a contract for strongly-typed, memory-safe secrets that prevent accidental leakage
/// and support controlled access to underlying secret data.
/// </summary>
public interface ISecret : IDisposable
{
    /// <summary>
    /// Gets the length of the secret material in bytes or characters.
    /// </summary>
    int Length { get; }

    /// <summary>
    /// Gets a value indicating whether this secret container has been disposed and its memory scrubbed.
    /// </summary>
    bool IsDisposed { get; }
}
