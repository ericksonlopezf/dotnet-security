// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Abstractions.Primitives;

/// <summary>
/// Defines a contract for a strongly-typed generic secret container that provides access to the underlying secret data.
/// </summary>
/// <typeparam name="T">Type of the underlying secret value.</typeparam>
public interface ISecret<out T> : ISecret
{
    /// <summary>
    /// Gets the protected secret value.
    /// </summary>
    /// <exception cref="System.ObjectDisposedException">The secret container has been disposed</exception>
    T Value { get; }
}
