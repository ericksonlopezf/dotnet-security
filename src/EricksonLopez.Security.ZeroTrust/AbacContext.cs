// Copyright © Erickson Lopez. MIT License.
using System;
using System.Collections.Generic;

namespace EricksonLopez.Security.ZeroTrust;

/// <summary>
/// Encapsulates the multi-dimensional contextual attributes (Subject, Resource, Action, Environment)
/// required to evaluate ABAC security policies.
/// </summary>
public sealed class AbacContext
{
    private readonly Dictionary<(string Category, string Name), object> _attributes = new();

    /// <summary>
    /// Adds or updates an attribute in the specified category.
    /// </summary>
    /// <param name="category">The attribute category (e.g., Subject, Resource, Action, Environment).</param>
    /// <param name="name">The name of the attribute.</param>
    /// <param name="value">The attribute value.</param>
    /// <returns>This context instance for fluent chaining.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="category"/>, <paramref name="name"/>, or <paramref name="value"/> is <see langword="null"/></exception>
    public AbacContext Set(string category, string name, object value)
    {
        ArgumentNullException.ThrowIfNull(category);
        ArgumentNullException.ThrowIfNull(name);
        ArgumentNullException.ThrowIfNull(value);

        _attributes[(category, name)] = value;
        return this;
    }

    /// <summary>
    /// Sets a Subject attribute on this evaluation context.
    /// </summary>
    /// <param name="name">The name of the subject attribute.</param>
    /// <param name="value">The value of the subject attribute.</param>
    /// <returns>This context instance for fluent chaining.</returns>
    public AbacContext WithSubject(string name, object value) => Set(AbacAttributeCategory.Subject, name, value);

    /// <summary>
    /// Sets a Resource attribute on this evaluation context.
    /// </summary>
    /// <param name="name">The name of the resource attribute.</param>
    /// <param name="value">The value of the resource attribute.</param>
    /// <returns>This context instance for fluent chaining.</returns>
    public AbacContext WithResource(string name, object value) => Set(AbacAttributeCategory.Resource, name, value);

    /// <summary>
    /// Sets the Action name attribute on this evaluation context.
    /// </summary>
    /// <param name="actionName">The name of the requested action.</param>
    /// <returns>This context instance for fluent chaining.</returns>
    public AbacContext WithAction(string actionName) => Set(AbacAttributeCategory.Action, "Name", actionName);

    /// <summary>
    /// Sets an Environment attribute on this evaluation context.
    /// </summary>
    /// <param name="name">The name of the environment attribute.</param>
    /// <param name="value">The value of the environment attribute.</param>
    /// <returns>This context instance for fluent chaining.</returns>
    public AbacContext WithEnvironment(string name, object value) => Set(AbacAttributeCategory.Environment, name, value);

    /// <summary>
    /// Retrieves a strongly-typed attribute value, throwing an exception if not found or incompatible.
    /// </summary>
    /// <typeparam name="T">The expected type of the attribute.</typeparam>
    /// <param name="category">The category name.</param>
    /// <param name="name">The attribute name.</param>
    /// <returns>The attribute value cast to <typeparamref name="T"/>.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="category"/> or <paramref name="name"/> is <see langword="null"/></exception>
    /// <exception cref="KeyNotFoundException">The requested attribute was not found in the context</exception>
    public T Get<T>(string category, string name)
    {
        if (TryGet<T>(category, name, out var value) && value is not null)
        {
            return value;
        }

        throw new KeyNotFoundException($"ABAC attribute '{category}.{name}' of type {typeof(T).Name} was not found in the context.");
    }

    /// <summary>
    /// Attempts to retrieve a strongly-typed attribute value.
    /// </summary>
    /// <typeparam name="T">The expected type of the attribute.</typeparam>
    /// <param name="category">The category name.</param>
    /// <param name="name">The attribute name.</param>
    /// <param name="value">When the operation completes, contains the value associated with the specified attribute if found; otherwise, the default value.</param>
    /// <returns><see langword="true"/> if the attribute was found and matches type; otherwise, <see langword="false"/>.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="category"/> or <paramref name="name"/> is <see langword="null"/></exception>
    public bool TryGet<T>(string category, string name, out T? value)
    {
        ArgumentNullException.ThrowIfNull(category);
        ArgumentNullException.ThrowIfNull(name);

        if (_attributes.TryGetValue((category, name), out var rawValue) && rawValue is T typedValue)
        {
            value = typedValue;
            return true;
        }

        value = default;
        return false;
    }

    /// <summary>
    /// Determines whether an attribute exists in this context.
    /// </summary>
    /// <param name="category">The category of the attribute to locate.</param>
    /// <param name="name">The name of the attribute to locate.</param>
    /// <returns><see langword="true"/> if the attribute exists; otherwise, <see langword="false"/>.</returns>
    public bool Has(string category, string name) => _attributes.ContainsKey((category, name));
}
