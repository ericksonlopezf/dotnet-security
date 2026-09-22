// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Testing.Logging;

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using Microsoft.Extensions.Logging;

/// <summary>
/// Provides a thread-safe test double implementation of <see cref="ILogger{TCategoryName}"/> for capturing and asserting on structured log output.
/// </summary>
/// <typeparam name="TCategoryName">The logger category type.</typeparam>
public sealed class FakeLogger<TCategoryName> : ILogger<TCategoryName>
{
    private readonly ConcurrentQueue<FakeLogRecord> _entries = new();
    private readonly LogLevel _minLevel;

    /// <summary>
    /// Initializes a new instance of the <see cref="FakeLogger{TCategoryName}"/> class with an optional minimum enabled log level.
    /// </summary>
    /// <param name="minLevel">The minimum log level to accept (defaults to <see cref="LogLevel.Trace"/>).</param>
    public FakeLogger(LogLevel minLevel = LogLevel.Trace)
    {
        _minLevel = minLevel;
    }

    /// <summary>
    /// Gets a snapshot of all captured log entries in chronological order.
    /// </summary>
    public IReadOnlyList<FakeLogRecord> Entries => _entries.ToArray();

    /// <summary>
    /// Gets a list of all formatted log message strings captured so far.
    /// </summary>
    public IReadOnlyList<string> Messages => _entries.Select(e => e.Message).ToList();

    /// <summary>
    /// Gets the total number of captured log entries.
    /// </summary>
    public int Count => _entries.Count;

    /// <summary>
    /// Determines whether any captured log entry contains the specified substring.
    /// </summary>
    /// <param name="substring">The substring to look for.</param>
    /// <returns><see langword="true"/> if a matching entry was logged; otherwise, <see langword="false"/>.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="substring"/> is <see langword="null"/></exception>
    public bool HasMessage(string substring)
    {
        ArgumentNullException.ThrowIfNull(substring);
        return _entries.Any(e => e.Message.Contains(substring, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// Determines whether any captured log entry with the given log level contains the specified substring.
    /// </summary>
    /// <param name="level">The expected log level.</param>
    /// <param name="substring">The substring to look for.</param>
    /// <returns><see langword="true"/> if a matching entry was logged; otherwise, <see langword="false"/>.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="substring"/> is <see langword="null"/></exception>
    public bool HasMessage(LogLevel level, string substring)
    {
        ArgumentNullException.ThrowIfNull(substring);
        return _entries.Any(e => e.LogLevel == level && e.Message.Contains(substring, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// Determines whether a warning log entry contains the specified substring.
    /// </summary>
    /// <param name="substring">The substring to look for in warning log messages.</param>
    /// <returns><see langword="true"/> if a matching warning entry was logged; otherwise, <see langword="false"/>.</returns>
    public bool HasWarning(string substring) => HasMessage(LogLevel.Warning, substring);

    /// <summary>
    /// Determines whether an error log entry contains the specified substring.
    /// </summary>
    /// <param name="substring">The substring to look for in error log messages.</param>
    /// <returns><see langword="true"/> if a matching error entry was logged; otherwise, <see langword="false"/>.</returns>
    public bool HasError(string substring) => HasMessage(LogLevel.Error, substring);

    /// <summary>
    /// Clears all recorded entries.
    /// </summary>
    public void Clear() => _entries.Clear();

    /// <inheritdoc />
    public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

    /// <inheritdoc />
    public bool IsEnabled(LogLevel logLevel) => logLevel >= _minLevel;

    /// <inheritdoc />
    public void Log<TState>(
        LogLevel logLevel,
        EventId eventId,
        TState state,
        Exception? exception,
        Func<TState, Exception?, string> formatter)
    {
        if (!IsEnabled(logLevel))
        {
            return;
        }

        ArgumentNullException.ThrowIfNull(formatter);
        var message = formatter(state, exception);
        _entries.Enqueue(new FakeLogRecord(logLevel, eventId, state, exception, message));
    }
}
