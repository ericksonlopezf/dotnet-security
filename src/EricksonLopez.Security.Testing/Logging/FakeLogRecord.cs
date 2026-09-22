// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Testing.Logging;

using System;
using Microsoft.Extensions.Logging;

/// <summary>
/// Represents an immutable record of a captured log invocation in <see cref="FakeLogger{T}"/>.
/// </summary>
/// <param name="LogLevel">The severity level of the log entry.</param>
/// <param name="EventId">The event identifier associated with the log entry.</param>
/// <param name="State">The state object passed to the logger.</param>
/// <param name="Exception">The exception associated with the log entry, if any.</param>
/// <param name="Message">The formatted log message text.</param>
public sealed record FakeLogRecord(
    LogLevel LogLevel,
    EventId EventId,
    object? State,
    Exception? Exception,
    string Message);
