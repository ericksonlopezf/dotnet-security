// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.OpenTelemetry;

using System;
using global::OpenTelemetry.Metrics;
using global::OpenTelemetry.Trace;
using EricksonLopez.Security.Diagnostics;


/// <summary>
/// Provides extension methods for registering EricksonLopez.Security instrumentation in OpenTelemetry tracing and metrics pipelines.
/// </summary>
/// <example>
/// <code>
/// // Tracing
/// builder.Services.AddOpenTelemetry()
///     .WithTracing(tracing => tracing
///         .AddEricksonLopezSecurityInstrumentation()
///         .AddOtlpExporter());
///
/// // Metrics
/// builder.Services.AddOpenTelemetry()
///     .WithMetrics(metrics => metrics
///         .AddEricksonLopezSecurityInstrumentation()
///         .AddOtlpExporter());
/// </code>
/// </example>
public static class SecurityOpenTelemetryExtensions
{
    /// <summary>
    /// Subscribes the EricksonLopez.Security <see cref="SecurityActivitySource"/>
    /// to the OpenTelemetry tracing pipeline.
    /// </summary>
    /// <param name="builder">The tracer provider builder to configure.</param>
    /// <returns>The configured <see cref="TracerProviderBuilder"/> instance.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="builder"/> is <see langword="null"/></exception>
    public static TracerProviderBuilder AddEricksonLopezSecurityInstrumentation(
        this TracerProviderBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);
        return builder.AddSource(SecurityActivitySource.SourceName);
    }

    /// <summary>
    /// Subscribes the EricksonLopez.Security <see cref="SecurityMeter"/>
    /// to the OpenTelemetry metrics pipeline.
    /// </summary>
    /// <param name="builder">The meter provider builder to configure.</param>
    /// <returns>The configured <see cref="MeterProviderBuilder"/> instance.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="builder"/> is <see langword="null"/></exception>
    public static MeterProviderBuilder AddEricksonLopezSecurityInstrumentation(
        this MeterProviderBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);
        return builder.AddMeter(SecurityMeter.MeterName);
    }
}
