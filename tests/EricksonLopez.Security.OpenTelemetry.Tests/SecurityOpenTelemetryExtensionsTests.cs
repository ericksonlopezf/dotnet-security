// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.OpenTelemetry.Tests;

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.Metrics;
using AwesomeAssertions;
using EricksonLopez.Security.Diagnostics;
using EricksonLopez.Security.OpenTelemetry;
using global::OpenTelemetry;
using global::OpenTelemetry.Metrics;
using global::OpenTelemetry.Trace;
using Xunit;

public sealed class SecurityOpenTelemetryExtensionsTests
{
    [Fact]
    public void AddEricksonLopezSecurityInstrumentation_TracerProviderBuilder_NullBuilder_ThrowsArgumentNullException()
    {
        TracerProviderBuilder builder = null!;
        Assert.Throws<ArgumentNullException>(() => builder.AddEricksonLopezSecurityInstrumentation());
    }

    [Fact]
    public void AddEricksonLopezSecurityInstrumentation_MeterProviderBuilder_NullBuilder_ThrowsArgumentNullException()
    {
        MeterProviderBuilder builder = null!;
        Assert.Throws<ArgumentNullException>(() => builder.AddEricksonLopezSecurityInstrumentation());
    }

    [Fact]
    public void AddEricksonLopezSecurityInstrumentation_TracerProvider_BuildsSuccessfullyAndSubscribesSource()
    {
        using var tracerProvider = Sdk.CreateTracerProviderBuilder()
            .AddEricksonLopezSecurityInstrumentation()
            .Build();

        // Verify activity creation via SecurityActivitySource
        using var activity = SecurityActivitySource.Instance.StartActivity(SecurityActivitySource.EncryptOperation);
        activity.Should().NotBeNull();
        activity!.Source.Name.Should().Be(SecurityActivitySource.SourceName);
    }

    [Fact]
    public void AddEricksonLopezSecurityInstrumentation_MeterProvider_BuildsSuccessfullyAndSubscribesMeter()
    {
        var measurements = new System.Collections.Generic.List<(string InstrumentName, long Value)>();
        using var listener = new System.Diagnostics.Metrics.MeterListener
        {
            InstrumentPublished = (inst, l) =>
            {
                if (inst.Meter.Name == SecurityMeter.MeterName)
                {
                    l.EnableMeasurementEvents(inst);
                }
            }
        };
        listener.SetMeasurementEventCallback<long>((inst, val, tags, state) =>
        {
            measurements.Add((inst.Name, val));
        });
        listener.Start();

        using var meterProvider = Sdk.CreateMeterProviderBuilder()
            .AddEricksonLopezSecurityInstrumentation()
            .Build();

        meterProvider.Should().NotBeNull();

        // Verify metrics recording via SecurityMeter
        SecurityMeter.EncryptTotal.Add(1, new KeyValuePair<string, object?>("security.algorithm", "aes-256-gcm"));
        SecurityMeter.DecryptTotal.Add(1, new KeyValuePair<string, object?>("security.algorithm", "aes-256-gcm"));
        SecurityMeter.KeyRotationsTotal.Add(1, new KeyValuePair<string, object?>("security.key.version", 2));
        SecurityMeter.KeyRevocationsTotal.Add(1, new KeyValuePair<string, object?>("security.result", "success"));

        listener.RecordObservableInstruments();

        measurements.Should().Contain(m => m.InstrumentName == "security.encrypt.total" && m.Value == 1);
        measurements.Should().Contain(m => m.InstrumentName == "security.decrypt.total" && m.Value == 1);
        measurements.Should().Contain(m => m.InstrumentName == "security.key.rotations_total" && m.Value == 1);
        measurements.Should().Contain(m => m.InstrumentName == "security.key.revocations_total" && m.Value == 1);
    }
}
