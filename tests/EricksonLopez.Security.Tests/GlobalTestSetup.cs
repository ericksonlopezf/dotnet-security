// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Tests;

using System.Diagnostics;
using System.Runtime.CompilerServices;
using EricksonLopez.Security.Diagnostics;

internal static class GlobalTestSetup
{
    private static ActivityListener? s_listener;

    [ModuleInitializer]
    internal static void Initialize()
    {
        s_listener = new ActivityListener
        {
            ShouldListenTo = s => s.Name == SecurityActivitySource.SourceName,
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllData,
            ActivityStarted = _ => { },
            ActivityStopped = _ => { }
        };
        ActivitySource.AddActivityListener(s_listener);
    }
}
