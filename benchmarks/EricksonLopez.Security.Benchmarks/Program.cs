// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Benchmarks;

using System;
using System.Linq;
using BenchmarkDotNet.Configs;
using BenchmarkDotNet.Jobs;
using BenchmarkDotNet.Running;
using BenchmarkDotNet.Toolchains.InProcess.Emit;

internal static class Program
{
    public static void Main(string[] args)
    {
        IConfig config = DefaultConfig.Instance;
        if (args.Contains("--inprocess", StringComparer.OrdinalIgnoreCase))
        {
            config = config.AddJob(Job.Default.WithToolchain(InProcessEmitToolchain.Instance));
        }

        var filteredArgs = args.Where(a => !string.Equals(a, "--inprocess", StringComparison.OrdinalIgnoreCase)).ToArray();
        BenchmarkSwitcher.FromAssembly(typeof(Program).Assembly).Run(filteredArgs, config);
    }
}
