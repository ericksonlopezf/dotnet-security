// Copyright © Erickson Lopez. MIT License.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using EricksonLopez.Security.Sample.Levels;

Console.WriteLine("################################################################################");
Console.WriteLine("#                                                                              #");
Console.WriteLine("#     ERICKSONLOPEZ.SECURITY — OFFICIAL REFERENCE SHOWCASE & EXECUTABLE SPEC    #");
Console.WriteLine("#                                                                              #");
Console.WriteLine("################################################################################");
Console.WriteLine("Target Frameworks: .NET 8.0 | .NET 9.0 | .NET 10.0");
Console.WriteLine("Design Invariants: Native AOT | Zero-Allocation | Misuse-Resistance | Zero Trust\n");

var requestedLevels = new HashSet<int>();
var runAll = false;

if (args.Length == 0 || args.Any(a => a.Equals("all", StringComparison.OrdinalIgnoreCase) || a.Equals("--all", StringComparison.OrdinalIgnoreCase)))
{
    runAll = true;
}
else if (args.Any(a => a.Equals("-h", StringComparison.OrdinalIgnoreCase) || a.Equals("--help", StringComparison.OrdinalIgnoreCase) || a.Equals("help", StringComparison.OrdinalIgnoreCase)))
{
    Console.WriteLine("Usage: dotnet run [--all] [level-numbers...]");
    Console.WriteLine("Available Showcase Levels:");
    Console.WriteLine("   0 : Level 0 — Conceptual Foundations & Architectural Invariants");
    Console.WriteLine("   1 : Level 1 — Quick Start & Minimum Setup");
    Console.WriteLine("   2 : Level 2 — Configuration, Policies, Memory Safety, PQ Crypto");
    Console.WriteLine("   3 : Level 3 — Production Use Cases, Key Rotation, ProtectedSecret & Sync APIs");
    Console.WriteLine("   4 : Level 4 — Advanced Integration, Defense-in-Depth, Security Events & IKeyRing");
    Console.WriteLine("   5 : Level 5 — Security Protocols & Ceremonies (Passkeys, SAML 2.0, XmlDSig)");
    Console.WriteLine("   6 : Level 6 — Error Handling, SecurityError Catalog, Resilience & Constant-Time");
    Console.WriteLine("   7 : Level 7 — Scalability, Performance & Zero-Allocation Primitives");
    Console.WriteLine("   8 : Level 8 — Customization, Extensibility & Component Replacement");
    Console.WriteLine("   9 : Level 9 — Cloud KMS Adapters, HSM & Ecosystem Extensions");
    Console.WriteLine("  10 : Level 10 — Enterprise Zero Trust Architecture & Observability");
    Console.WriteLine("  11 : Level 11 — Comprehensive Public API Coverage Verification");
    Console.WriteLine("\nExample: dotnet run -- 0 3 11");
    return;
}
else
{
    foreach (var arg in args)
    {
        var cleaned = arg.Trim().Replace("level", "", StringComparison.OrdinalIgnoreCase).Replace("-", "").Replace("_", "");
        if (int.TryParse(cleaned, out var lvl) && lvl >= 0 && lvl <= 11)
        {
            requestedLevels.Add(lvl);
        }
    }

    if (requestedLevels.Count == 0)
    {
        Console.WriteLine($"[WARN] No recognized level arguments in: {string.Join(" ", args)}. Defaulting to all levels.\n");
        runAll = true;
    }
}

if (runAll || requestedLevels.Contains(0))
{
    // Level 0: Conceptual Foundations & Architectural Invariants
    Level0_Conceptual.Run();
}

if (runAll || requestedLevels.Contains(1))
{
    // Level 1: Quick Start & Minimum Setup
    await Level1_QuickStart.RunAsync();
}

if (runAll || requestedLevels.Contains(2))
{
    // Level 2: Comprehensive Configuration, Policies, Memory Safety, PQ Crypto & Primitives
    Level2_FullConfiguration.Run();
}

if (runAll || requestedLevels.Contains(3))
{
    // Level 3: Real-World Production Use Cases, Key Rotation, ProtectedSecret & Sync APIs
    await Level3_RealWorldUseCases.RunAsync();
}

if (runAll || requestedLevels.Contains(4))
{
    // Level 4: Advanced Integration, Defense-in-Depth, Security Events & IKeyRing
    await Level4_AdvancedIntegration.Run();
}

if (runAll || requestedLevels.Contains(5))
{
    // Level 5: Security Protocols & Ceremonies (Passkeys FIDO2, SAML 2.0, XmlDSig)
    Level5_ProtocolsAndCeremonies.Run();
}

if (runAll || requestedLevels.Contains(6))
{
    // Level 6: Error Handling, SecurityError Catalog, Resilience & Constant-Time
    await Level6_ErrorHandlingAndResilience.RunAsync();
}

if (runAll || requestedLevels.Contains(7))
{
    // Level 7: Scalability, Performance & Zero-Allocation Primitives
    await Level7_ScalabilityAndPerformance.RunAsync();
}

if (runAll || requestedLevels.Contains(8))
{
    // Level 8: Customization, Extensibility & Component Replacement
    await Level8_CustomizationAndExtensibility.RunAsync();
}

if (runAll || requestedLevels.Contains(9))
{
    // Level 9: Cloud KMS Adapters, HSM & Ecosystem Extensions
    Level9_ExtensionsAndCloudKms.Run();
}

if (runAll || requestedLevels.Contains(10))
{
    // Level 10: Enterprise Zero Trust Architecture & Observability
    Level10_EnterpriseZeroTrust.Run();
}

if (runAll || requestedLevels.Contains(11))
{
    // Level 11: Comprehensive Public API Coverage Verification
    await Level11_ComprehensiveApiCoverage.RunAsync();
}

var executedCount = runAll ? 12 : requestedLevels.Count;
Console.WriteLine("\n################################################################################");
Console.WriteLine($"#  [OK] SHOWCASE EXECUTION COMPLETED ({executedCount} LEVEL(S)) WITH ZERO ERRORS          #");
Console.WriteLine("################################################################################\n");
