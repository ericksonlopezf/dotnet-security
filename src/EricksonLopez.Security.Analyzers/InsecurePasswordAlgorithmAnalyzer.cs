// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Analyzers;

using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;

/// <summary>
/// Represents a diagnostic analyzer that detects the use of insecure or deprecated algorithms for password hashing.
/// </summary>
[DiagnosticAnalyzer(LanguageNames.CSharp)]
public sealed class InsecurePasswordAlgorithmAnalyzer : DiagnosticAnalyzer
{
    internal static readonly DiagnosticDescriptor Md5Sha1Rule = new(
        id: DiagnosticIds.InsecurePasswordAlgorithm,
        title: "Insecure algorithm used for password hashing",
        messageFormat: "'{0}' is not suitable for password hashing. Use Argon2id or PBKDF2-SHA512 via EricksonLopez.Security.",
        category: "Security",
        defaultSeverity: DiagnosticSeverity.Error,
        isEnabledByDefault: true,
        description: "MD5 and SHA-1/SHA-256 are cryptographic hash functions, not password hashing functions. " +
                     "They are extremely fast, making brute-force attacks trivial even with salting. " +
                     "Use Argon2id (memory-hard) or PBKDF2-SHA512 (high iteration count) instead.",
        helpLinkUri: "https://ericksonlopez.dev/security/analyzers/ELS0004");

    // Known insecure algorithm names for password hashing
    private static readonly string[] InsecureAlgorithms =
    [
        "MD5", "SHA1", "SHA-1", "SHA256", "SHA-256", "RIPEMD160",
    ];

    /// <summary>
    /// Gets a set of descriptors for the diagnostic rules that this analyzer is capable of producing.
    /// </summary>
    public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics =>
        ImmutableArray.Create(Md5Sha1Rule);

    /// <inheritdoc/>
    [System.Diagnostics.CodeAnalysis.ExcludeFromCodeCoverage]
    public override void Initialize(AnalysisContext context)
    {
        context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.None);
        context.EnableConcurrentExecution();
        context.RegisterOperationAction(AnalyzeInvocation, Microsoft.CodeAnalysis.OperationKind.Invocation);
    }

    [System.Diagnostics.CodeAnalysis.ExcludeFromCodeCoverage]
    private static void AnalyzeInvocation(OperationAnalysisContext context)
    {
        var invocation = (Microsoft.CodeAnalysis.Operations.IInvocationOperation)context.Operation;

        var targetMethod = invocation.TargetMethod;
        if (targetMethod is null)
            return;

        var containingType = targetMethod.ContainingType;
        if (containingType is null)
            return;

        var methodName = targetMethod.Name;
        var typeName = containingType.Name;

        // Detect HashAlgorithm.Create("MD5") or MD5.Create()
        if (typeName is "MD5" or "SHA1" or "RIPEMD160")
        {
            context.ReportDiagnostic(Diagnostic.Create(
                Md5Sha1Rule,
                invocation.Syntax.GetLocation(),
                typeName));
            return;
        }

        // Detect HashAlgorithmName.SHA1 / HashAlgorithmName.MD5 usage in a password context
        if (methodName is "Pbkdf2" && typeName is "Rfc2898DeriveBytes")
        {
            // Check if any argument to Pbkdf2 is HashAlgorithmName.MD5 or .SHA1
            foreach (var arg in invocation.Arguments)
            {
                var argDisplay = arg.Value?.Syntax?.ToString();
                if (argDisplay is null)
                    continue;

                foreach (var insecure in InsecureAlgorithms)
                {
                    if (argDisplay.Contains(insecure))
                    {
                        context.ReportDiagnostic(Diagnostic.Create(
                            Md5Sha1Rule,
                            arg.Syntax.GetLocation(),
                            insecure));
                    }
                }
            }
        }
    }
}
