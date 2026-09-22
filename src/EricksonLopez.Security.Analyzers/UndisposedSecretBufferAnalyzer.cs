// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Analyzers;

using System.Collections.Immutable;
using System.Linq;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Diagnostics;

/// <summary>
/// Represents a diagnostic analyzer that detects secret buffers that are not properly disposed.
/// </summary>
/// <remarks>
/// Ensures that instances of <c>SecretBuffer</c> are scoped within using statements or explicitly disposed
/// to guarantee that sensitive memory is zeroed upon disposal.
/// </remarks>
[DiagnosticAnalyzer(LanguageNames.CSharp)]
public sealed class UndisposedSecretBufferAnalyzer : DiagnosticAnalyzer
{
    internal static readonly DiagnosticDescriptor Rule = new(
        id: DiagnosticIds.UndisposedSecretBuffer,
        title: "SecretBuffer must be disposed to zero sensitive memory",
        messageFormat: "'{0}' is a SecretBuffer that should be disposed with 'using' to ensure sensitive bytes are zeroed from memory when no longer needed",
        category: "Security",
        defaultSeverity: DiagnosticSeverity.Warning,
        isEnabledByDefault: true,
        description: "SecretBuffer holds sensitive data in managed memory. If not disposed, " +
                     "the ZeroMemory scrubbing in Dispose() is never called, leaving secret bytes " +
                     "potentially accessible in memory for the lifetime of the process.",
        helpLinkUri: "https://ericksonlopez.dev/security/analyzers/ELS0002");

    /// <summary>
    /// Gets a set of descriptors for the diagnostic rules that this analyzer is capable of producing.
    /// </summary>
    public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics =>
        ImmutableArray.Create(Rule);

    /// <inheritdoc/>
    [System.Diagnostics.CodeAnalysis.ExcludeFromCodeCoverage]
    public override void Initialize(AnalysisContext context)
    {
        context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.None);
        context.EnableConcurrentExecution();
        context.RegisterSyntaxNodeAction(AnalyzeLocalDeclaration, SyntaxKind.LocalDeclarationStatement);
    }

    private static void AnalyzeLocalDeclaration(SyntaxNodeAnalysisContext context)
    {
        var localDecl = (LocalDeclarationStatementSyntax)context.Node;

        // Skip if already declared with 'using'
        if (localDecl.UsingKeyword.IsKind(SyntaxKind.UsingKeyword))
            return;

        foreach (var variable in localDecl.Declaration.Variables)
        {
            if (variable.Initializer?.Value is null)
                continue;

            var typeInfo = context.SemanticModel.GetTypeInfo(variable.Initializer.Value);
            var type = typeInfo.Type;

            if (!IsSecretBufferType(type))
                continue;

            // Check if parent block has a 'using' statement or the variable is in a 'using' block higher up
            // Heuristic: if there's no using keyword on the declaration, warn.
            context.ReportDiagnostic(Diagnostic.Create(
                Rule,
                variable.GetLocation(),
                variable.Identifier.Text));
        }
    }

    [System.Diagnostics.CodeAnalysis.ExcludeFromCodeCoverage]
    private static bool IsSecretBufferType(ITypeSymbol? type)
    {
        if (type is null) return false;
        return type.Name == "SecretBuffer" &&
               type.ContainingNamespace?.ToDisplayString() is
                   "EricksonLopez.Security.Secrets" or
                   "EricksonLopez.Security.Memory";
    }
}
