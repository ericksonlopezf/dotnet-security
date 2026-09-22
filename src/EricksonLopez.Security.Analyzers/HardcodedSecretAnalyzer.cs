// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Analyzers;

using System.Collections.Immutable;
using System.Linq;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Diagnostics;

/// <summary>
/// Represents a diagnostic analyzer that detects hardcoded string literals assigned to variables with security-sensitive names.
/// </summary>
[DiagnosticAnalyzer(LanguageNames.CSharp)]
public sealed class HardcodedSecretAnalyzer : DiagnosticAnalyzer
{
    internal static readonly DiagnosticDescriptor Rule = new(
        id: DiagnosticIds.HardcodedSecret,
        title: "Hardcoded secret or key detected",
        messageFormat: "'{0}' appears to be a hardcoded secret or cryptographic key. " +
                       "Secrets should be loaded from configuration, environment variables, or a secrets manager (e.g. HashiCorp Vault, Azure Key Vault).",
        category: "Security",
        defaultSeverity: DiagnosticSeverity.Warning,
        isEnabledByDefault: true,
        description: "Hardcoded secrets in source code are a severe security risk. They are committed to source control, " +
                     "visible in binaries, and cannot be rotated without a code change. " +
                     "Use EricksonLopez.Security.HashiCorpVault or EricksonLopez.Security.Azure to retrieve secrets at runtime.",
        helpLinkUri: "https://ericksonlopez.dev/security/analyzers/ELS0003");

    private static readonly string[] SensitiveVariableNameFragments =
    [
        "password", "passwd", "secret", "apikey", "api_key", "secretkey", "privatekey",
        "passphrase", "encryptionkey", "signingkey", "hmackey", "connectionstring",
    ];

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
        context.RegisterSyntaxNodeAction(AnalyzeAssignment, SyntaxKind.SimpleAssignmentExpression);
        context.RegisterSyntaxNodeAction(AnalyzeLocalDeclaration, SyntaxKind.LocalDeclarationStatement);
        context.RegisterSyntaxNodeAction(AnalyzeFieldDeclaration, SyntaxKind.FieldDeclaration);
    }

    private static void AnalyzeAssignment(SyntaxNodeAnalysisContext context)
    {
        var assignment = (AssignmentExpressionSyntax)context.Node;
        if (assignment.Right is not LiteralExpressionSyntax literal ||
            !literal.IsKind(SyntaxKind.StringLiteralExpression))
            return;

        // Skip empty or very short strings
        var value = literal.Token.ValueText;
        if (string.IsNullOrWhiteSpace(value) || value.Length < 4)
            return;

        var leftName = GetIdentifierName(assignment.Left);
        if (IsSensitiveName(leftName))
        {
            context.ReportDiagnostic(Diagnostic.Create(Rule, assignment.GetLocation(), leftName));
        }
    }

    private static void AnalyzeLocalDeclaration(SyntaxNodeAnalysisContext context)
    {
        var localDecl = (LocalDeclarationStatementSyntax)context.Node;
        foreach (var variable in localDecl.Declaration.Variables)
        {
            if (variable.Initializer?.Value is LiteralExpressionSyntax literal &&
                literal.IsKind(SyntaxKind.StringLiteralExpression))
            {
                var value = literal.Token.ValueText;
                if (string.IsNullOrWhiteSpace(value) || value.Length < 4)
                    continue;

                if (IsSensitiveName(variable.Identifier.Text))
                {
                    context.ReportDiagnostic(Diagnostic.Create(
                        Rule, variable.GetLocation(), variable.Identifier.Text));
                }
            }
        }
    }

    private static void AnalyzeFieldDeclaration(SyntaxNodeAnalysisContext context)
    {
        var fieldDecl = (FieldDeclarationSyntax)context.Node;
        foreach (var variable in fieldDecl.Declaration.Variables)
        {
            if (variable.Initializer?.Value is LiteralExpressionSyntax literal &&
                literal.IsKind(SyntaxKind.StringLiteralExpression))
            {
                var value = literal.Token.ValueText;
                if (string.IsNullOrWhiteSpace(value) || value.Length < 4)
                    continue;

                if (IsSensitiveName(variable.Identifier.Text))
                {
                    context.ReportDiagnostic(Diagnostic.Create(
                        Rule, variable.GetLocation(), variable.Identifier.Text));
                }
            }
        }
    }

    private static string? GetIdentifierName(ExpressionSyntax expr) => expr switch
    {
        IdentifierNameSyntax id => id.Identifier.Text,
        MemberAccessExpressionSyntax ma => ma.Name.Identifier.Text,
        _ => null,
    };

    private static bool IsSensitiveName(string? name)
    {
        if (name is null) return false;
        var lower = name.ToLowerInvariant();
        return SensitiveVariableNameFragments.Any(s => lower.Contains(s));
    }
}
