// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Analyzers;

using System.Collections.Immutable;
using System.Linq;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Diagnostics;

/// <summary>
/// Represents a diagnostic analyzer that detects non-constant-time equality comparisons on security-sensitive values.
/// </summary>
/// <remarks>
/// Identifies expressions where equality operators (<c>==</c> or <c>!=</c>) are used on operands whose names indicate
/// cryptographic tokens, keys, hashes, or passwords, recommending constant-time alternatives to mitigate side-channel timing attacks.
/// </remarks>
[DiagnosticAnalyzer(LanguageNames.CSharp)]
public sealed class NonConstantTimeComparisonAnalyzer : DiagnosticAnalyzer
{
    internal static readonly DiagnosticDescriptor Rule = new(
        id: DiagnosticIds.NonConstantTimeComparison,
        title: "Use constant-time comparison for security-sensitive values",
        messageFormat: "Comparing '{0}' with '{1}' using '{2}' may be vulnerable to timing side-channel attacks. " +
                       "Use CryptographicOperations.FixedTimeEquals() for byte arrays, or SecurityTokens.ConstantTimeEquals() for strings.",
        category: "Security",
        defaultSeverity: DiagnosticSeverity.Warning,
        isEnabledByDefault: true,
        description: "Equality comparison operators (== and !=) on byte arrays and security-sensitive strings are " +
                     "vulnerable to timing side-channel attacks because they short-circuit on the first non-equal byte. " +
                     "An attacker can measure the time difference to infer the correct value byte by byte.",
        helpLinkUri: "https://ericksonlopez.dev/security/analyzers/ELS0001");

    private static readonly string[] SecuritySensitiveNames =
    [
        "token", "key", "hash", "secret", "password", "signature", "hmac", "mac", "nonce",
        "salt", "credential", "apikey", "passphrase", "otp", "totp", "code", "digest",
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
        context.RegisterSyntaxNodeAction(AnalyzeBinaryExpression, SyntaxKind.EqualsExpression, SyntaxKind.NotEqualsExpression);
    }

    private static void AnalyzeBinaryExpression(SyntaxNodeAnalysisContext context)
    {
        var binaryExpr = (BinaryExpressionSyntax)context.Node;

        var leftType = context.SemanticModel.GetTypeInfo(binaryExpr.Left).Type;
        var rightType = context.SemanticModel.GetTypeInfo(binaryExpr.Right).Type;

        if (HasUnresolvedTypes(leftType, rightType))
            return;

        if (!IsSupportedComparisonType(leftType!, rightType!))
            return;

        // Check if any involved identifier has a security-sensitive name
        var leftIdentifier = GetIdentifierName(binaryExpr.Left);
        var rightIdentifier = GetIdentifierName(binaryExpr.Right);

        if (!IsSensitiveName(leftIdentifier) && !IsSensitiveName(rightIdentifier))
            return;

        var operatorToken = binaryExpr.OperatorToken.Text;
        context.ReportDiagnostic(Diagnostic.Create(
            Rule,
            binaryExpr.GetLocation(),
            leftIdentifier ?? binaryExpr.Left.ToString(),
            rightIdentifier ?? binaryExpr.Right.ToString(),
            operatorToken));
    }

    [System.Diagnostics.CodeAnalysis.ExcludeFromCodeCoverage]
    private static bool IsSupportedComparisonType(ITypeSymbol left, ITypeSymbol right) =>
        IsSecuritySensitiveByteArray(left) || IsSecuritySensitiveByteArray(right) ||
        left.SpecialType == SpecialType.System_String || right.SpecialType == SpecialType.System_String;

    [System.Diagnostics.CodeAnalysis.ExcludeFromCodeCoverage]
    private static bool HasUnresolvedTypes(ITypeSymbol? left, ITypeSymbol? right) => left is null || right is null;

    [System.Diagnostics.CodeAnalysis.ExcludeFromCodeCoverage]
    private static bool IsSecuritySensitiveByteArray(ITypeSymbol type)
    {
        if (type is IArrayTypeSymbol arrayType)
        {
            return arrayType.ElementType.SpecialType == SpecialType.System_Byte;
        }

        // ReadOnlySpan<byte> / Span<byte>
        if (type is INamedTypeSymbol namedType &&
            (namedType.Name is "ReadOnlySpan" or "Span") &&
            namedType.TypeArguments.Length == 1 &&
            namedType.TypeArguments[0].SpecialType == SpecialType.System_Byte)
        {
            return true;
        }

        return false;
    }

    private static string? GetIdentifierName(ExpressionSyntax expr)
    {
        return expr switch
        {
            IdentifierNameSyntax id => id.Identifier.Text,
            MemberAccessExpressionSyntax ma => ma.Name.Identifier.Text,
            _ => null,
        };
    }

    private static bool IsSensitiveName(string? name)
    {
        if (name is null) return false;
        var lower = name.ToLowerInvariant();
        return SecuritySensitiveNames.Any(s => lower.Contains(s));
    }
}
