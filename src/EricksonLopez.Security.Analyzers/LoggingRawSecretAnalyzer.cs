// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Analyzers;

using System.Collections.Immutable;
using System.Linq;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Diagnostics;

/// <summary>
/// Represents a diagnostic analyzer that detects when security-sensitive values are logged without redaction.
/// </summary>
[DiagnosticAnalyzer(LanguageNames.CSharp)]
public sealed class LoggingRawSecretAnalyzer : DiagnosticAnalyzer
{
    internal static readonly DiagnosticDescriptor Rule = new(
        id: DiagnosticIds.LoggingRawSecret,
        title: "Security-sensitive value passed to logger without Redacted<T>",
        messageFormat: "'{0}' appears to be a security-sensitive value. Wrap it in Redacted<T> before logging to prevent secret leakage in log sinks.",
        category: "Security",
        defaultSeverity: DiagnosticSeverity.Warning,
        isEnabledByDefault: true,
        description: "Passing secrets, tokens, keys, or passwords directly to an ILogger method will write them " +
                     "to the log sink in plaintext, potentially exposing them in log aggregation systems, " +
                     "storage backends, or monitoring dashboards. Wrap the value in Redacted<T> from " +
                     "EricksonLopez.Security to ensure only '[REDACTED]' appears in the log output.",
        helpLinkUri: "https://ericksonlopez.dev/security/analyzers/ELS0005");

    private static readonly string[] LoggerMethodNames =
    [
        "LogTrace", "LogDebug", "LogInformation", "LogWarning", "LogError", "LogCritical",
        "Log", "BeginScope",
    ];

    private static readonly string[] SensitiveNameFragments =
    [
        "token", "key", "hash", "secret", "password", "signature", "hmac", "mac",
        "nonce", "salt", "credential", "apikey", "passphrase", "otp", "totp",
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
        context.RegisterSyntaxNodeAction(AnalyzeInvocation, SyntaxKind.InvocationExpression);
    }

    private static void AnalyzeInvocation(SyntaxNodeAnalysisContext context)
    {
        var invocation = (InvocationExpressionSyntax)context.Node;

        // Check if this is a logger method call
        if (invocation.Expression is not MemberAccessExpressionSyntax memberAccess)
            return;

        var methodName = memberAccess.Name.Identifier.Text;
        if (!LoggerMethodNames.Any(m => m == methodName))
            return;

        // Check if the receiver is an ILogger
        var receiverType = context.SemanticModel.GetTypeInfo(memberAccess.Expression).Type;
        if (!IsLoggerType(receiverType))
            return;

        // Check each argument for security-sensitive names
        foreach (var argument in invocation.ArgumentList.Arguments)
        {
            var argName = GetArgumentName(argument.Expression);
            if (IsSensitiveName(argName))
            {
                // Check it's NOT already wrapped in Redacted<T>
                if (!IsWrappedInRedacted(argument.Expression))
                {
                    context.ReportDiagnostic(Diagnostic.Create(
                        Rule,
                        argument.GetLocation(),
                        argName));
                }
            }
        }
    }

    [System.Diagnostics.CodeAnalysis.ExcludeFromCodeCoverage]
    private static bool IsLoggerType(ITypeSymbol? type)
    {
        if (type is null) return false;
        var fullName = type.ToDisplayString();
        return fullName.Contains("ILogger") || fullName.Contains("Microsoft.Extensions.Logging");
    }

    private static string? GetArgumentName(ExpressionSyntax expr) => expr switch
    {
        IdentifierNameSyntax id => id.Identifier.Text,
        MemberAccessExpressionSyntax ma => ma.Name.Identifier.Text,
        _ => null,
    };

    private static bool IsSensitiveName(string? name)
    {
        if (name is null) return false;
        var lower = name.ToLowerInvariant();
        return SensitiveNameFragments.Any(s => lower.Contains(s));
    }

    private static bool IsWrappedInRedacted(ExpressionSyntax expr)
    {
        // Check if the expression is Redacted.From(...) or new Redacted<T>(...)
        var text = expr.ToString();
        return text.Contains("Redacted");
    }
}
