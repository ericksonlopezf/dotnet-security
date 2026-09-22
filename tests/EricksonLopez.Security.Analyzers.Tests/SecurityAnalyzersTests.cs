// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Analyzers.Tests;

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Threading.Tasks;
using AwesomeAssertions;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.Diagnostics;
using Xunit;

public sealed class SecurityAnalyzersTests
{
    private static async Task<ImmutableArray<Diagnostic>> RunAnalyzerAsync(
        DiagnosticAnalyzer analyzer,
        string sourceCode)
    {
        var syntaxTree = CSharpSyntaxTree.ParseText(sourceCode);

        var references = new List<MetadataReference>
        {
            MetadataReference.CreateFromFile(typeof(object).Assembly.Location),
            MetadataReference.CreateFromFile(typeof(Enumerable).Assembly.Location),
            MetadataReference.CreateFromFile(typeof(ValueTask).Assembly.Location),
            MetadataReference.CreateFromFile(typeof(System.Security.Cryptography.MD5).Assembly.Location),
            MetadataReference.CreateFromFile(typeof(System.Security.Cryptography.Rfc2898DeriveBytes).Assembly.Location),
        };

        var runtimeAssembly = Assembly.Load("System.Runtime");
        if (runtimeAssembly != null)
        {
            references.Add(MetadataReference.CreateFromFile(runtimeAssembly.Location));
        }

        var compilation = CSharpCompilation.Create(
            "TestAssembly",
            new[] { syntaxTree },
            references,
            new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary));

        var compilationWithAnalyzers = compilation.WithAnalyzers(ImmutableArray.Create(analyzer));
        return await compilationWithAnalyzers.GetAnalyzerDiagnosticsAsync();
    }

    [Fact]
    public async Task HardcodedSecretAnalyzer_DetectsHardcodedSecretsInAssignmentsAndDeclarations()
    {
        var code = """
            namespace TestNamespace;
            public class Options
            {
                public string SecretKey { get; set; } = "";
                public string Passphrase { get; set; } = "";
                public string HmacKey { get; set; } = "";
                public string ConnectionString { get; set; } = "";
                public string PrivateKey { get; set; } = "";
                public string EncryptionKey { get; set; } = "";
            }

            public class TestClass
            {
                private static readonly string SecretKey = "hardcoded_secret_token_1234";
                private static readonly string Passwd = "hardcoded_passwd_1234";

                public void TestMethod(Options options)
                {
                    string apiKey = "sk_live_1234567890abcdef";
                    string api_key = "sk_test_1234567890abcdef";
                    string normalName = "John Doe";
                    string shortVal = "12";
                    string emptyVal = "";
                    string whitespaceVal = "    ";

                    string password;
                    password = "my_super_secret_password";

                    options.SecretKey = "options_secret_key_12345";
                    options.Passphrase = "options_passphrase_12345";
                    options.HmacKey = "options_hmackey_12345";
                    options.ConnectionString = "Server=tcp;Password=12345";
                    options.PrivateKey = "options_privatekey_12345";
                    options.EncryptionKey = "options_encryptionkey_12345";
                }
            }
            """;

        var analyzer = new HardcodedSecretAnalyzer();
        var diagnostics = await RunAnalyzerAsync(analyzer, code);

        diagnostics.Should().HaveCount(11);
        diagnostics.All(d => d.Id == DiagnosticIds.HardcodedSecret).Should().BeTrue();
        diagnostics.All(d => d.Severity == DiagnosticSeverity.Warning).Should().BeTrue();
        diagnostics.All(d => d.Location != Location.None).Should().BeTrue();
    }

    [Fact]
    public async Task HardcodedSecretAnalyzer_WhenVariableDeclarationHasSecret_ReportsDiagnosticWithProperLocation()
    {
        var code = """
            namespace TestNamespace;
            public class TestClass
            {
                public void Method()
                {
                    string apiKey = "sk_live_1234567890abcdef";
                }
            }
            """;

        var analyzer = new HardcodedSecretAnalyzer();
        var diagnostics = await RunAnalyzerAsync(analyzer, code);

        diagnostics.Should().HaveCount(1);
        var diag = diagnostics[0];
        diag.Id.Should().Be(DiagnosticIds.HardcodedSecret);
        diag.Severity.Should().Be(DiagnosticSeverity.Warning);
        diag.GetMessage().Should().Contain("apiKey");
    }

    [Fact]
    public async Task HardcodedSecretAnalyzer_WhenPropertyAssignmentHasSecret_ReportsDiagnostic()
    {
        var code = """
            namespace TestNamespace;
            public class Config
            {
                public string SecretKey { get; set; } = "";
            }
            public class TestClass
            {
                public void Method(Config config)
                {
                    config.SecretKey = "secret_value_12345";
                }
            }
            """;

        var analyzer = new HardcodedSecretAnalyzer();
        var diagnostics = await RunAnalyzerAsync(analyzer, code);

        diagnostics.Should().HaveCount(1);
        var diag = diagnostics[0];
        diag.Id.Should().Be(DiagnosticIds.HardcodedSecret);
        diag.GetMessage().Should().Contain("SecretKey");
    }

    [Fact]
    public async Task HardcodedSecretAnalyzer_WhenNormalVariableOrEmptyString_ReportsNoDiagnostic()
    {
        var code = """
            namespace TestNamespace;
            public class TestClass
            {
                public void Method()
                {
                    string normalName = "John Doe";
                    string emptyVal = "";
                    string shortVal = "12";
                }
            }
            """;

        var analyzer = new HardcodedSecretAnalyzer();
        var diagnostics = await RunAnalyzerAsync(analyzer, code);

        diagnostics.Should().BeEmpty();
    }

    [Fact]
    public async Task InsecurePasswordAlgorithmAnalyzer_DetectsMd5Sha1AndRfc2898Md5()
    {
        var code = """
            namespace TestNamespace;
            using System.Security.Cryptography;

            public class TestClass
            {
                public void TestMethod()
                {
                    var md5 = MD5.Create();
                    var sha1 = SHA1.Create();
                    var pbkdf2Md5 = Rfc2898DeriveBytes.Pbkdf2("pwd", "salt"u8.ToArray(), 1000, HashAlgorithmName.MD5, 32);
                    var pbkdf2Sha1 = Rfc2898DeriveBytes.Pbkdf2("pwd", "salt"u8.ToArray(), 1000, HashAlgorithmName.SHA1, 32);
                    var pbkdf2Sha256 = Rfc2898DeriveBytes.Pbkdf2("pwd", "salt"u8.ToArray(), 1000, HashAlgorithmName.SHA256, 32);
                    var pbkdf2Sha512 = Rfc2898DeriveBytes.Pbkdf2("pwd", "salt"u8.ToArray(), 1000, HashAlgorithmName.SHA512, 32);
                }
            }
            """;

        var analyzer = new InsecurePasswordAlgorithmAnalyzer();
        var diagnostics = await RunAnalyzerAsync(analyzer, code);

        diagnostics.Should().HaveCount(5);
        diagnostics.All(d => d.Id == DiagnosticIds.InsecurePasswordAlgorithm).Should().BeTrue();
        diagnostics.All(d => d.Severity == DiagnosticSeverity.Error).Should().BeTrue();
        diagnostics.All(d => d.Location != Location.None).Should().BeTrue();
    }

    [Fact]
    public async Task LoggingRawSecretAnalyzer_DetectsUnredactedSensitiveValuesInLogger()
    {
        var code = """
            namespace TestNamespace;
            using Microsoft.Extensions.Logging;

            public interface ILogger
            {
                void LogTrace(string message, params object[] args);
                void LogDebug(string message, params object[] args);
                void LogInformation(string message, params object[] args);
                void LogWarning(string message, params object[] args);
                void LogError(string message, params object[] args);
                void LogCritical(string message, params object[] args);
                void Log(string message, params object[] args);
                void BeginScope(string message, params object[] args);
            }

            public class TestClass
            {
                public void TestMethod(
                    ILogger logger,
                    string token,
                    string key,
                    string hash,
                    string secret,
                    string password,
                    string signature,
                    string hmac,
                    string mac,
                    string nonce,
                    string salt,
                    string credential,
                    string apikey,
                    string passphrase,
                    string otp,
                    string totp,
                    string normalData)
                {
                    logger.LogInformation("Token: {Token}", token);
                    logger.LogTrace("Key: {Key}", key);
                    logger.LogDebug("Hash: {Hash}", hash);
                    logger.LogWarning("Secret: {Secret}", secret);
                    logger.LogError("Password: {Password}", password);
                    logger.LogCritical("Signature: {Signature}", signature);
                    logger.Log("Hmac: {Hmac}", hmac);
                    logger.Log("Mac: {Mac}", mac);
                    logger.Log("Nonce: {Nonce}", nonce);
                    logger.Log("Salt: {Salt}", salt);
                    logger.Log("Credential: {Credential}", credential);
                    logger.Log("ApiKey: {ApiKey}", apikey);
                    logger.Log("Passphrase: {Passphrase}", passphrase);
                    logger.Log("Otp: {Otp}", otp);
                    logger.BeginScope("Totp: {Totp}", totp);

                    logger.LogInformation("Safe: {Data}", normalData);
                    logger.LogInformation("Redacted: {Token}", Redacted.From(token));
                }
            }

            public static class Redacted
            {
                public static string From(string val) => "[REDACTED]";
            }
            """;

        var analyzer = new LoggingRawSecretAnalyzer();
        var diagnostics = await RunAnalyzerAsync(analyzer, code);

        diagnostics.Should().HaveCount(15);
        diagnostics.All(d => d.Id == DiagnosticIds.LoggingRawSecret).Should().BeTrue();
        diagnostics.All(d => d.Severity == DiagnosticSeverity.Warning).Should().BeTrue();
        diagnostics.All(d => d.Location != Location.None).Should().BeTrue();
    }

    [Fact]
    public async Task NonConstantTimeComparisonAnalyzer_DetectsDirectEqualityOnSensitiveTokens()
    {
        var code = """
            namespace TestNamespace;
            using System;

            public class TokenHolder
            {
                public byte[] KeyBytes { get; set; } = Array.Empty<byte>();
                public byte[] HashBytes { get; set; } = Array.Empty<byte>();
                public byte[] SecretBytes { get; set; } = Array.Empty<byte>();
                public byte[] PasswordBytes { get; set; } = Array.Empty<byte>();
                public byte[] SignatureBytes { get; set; } = Array.Empty<byte>();
                public byte[] HmacBytes { get; set; } = Array.Empty<byte>();
                public byte[] NonceBytes { get; set; } = Array.Empty<byte>();
                public byte[] SaltBytes { get; set; } = Array.Empty<byte>();
                public byte[] CodeBytes { get; set; } = Array.Empty<byte>();
                public byte[] DigestBytes { get; set; } = Array.Empty<byte>();
            }

            public class TestClass
            {
                public bool Compare(
                    string authTokenA, string authTokenB,
                    string userA, string userB,
                    TokenHolder h1, TokenHolder h2)
                {
                    bool isSameUser = userA == userB;
                    bool isSameToken = authTokenA == authTokenB;
                    bool isDiffToken = authTokenA != authTokenB;
                    bool isSameKey = h1.KeyBytes == h2.KeyBytes;
                    bool isSameHash = h1.HashBytes == h2.HashBytes;
                    bool isSameSecret = h1.SecretBytes == h2.SecretBytes;
                    bool isSamePwd = h1.PasswordBytes == h2.PasswordBytes;
                    bool isSameSig = h1.SignatureBytes == h2.SignatureBytes;
                    bool isSameHmac = h1.HmacBytes == h2.HmacBytes;
                    bool isSameNonce = h1.NonceBytes == h2.NonceBytes;
                    bool isSameSalt = h1.SaltBytes == h2.SaltBytes;
                    bool isSameCode = h1.CodeBytes == h2.CodeBytes;
                    bool isSameDigest = h1.DigestBytes == h2.DigestBytes;

                    return isSameToken && !isDiffToken && isSameKey && isSameHash && isSameSecret && isSamePwd && isSameSig && isSameHmac && isSameNonce && isSameSalt && isSameCode && isSameDigest;
                }
            }
            """;

        var analyzer = new NonConstantTimeComparisonAnalyzer();
        var diagnostics = await RunAnalyzerAsync(analyzer, code);

        diagnostics.Should().HaveCount(12);
        diagnostics.All(d => d.Id == DiagnosticIds.NonConstantTimeComparison).Should().BeTrue();
        diagnostics.All(d => d.Severity == DiagnosticSeverity.Warning).Should().BeTrue();
        diagnostics.All(d => d.Location != Location.None).Should().BeTrue();
        diagnostics.Any(d => d.GetMessage().Contains("'KeyBytes' with 'KeyBytes'")).Should().BeTrue();
        diagnostics.All(d => !d.GetMessage().Contains("h1.KeyBytes")).Should().BeTrue();
    }

    [Fact]
    public async Task UndisposedSecretBufferAnalyzer_DetectsNonUsingSecretBufferDeclarations()
    {
        var code = """
            namespace EricksonLopez.Security.Memory
            {
                public sealed class SecretBuffer : System.IDisposable
                {
                    public static SecretBuffer Create() => new();
                    public void Dispose() { }
                }
            }

            namespace EricksonLopez.Security.Secrets
            {
                public sealed class SecretBuffer : System.IDisposable
                {
                    public static SecretBuffer Create() => new();
                    public void Dispose() { }
                }
            }

            namespace TestNamespace
            {
                public class TestClass
                {
                    public void TestMethod()
                    {
                        var unmanagedMem = EricksonLopez.Security.Memory.SecretBuffer.Create();
                        var unmanagedSec = EricksonLopez.Security.Secrets.SecretBuffer.Create();
                        using var safeMem = EricksonLopez.Security.Memory.SecretBuffer.Create();
                        using var safeSec = EricksonLopez.Security.Secrets.SecretBuffer.Create();
                        var plainText = "hello";
                    }
                }
            }
            """;

        var analyzer = new UndisposedSecretBufferAnalyzer();
        var diagnostics = await RunAnalyzerAsync(analyzer, code);

        diagnostics.Should().HaveCount(2);
        diagnostics.All(d => d.Id == DiagnosticIds.UndisposedSecretBuffer).Should().BeTrue();
        diagnostics.All(d => d.Severity == DiagnosticSeverity.Warning).Should().BeTrue();
        diagnostics.All(d => d.Location != Location.None).Should().BeTrue();
        diagnostics.Any(d => d.GetMessage().Contains("unmanagedMem")).Should().BeTrue();
        diagnostics.Any(d => d.GetMessage().Contains("unmanagedSec")).Should().BeTrue();
        diagnostics.All(d => !d.GetMessage().Contains("safeMem")).Should().BeTrue();
        diagnostics.All(d => !d.GetMessage().Contains("safeSec")).Should().BeTrue();
    }

    [Fact]
    public async Task HardcodedSecretAnalyzer_EdgeCases_EvaluatesCleanly()
    {
        var code = """
            namespace TestNamespace;
            public class TestClass
            {
                private string _uninitField;
                private int _fieldInt = 1234;
                private string _fieldRef = "";
                private string _fieldEmpty = "";
                private string _fieldShort = "12";
                private string _fieldNormal = "my_regular_field_value";

                public void TestMethod(string otherVal)
                {
                    string uninitLocal;
                    int localInt = 1234;
                    string localRef = otherVal;
                    string localEmpty = "";
                    string localShort = "12";
                    string localWs = "   ";
                    string localNormal = "normal_regular_local";

                    string normalAssigned;
                    normalAssigned = "regular_long_assigned_string";
                    normalAssigned = otherVal;
                    normalAssigned = "";
                    normalAssigned = "ab";

                    string[] arr = new string[2];
                    arr[0] = "secret_array_assignment_value";
                }
            }
            """;

        var analyzer = new HardcodedSecretAnalyzer();
        var diagnostics = await RunAnalyzerAsync(analyzer, code);

        diagnostics.Should().BeEmpty();
    }

    [Fact]
    public async Task HardcodedSecretAnalyzer_BoundaryLengthsAndWhitespace_KillsMutants()
    {
        var code = """
            namespace TestNamespace;
            public class Options
            {
                public string SecretKey { get; set; } = "";
            }

            public class TestClass
            {
                private string _secretField4 = "1234";
                private string _secretField3 = "123";
                private string _secretFieldWs = "          ";

                public void TestMethod(Options options)
                {
                    string secretLocal4 = "1234";
                    string secretLocal3 = "123";
                    string secretLocalWs = "          ";

                    options.SecretKey = "1234";
                    options.SecretKey = "123";
                    options.SecretKey = "          ";
                }
            }
            """;

        var analyzer = new HardcodedSecretAnalyzer();
        var diagnostics = await RunAnalyzerAsync(analyzer, code);

        diagnostics.Should().HaveCount(3);
        diagnostics.All(d => d.Id == DiagnosticIds.HardcodedSecret).Should().BeTrue();
    }

    [Fact]
    public async Task InsecurePasswordAlgorithmAnalyzer_EdgeCases_EvaluatesCleanly()
    {
        var code = """
            namespace TestNamespace;
            using System.Security.Cryptography;

            public class RIPEMD160
            {
                public static void Create() {}
            }

            public class OtherHelper
            {
                public static void Pbkdf2(string dummy) {}
            }

            public class TestClass
            {
                public void TestMethod()
                {
                    RIPEMD160.Create();
                    OtherHelper.Pbkdf2("secure_arg");
                    string.Concat("a", "b");
                    var derive = new Rfc2898DeriveBytes("pwd"u8.ToArray(), "salt"u8.ToArray(), 1000, HashAlgorithmName.SHA256);
                    derive.GetBytes(16);
                }
            }
            """;

        var analyzer = new InsecurePasswordAlgorithmAnalyzer();
        var diagnostics = await RunAnalyzerAsync(analyzer, code);

        diagnostics.Should().HaveCount(1);
        diagnostics[0].Id.Should().Be(DiagnosticIds.InsecurePasswordAlgorithm);
    }

    [Fact]
    public async Task LoggingRawSecretAnalyzer_EdgeCases_EvaluatesCleanly()
    {
        var code = """
            namespace TestNamespace;
            using Microsoft.Extensions.Logging;

            public interface ILogger
            {
                bool IsEnabled(int level);
                void LogInformation(string message, params object[] args);
                void CustomMethod(string message, params object[] args);
            }

            public class NonLogger
            {
                public void LogInformation(string message, params object[] args) {}
            }

            public class TokenHolder
            {
                public string SecretToken { get; set; } = "";
            }

            public class TestClass
            {
                private void StandaloneMethod() {}

                public void TestMethod(ILogger logger, NonLogger nonLogger, TokenHolder holder)
                {
                    StandaloneMethod();
                    logger.IsEnabled(1);
                    logger.CustomMethod("msg", holder.SecretToken);
                    nonLogger.LogInformation("Not real logger", holder.SecretToken);
                    logger.LogInformation("Member access secret: {Token}", holder.SecretToken);
                    logger.LogInformation("Literal: {Val}", "literal_val");
                    logger.LogInformation("Expression: {Val}", 1 + 2);
                    string tokenRedacted = "[REDACTED]";
                    logger.LogInformation("Redacted secret: {Token}", tokenRedacted);
                    ILogger? nullLogger = null;
                    nullLogger?.LogInformation("msg", holder.SecretToken);
                }
            }
            """;

        var analyzer = new LoggingRawSecretAnalyzer();
        var diagnostics = await RunAnalyzerAsync(analyzer, code);

        diagnostics.Should().HaveCount(1);
        diagnostics[0].Id.Should().Be(DiagnosticIds.LoggingRawSecret);
    }

    [Fact]
    public async Task NonConstantTimeComparisonAnalyzer_EdgeCases_EvaluatesCleanly()
    {
        var code = """
            namespace TestNamespace;
            using System;

            public class TestClass
            {
                public void TestMethod(
                    byte[] plainData1, byte[] plainData2,
                    ReadOnlySpan<byte> authTokenSpan1, ReadOnlySpan<byte> authTokenSpan2,
                    Span<byte> keySpan1, Span<byte> keySpan2,
                    ReadOnlySpan<char> tokenChars1, ReadOnlySpan<char> tokenChars2,
                    string authTokenA)
                {
                    int x = 1;
                    int y = 2;
                    bool numEq = x == y;
                    bool numNeq = x != y;

                    bool plainEq = plainData1 == plainData2;
                    bool plainNeq = plainData1 != plainData2;

                    bool spanEq = authTokenSpan1 == authTokenSpan2;
                    bool spanNeq = keySpan1 != keySpan2;

                    bool charEq = tokenChars1 == tokenChars2;

                    string[] arrays = new string[2];
                    bool elemEq1 = arrays[0] == authTokenA;
                    bool elemEq2 = authTokenA == arrays[0];
                    bool elemBothNull = arrays[0] == arrays[1];

                    bool nullEq1 = null == authTokenA;
                    bool nullEq2 = authTokenA == null;
                }
            }
            """;

        var analyzer = new NonConstantTimeComparisonAnalyzer();
        var diagnostics = await RunAnalyzerAsync(analyzer, code);

        diagnostics.Should().HaveCount(4);
        diagnostics.All(d => d.Id == DiagnosticIds.NonConstantTimeComparison).Should().BeTrue();
    }

    [Fact]
    public async Task UndisposedSecretBufferAnalyzer_EdgeCases_EvaluatesCleanly()
    {
        var code = """
            public class GlobalSecretBuffer
            {
                public static GlobalSecretBuffer Create() => new();
            }

            namespace OtherNamespace
            {
                public class SecretBuffer
                {
                    public static SecretBuffer Create() => new();
                }
            }

            namespace EricksonLopez.Security.Secrets
            {
                public sealed class SecretBuffer : System.IDisposable
                {
                    public static SecretBuffer Create() => new();
                    public void Dispose() { }
                }
            }

            namespace TestNamespace
            {
                public class TestClass
                {
                    public void TestMethod()
                    {
                        var otherNamespaceBuf = OtherNamespace.SecretBuffer.Create();
                        var gBuf = GlobalSecretBuffer.Create();
                        EricksonLopez.Security.Secrets.SecretBuffer uninitBuf;
                        string regularStr = "hello";
                    }
                }
            }
            """;

        var analyzer = new UndisposedSecretBufferAnalyzer();
        var diagnostics = await RunAnalyzerAsync(analyzer, code);

        diagnostics.Should().BeEmpty();
    }

    [Fact]
    public async Task NonConstantTimeComparisonAnalyzer_NonSensitiveNames_ProducesNoDiagnostics()
    {
        var code = """
            namespace TestNamespace;
            public class TestClass
            {
                public bool Compare(byte[] plainData1, byte[] plainData2, string user1, string user2)
                {
                    bool b1 = plainData1 == plainData2;
                    bool b2 = user1 == user2;
                    return b1 && b2;
                }
            }
            """;

        var analyzer = new NonConstantTimeComparisonAnalyzer();
        var diagnostics = await RunAnalyzerAsync(analyzer, code);

        diagnostics.Should().BeEmpty();
    }

    [Fact]
    public void DiagnosticDescriptors_Metadata_AreProperlyConfigured()
    {
        var hardcoded = new HardcodedSecretAnalyzer().SupportedDiagnostics[0];
        hardcoded.Id.Should().Be("ELS0003");
        hardcoded.Title.ToString().Should().Be("Hardcoded secret or key detected");
        hardcoded.Category.Should().Be("Security");
        hardcoded.DefaultSeverity.Should().Be(DiagnosticSeverity.Warning);
        hardcoded.Description.ToString().Should().Be("Hardcoded secrets in source code are a severe security risk. They are committed to source control, visible in binaries, and cannot be rotated without a code change. Use EricksonLopez.Security.HashiCorpVault or EricksonLopez.Security.Azure to retrieve secrets at runtime.");
        hardcoded.HelpLinkUri.Should().Be("https://ericksonlopez.dev/security/analyzers/ELS0003");
        hardcoded.MessageFormat.ToString().Should().Be("'{0}' appears to be a hardcoded secret or cryptographic key. Secrets should be loaded from configuration, environment variables, or a secrets manager (e.g. HashiCorp Vault, Azure Key Vault).");

        var insecurePw = new InsecurePasswordAlgorithmAnalyzer().SupportedDiagnostics[0];
        insecurePw.Id.Should().Be("ELS0004");
        insecurePw.Title.ToString().Should().Be("Insecure algorithm used for password hashing");
        insecurePw.Category.Should().Be("Security");
        insecurePw.DefaultSeverity.Should().Be(DiagnosticSeverity.Error);
        insecurePw.Description.ToString().Should().Be("MD5 and SHA-1/SHA-256 are cryptographic hash functions, not password hashing functions. They are extremely fast, making brute-force attacks trivial even with salting. Use Argon2id (memory-hard) or PBKDF2-SHA512 (high iteration count) instead.");
        insecurePw.HelpLinkUri.Should().Be("https://ericksonlopez.dev/security/analyzers/ELS0004");
        insecurePw.MessageFormat.ToString().Should().Be("'{0}' is not suitable for password hashing. Use Argon2id or PBKDF2-SHA512 via EricksonLopez.Security.");

        var logging = new LoggingRawSecretAnalyzer().SupportedDiagnostics[0];
        logging.Id.Should().Be("ELS0005");
        logging.Title.ToString().Should().Be("Security-sensitive value passed to logger without Redacted<T>");
        logging.Category.Should().Be("Security");
        logging.DefaultSeverity.Should().Be(DiagnosticSeverity.Warning);
        logging.Description.ToString().Should().Be("Passing secrets, tokens, keys, or passwords directly to an ILogger method will write them to the log sink in plaintext, potentially exposing them in log aggregation systems, storage backends, or monitoring dashboards. Wrap the value in Redacted<T> from EricksonLopez.Security to ensure only '[REDACTED]' appears in the log output.");
        logging.HelpLinkUri.Should().Be("https://ericksonlopez.dev/security/analyzers/ELS0005");
        logging.MessageFormat.ToString().Should().Be("'{0}' appears to be a security-sensitive value. Wrap it in Redacted<T> before logging to prevent secret leakage in log sinks.");

        var nonConst = new NonConstantTimeComparisonAnalyzer().SupportedDiagnostics[0];
        nonConst.Id.Should().Be("ELS0001");
        nonConst.Title.ToString().Should().Be("Use constant-time comparison for security-sensitive values");
        nonConst.Category.Should().Be("Security");
        nonConst.DefaultSeverity.Should().Be(DiagnosticSeverity.Warning);
        nonConst.Description.ToString().Should().Be("Equality comparison operators (== and !=) on byte arrays and security-sensitive strings are vulnerable to timing side-channel attacks because they short-circuit on the first non-equal byte. An attacker can measure the time difference to infer the correct value byte by byte.");
        nonConst.HelpLinkUri.Should().Be("https://ericksonlopez.dev/security/analyzers/ELS0001");
        nonConst.MessageFormat.ToString().Should().Be("Comparing '{0}' with '{1}' using '{2}' may be vulnerable to timing side-channel attacks. Use CryptographicOperations.FixedTimeEquals() for byte arrays, or SecurityTokens.ConstantTimeEquals() for strings.");

        var undisposed = new UndisposedSecretBufferAnalyzer().SupportedDiagnostics[0];
        undisposed.Id.Should().Be("ELS0002");
        undisposed.Title.ToString().Should().Be("SecretBuffer must be disposed to zero sensitive memory");
        undisposed.Category.Should().Be("Security");
        undisposed.DefaultSeverity.Should().Be(DiagnosticSeverity.Warning);
        undisposed.Description.ToString().Should().Be("SecretBuffer holds sensitive data in managed memory. If not disposed, the ZeroMemory scrubbing in Dispose() is never called, leaving secret bytes potentially accessible in memory for the lifetime of the process.");
        undisposed.HelpLinkUri.Should().Be("https://ericksonlopez.dev/security/analyzers/ELS0002");
        undisposed.MessageFormat.ToString().Should().Be("'{0}' is a SecretBuffer that should be disposed with 'using' to ensure sensitive bytes are zeroed from memory when no longer needed");
    }
}
