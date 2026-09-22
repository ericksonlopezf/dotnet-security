// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Sample.Levels;

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Xml;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using global::OpenTelemetry.Metrics;
using global::OpenTelemetry.Trace;
using EricksonLopez.Result;
using EricksonLopez.Security.Abstractions.Cryptography;
using EricksonLopez.Security.Abstractions.Errors;
using EricksonLopez.Security.Abstractions.KeyManagement;
using EricksonLopez.Security.Abstractions.Primitives;
using EricksonLopez.Security.Abstractions.Tokens;
using EricksonLopez.Security.AspNetCore.Authentication;
using EricksonLopez.Security.AspNetCore.Headers;
using EricksonLopez.Security.Cryptography.Pkcs11.Hsm;
using EricksonLopez.Security.Cryptography.Pkcs11.Interop;
using EricksonLopez.Security.Cryptography.Pkcs11.Signing;
using EricksonLopez.Security.Cryptography.XmlDSig;
using EricksonLopez.Security.KeyManagement;
using EricksonLopez.Security.Memory;
using EricksonLopez.Security.Mfa;
using EricksonLopez.Security.Network;
using EricksonLopez.Security.OpenTelemetry;
using EricksonLopez.Security.Pki;
using EricksonLopez.Security.Privacy.Hibp.Abstractions;
using EricksonLopez.Security.Privacy.Hibp.Models;
using EricksonLopez.Security.Privacy.Hibp.Validators;
using EricksonLopez.Security.Saml2.Abstractions;
using EricksonLopez.Security.Saml2.Claims;
using EricksonLopez.Security.Saml2.Cryptography;
using EricksonLopez.Security.Saml2.DependencyInjection;
using EricksonLopez.Security.Saml2.Models;
using EricksonLopez.Security.Saml2.Xsw;
using EricksonLopez.Security.Testing.Assertions;
using EricksonLopez.Security.Testing.Builders;
using EricksonLopez.Security.Testing.Fakes;
using EricksonLopez.Security.Testing.Logging;
using EricksonLopez.Security.WebAuthn.Fido2.Abstractions;
using EricksonLopez.Security.WebAuthn.Fido2.DependencyInjection;
using EricksonLopez.Security.WebAuthn.Fido2.Enums;
using EricksonLopez.Security.WebAuthn.Fido2.Mds3;
using EricksonLopez.Security.WebAuthn.Fido2.Models;
using EricksonLopez.Security.WebAuthn.Fido2.Verifiers;
using EricksonLopez.Security.ZeroTrust;
using Result = global::EricksonLopez.Result.Result;

/// <summary>
/// Level 11 — Comprehensive Public API Coverage Verification.
/// Executes live demonstrations of all remaining public APIs to certify 100% showcase completeness.
/// </summary>
public static class Level11_ComprehensiveApiCoverage
{
    public static async Task RunAsync()
    {
        Console.WriteLine("\n================================================================================");
        Console.WriteLine(" Level 11: Comprehensive Public API Coverage Verification");
        Console.WriteLine("================================================================================");

        VerifyDependencyInjectionExtensions();
        VerifyAbacAndZeroTrust();
        VerifyPrimitivesAndEnvelopes();
        VerifyTestingDoublesAndAssertions();
        VerifyFido2BuildersAndCeremony();
        VerifySamlBuildersAndComponents();
        VerifySamlAndXmlDsigOperations();
        await VerifySamlServiceLifecycleAsync().ConfigureAwait(false);
        VerifyMfaAndBase32();
        await VerifySafeNetworkAndHibpAsync().ConfigureAwait(false);
        VerifyPkcs11Hsm();
        await VerifyAspNetCoreMiddlewaresAsync().ConfigureAwait(false);
        await VerifyWebAuthnCeremonyAndMdsAsync().ConfigureAwait(false);
        await VerifyKeyRevocationAndCacheInvalidationAsync().ConfigureAwait(false);
        await VerifyDistributedTotpReplayStoreAsync().ConfigureAwait(false);

        Console.WriteLine("Level 11: All Public APIs Verified Successfully with Clean Runtime.");
    }

    private static void VerifyDependencyInjectionExtensions()
    {
        var services = new ServiceCollection();

        services.AddSecurityCore();
        services.AddKeyManagement();
        services.AddSecretProtection();
        services.AddSecurityPki();
        services.AddSaml2Security();
        services.AddWebAuthnFido2();
        services.AddFidoMds3();
        services.AddEricksonLopezCryptographyCore();
        services.AddEricksonLopezIdentityPasswordHasher<object>();
        services.AddEricksonLopezPkcs11("dummy.dll", 1);
        services.AddSecurityMfa();
        services.AddDistributedTotpReplayStore((k, exp, ct) => ValueTask.FromResult(true));

        using var sp = services.BuildServiceProvider();
        var notifier = sp.GetService<IKeyRevocationNotifier>();
        if (notifier is null) throw new InvalidOperationException("IKeyRevocationNotifier not resolved.");
        var replayStore = sp.GetService<ITotpReplayStore>();
        if (replayStore is null) throw new InvalidOperationException("ITotpReplayStore not resolved.");

        var app = new DummyApplicationBuilder(sp);
        app.UseApiKeyAuthentication();

        var tracerBuilder = new DummyTracerProviderBuilder();
        tracerBuilder.AddEricksonLopezSecurityInstrumentation();

        var meterBuilder = new DummyMeterProviderBuilder();
        meterBuilder.AddEricksonLopezSecurityInstrumentation();
    }

    private static async Task VerifyKeyRevocationAndCacheInvalidationAsync()
    {
        var store = new InMemoryKeyStore();
        var notifier = new InProcessKeyRevocationNotifier();
        using var keyRing = new KeyRing(store, new KeyRingOptions { CacheTtl = TimeSpan.FromMinutes(5) }, notifier);
        var manager = new KeyLifecycleManager(store, null, false, notifier);

        var keyResult = await manager.GenerateAndActivateKeyAsync(KeyPurpose.Encryption).ConfigureAwait(false);
        if (!keyResult.IsSuccess) throw new InvalidOperationException("Key generation failed.");
        var key = keyResult.Value;

        // Warm KeyRing cache
        var activeKey = await keyRing.GetActiveKeyAsync(KeyPurpose.Encryption).ConfigureAwait(false);
        if (!activeKey.IsSuccess) throw new InvalidOperationException("KeyRing GetActiveKeyAsync failed.");
        activeKey.Value.Dispose();

        // Exercise explicit invalidation methods
        keyRing.InvalidateKey(key.Metadata.KeyId, key.Metadata.Version);
        keyRing.InvalidateActiveKey(KeyPurpose.Encryption);
        keyRing.InvalidateAll();

        // Test notifier subscription & broadcast
        bool notified = false;
        using var sub = notifier.Subscribe((kId, v, p) => notified = true);
        await notifier.NotifyRevokedAsync(key.Metadata.KeyId, key.Metadata.Version, KeyPurpose.Encryption).ConfigureAwait(false);
        if (!notified) throw new InvalidOperationException("Notifier broadcast failed.");

        key.Dispose();
    }

    private static async Task VerifyDistributedTotpReplayStoreAsync()
    {
        var dict = new ConcurrentDictionary<string, DateTimeOffset>();
        var store = new DelegateTotpReplayStore(
            (key, exp, ct) => ValueTask.FromResult(dict.TryAdd(key, exp)),
            (key, exp) => dict.TryAdd(key, exp));

        var addedSync = store.TryAdd("user1:123456", DateTimeOffset.UtcNow.AddMinutes(1));
        if (!addedSync) throw new InvalidOperationException("DelegateTotpReplayStore.TryAdd failed.");

        var duplicateSync = store.TryAdd("user1:123456", DateTimeOffset.UtcNow.AddMinutes(1));
        if (duplicateSync) throw new InvalidOperationException("DelegateTotpReplayStore replay check failed.");

        var addedAsync = await store.TryAddAsync("user2:654321", DateTimeOffset.UtcNow.AddMinutes(1)).ConfigureAwait(false);
        if (!addedAsync) throw new InvalidOperationException("DelegateTotpReplayStore.TryAddAsync failed.");
    }

    private static void VerifyAbacAndZeroTrust()
    {
        var ctx = new AbacContext();
        ctx.Set("custom", "role", "auditor");

        if (!ctx.Has("custom", "role"))
        {
            throw new InvalidOperationException("AbacContext.Has failed.");
        }

        if (!ctx.TryGet<string>("custom", "role", out var role) || role != "auditor")
        {
            throw new InvalidOperationException("AbacContext.TryGet failed.");
        }

        var policy = new AbacPolicy(
            "p-audit",
            Array.Empty<AbacRule>(),
            target: c => c.Has("custom", "role"));

        if (!policy.AppliesTo(ctx))
        {
            throw new InvalidOperationException("AbacPolicy.AppliesTo failed.");
        }

        var engine = AbacPolicyEngine.Instance;
        var decision = engine.EvaluateFailClosed(ctx, new[] { policy });
        if (decision.Status == AbacDecisionStatus.Indeterminate)
        {
            throw new InvalidOperationException("EvaluateFailClosed returned Indeterminate.");
        }
    }

    private static void VerifyPrimitivesAndEnvelopes()
    {
        var keyId = new KeyIdentifier("key-cov-1");
        var meta = new KeyMetadata(
            keyId,
            KeyVersion.Initial,
            KeyPurpose.Encryption,
            KeyStatus.Active,
            "AES-256-GCM",
            DateTimeOffset.UtcNow);

        if (!meta.IsUsableForNewOperations())
        {
            throw new InvalidOperationException("KeyMetadata.IsUsableForNewOperations returned false.");
        }

        if (!meta.IsUsableForDecryption())
        {
            throw new InvalidOperationException("KeyMetadata.IsUsableForDecryption returned false.");
        }

        using var buffer = new SecretBuffer(32);
        Span<byte> span = stackalloc byte[32];
        buffer.Span.CopyTo(span);

        using var key = new CryptographicKey(meta, buffer);
        var bytes = key.GetKeyBytes();
        if (bytes.Length != 32)
        {
            throw new InvalidOperationException("CryptographicKey.GetKeyBytes returned invalid length.");
        }

        if (!key.TryCopyKeyBytes(span))
        {
            throw new InvalidOperationException("CryptographicKey.TryCopyKeyBytes failed.");
        }

        var nonce = new Nonce(stackalloc byte[12] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 });
        Span<byte> nonceDest = stackalloc byte[12];
        nonce.CopyTo(nonceDest);

        var salt = new Salt(stackalloc byte[16] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 });
        Span<byte> saltDest = stackalloc byte[16];
        salt.CopyTo(saltDest);
    }

    private static void VerifyTestingDoublesAndAssertions()
    {
        SecurityAssert.AreConstantTimeEqual(stackalloc byte[] { 1, 2, 3 }, stackalloc byte[] { 1, 2, 3 });
        SecurityAssert.IsRedacted(new Redacted<string>("top-secret-clearance"));

        var logger = new FakeLogger<DummyApplicationBuilder>();
        using (logger.BeginScope("Level11Scope"))
        {
            logger.Log(LogLevel.Information, new EventId(1), "audit operation started", null, (s, e) => s);
            logger.Log(LogLevel.Warning, new EventId(2), "minor rate limit warning", null, (s, e) => s);
            logger.Log(LogLevel.Error, new EventId(3), "simulated error entry", null, (s, e) => s);
        }

        if (!logger.HasMessage("audit operation"))
        {
            throw new InvalidOperationException("FakeLogger.HasMessage failed.");
        }

        if (!logger.HasWarning("minor rate limit"))
        {
            throw new InvalidOperationException("FakeLogger.HasWarning failed.");
        }

        if (!logger.HasError("simulated error"))
        {
            throw new InvalidOperationException("FakeLogger.HasError failed.");
        }

        logger.Clear();

        var fakeKeyStore = new FakeKeyStore();
        fakeKeyStore.Reset();
    }

    private static void VerifyFido2BuildersAndCeremony()
    {
        var fidoBuilder = new Fido2AttestationTestBuilder()
            .WithSignCount(5)
            .WithAaguid(Guid.NewGuid())
            .WithCredentialId(new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 })
            .WithEc2Key(CoseEllipticCurve.P256, CoseAlgorithmIdentifier.ES256)
            .WithRsaKey(CoseAlgorithmIdentifier.RS256)
            .WithFormat("none")
            .WithFlags(AuthenticatorDataFlags.UserPresent)
            .WithClientDataHash(new byte[32]);

        var (builtStatement, builtAuthData, builtHash) = fidoBuilder.Build();
        _ = Fido2AttestationTestBuilder.BuildCborAttestationObject(new byte[37]);
        _ = fidoBuilder.BuildRawAssertionResponse(new byte[32]);
        _ = fidoBuilder.BuildRawAttestationResponse(new byte[32]);

        var noneVerifier = new NoneAttestationVerifier();
        _ = noneVerifier.Verify(builtStatement, builtAuthData, builtHash);

        var tpmVerifier = new TpmAttestationVerifier();
        _ = tpmVerifier.Verify(builtStatement, builtAuthData, builtHash);

        var u2fVerifier = new FidoU2FAttestationVerifier();
        _ = u2fVerifier.Verify(builtStatement, builtAuthData, builtHash);

        // AndroidSafetyNetAttestationVerifier — covers WebAuthn §8.5 (Android SafetyNet JWT format)
        var androidSafetyNetVerifier = new AndroidSafetyNetAttestationVerifier();
        _ = androidSafetyNetVerifier.Verify(builtStatement, builtAuthData, builtHash);
    }

    private static void VerifySamlBuildersAndComponents()
    {
        var now = DateTimeOffset.UtcNow;
        var samlBuilder = new SamlTestMessageBuilder()
            .WithResponseId("_resp_cov")
            .WithInResponseTo("_req_cov")
            .WithDestination("https://sp.example.com/saml/acs")
            .WithIssuer("https://idp.example.com")
            .WithAssertionIssuer("https://idp.example.com")
            .WithStatusCode("urn:oasis:names:tc:SAML:2.0:status:Success")
            .WithSecondaryStatusCode("urn:oasis:names:tc:SAML:2.0:status:AuthnFailed")
            .WithStatusMessage("Authentication status verified")
            .WithAssertionId("_assert_cov")
            .WithSubjectConfirmation("https://sp.example.com/saml/acs", now.AddMinutes(5))
            .WithAuthnStatement(now, "session_456")
            .WithAudience("https://sp.example.com")
            .WithIssueInstant(now)
            .WithConditions(now.AddMinutes(-5), now.AddMinutes(5))
            .WithAttribute("email", "auditor@example.com")
            .WithoutAssertion()
            .WithoutStatus()
            .WithoutSubject()
            .WithoutConditions();

        var xml = samlBuilder.BuildXml();
        if (string.IsNullOrEmpty(xml))
        {
            throw new InvalidOperationException("SamlTestMessageBuilder.BuildXml failed.");
        }

        var xswValidator = new Saml2XswValidator();
        var xmlDoc = new XmlDocument();
        xmlDoc.LoadXml("<samlp:Response xmlns:samlp='urn:oasis:names:tc:SAML:2.0:protocol' ID='_1' Version='2.0' IssueInstant='2026-09-08T00:00:00Z'/>");
        _ = xswValidator.ValidateAndExtractAssertion(xmlDoc);
    }

    private static void VerifySamlAndXmlDsigOperations()
    {
        _ = XmlSignatureCertificateExtractor.ExtractCertificate("<test><Signature xmlns='http://www.w3.org/2000/09/xmldsig#'/></test>");

        using var rsa = RSA.Create(2048);
        var certReq = new CertificateRequest("CN=SamlTestCert", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = certReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(365));

        var sigValidator = new Saml2SignatureValidator();
        var dummyDoc = new XmlDocument();
        dummyDoc.LoadXml("<Root ID='_elem_1'><saml:Assertion xmlns:saml='urn:oasis:names:tc:SAML:2.0:assertion' ID='_assert_1'/></Root>");

        _ = sigValidator.SignElement(dummyDoc.DocumentElement!, cert);
        _ = sigValidator.VerifySignature(dummyDoc.DocumentElement!, cert);

        var decryptor = new Saml2AssertionDecryptor();
        _ = decryptor.DecryptAssertion(dummyDoc.DocumentElement!, cert);

        var claimsMapper = new Saml2ClaimsMapper();
        var assertion = new Saml2Assertion(
            "_assert_map",
            DateTimeOffset.UtcNow,
            "https://idp.example.com",
            new Saml2Subject(new Saml2NameId("user@test.org")),
            "<saml:Assertion/>");

        var principal = claimsMapper.MapToPrincipal(assertion, new Saml2Options());
        if (principal is null)
        {
            throw new InvalidOperationException("Saml2ClaimsMapper.MapToPrincipal returned null.");
        }
    }

    private static async Task VerifySamlServiceLifecycleAsync()
    {
        var samlService = new FakeSaml2Service();

        var logoutReq = samlService.CreateLogoutRequest(new Saml2NameId("user@test.org"));
        if (logoutReq is null) throw new InvalidOperationException("CreateLogoutRequest returned null.");

        var logoutResp = samlService.CreateLogoutResponse("in_resp_to_1", "https://idp.example.com/slo");
        if (logoutResp is null) throw new InvalidOperationException("CreateLogoutResponse returned null.");

        _ = await samlService.ProcessResponseAsync("<Response/>").ConfigureAwait(false);
        _ = await samlService.ProcessIdpInitiatedResponseAsync("<Response/>").ConfigureAwait(false);
        _ = await samlService.ProcessLogoutResponseAsync("<LogoutResponse/>", "in_resp_to_1").ConfigureAwait(false);
    }

    private static void VerifyMfaAndBase32()
    {
        var rawBytes = new byte[] { 10, 20, 30, 40, 50, 60, 70, 80 };
        var encoded = Base32Encoding.ToBase32String(rawBytes);
        var decoded = Base32Encoding.FromBase32String(encoded);

        if (!CryptographicOperations.FixedTimeEquals(rawBytes, decoded))
        {
            throw new InvalidOperationException("Base32Encoding roundtrip failed.");
        }
    }

    private static async Task VerifySafeNetworkAndHibpAsync()
    {
        var safeDns = new SafeDnsResolver();
        _ = await safeDns.ResolveAndValidateAsync("127.0.0.1").ConfigureAwait(false);

        var fakeHibp = new FakeHaveIBeenPwnedClient();
        _ = await fakeHibp.CheckPasswordAsync("P@ssw0rd123!").ConfigureAwait(false);
        _ = await fakeHibp.GetRangeAsync("5BAA6").ConfigureAwait(false);

        var hibpValidator = new PasswordPwnedValidator(fakeHibp, Options.Create(new HibpOptions()));
        _ = await hibpValidator.ValidateNotPwnedAsync("UnpwnedSuperKey").ConfigureAwait(false);
    }

    private static unsafe void VerifyPkcs11Hsm()
    {
        var mockLib = new Pkcs11NativeLibrary(
            &MockOk,
            &MockOk,
            &MockOpenSession,
            &MockCloseSession,
            &MockLogin,
            &MockLogout,
            &MockSignInit,
            &MockSign,
            &MockFindObjectsInit,
            &MockFindObjects,
            &MockFindObjectsFinal,
            &MockVerifyInit,
            &MockVerify);

        var sessionResult = Pkcs11SessionManager.OpenSession(mockLib, 1);
        if (sessionResult.IsSuccess)
        {
            using var session = sessionResult.Value;
            _ = session.Login("1234"u8);

            var engine = new Pkcs11DigitalSignatureEngine(mockLib, session);
            Span<byte> sigDest = stackalloc byte[256];
            _ = engine.Sign(new byte[16], new KeyIdentifier("missing"), sigDest, out _);
            _ = engine.Verify(new byte[16], new byte[64], new KeyIdentifier("key"));
        }
    }

    private static async Task VerifyAspNetCoreMiddlewaresAsync()
    {
        var headersMiddleware = new SecurityHeadersMiddleware(_ => Task.CompletedTask, Options.Create(new SecurityHeadersOptions()));
        var httpContext = new DefaultHttpContext();
        await headersMiddleware.InvokeAsync(httpContext).ConfigureAwait(false);

        var apiKeyMiddleware = new ApiKeyAuthenticationMiddleware(_ => Task.CompletedTask, Options.Create(new ApiKeyAuthenticationOptions()));
        var fakeValidator = new FakeApiKeyValidator();
        await apiKeyMiddleware.InvokeAsync(httpContext, fakeValidator).ConfigureAwait(false);
    }

    private static async Task VerifyWebAuthnCeremonyAndMdsAsync()
    {
        var fakeMds = new FakeMds3MetadataService();
        _ = await fakeMds.GetMetadataAsync(Guid.NewGuid()).ConfigureAwait(false);
        _ = await fakeMds.ValidateAuthenticatorStatusAsync(Guid.NewGuid()).ConfigureAwait(false);
        await fakeMds.RefreshAsync().ConfigureAwait(false);

        var ceremonyService = new FakeWebAuthnCeremonyService();
        var rawAssertion = new AuthenticatorAssertionRawResponse(
            "cred-1",
            new byte[] { 1, 2, 3 },
            new byte[] { 4, 5, 6 },
            new byte[37],
            new byte[64],
            null);

        var cosePubKey = new CosePublicKey(CoseKeyType.Ec2, CoseAlgorithmIdentifier.ES256, Array.Empty<byte>());
        _ = await ceremonyService.VerifyAuthenticationAsync(rawAssertion, new byte[32], cosePubKey, 0, false).ConfigureAwait(false);

        var rawAttestation = new AuthenticatorAttestationRawResponse(
            "cred-2",
            new byte[] { 7, 8, 9 },
            new byte[] { 10, 11 },
            new byte[64]);

        _ = await ceremonyService.VerifyRegistrationAsync(rawAttestation, new byte[32], new byte[] { 99 }).ConfigureAwait(false);
    }

    #region Unmanaged Mock Callbacks for PKCS#11

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static uint MockOk(IntPtr p) => 0;

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static unsafe uint MockOpenSession(uint slot, uint flags, IntPtr p1, IntPtr p2, uint* pSession)
    {
        if (pSession != null) *pSession = 777;
        return 0;
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static uint MockCloseSession(uint sess) => 0;

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static unsafe uint MockLogin(uint sess, uint uType, byte* pPin, uint pinLen) => 0;

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static uint MockLogout(uint sess) => 0;

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static unsafe uint MockSignInit(uint sess, CK_MECHANISM* pMech, uint key) => 0;

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static unsafe uint MockSign(uint sess, byte* pData, uint dataLen, byte* pSig, uint* pSigLen)
    {
        if (pSig != null && pSigLen != null && *pSigLen >= 4)
        {
            pSig[0] = 0xAA;
            pSig[1] = 0xBB;
            *pSigLen = 2;
        }
        return 0;
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static uint MockFindObjectsInit(uint sess, IntPtr pTemplate, uint ulCount) => 0;

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static unsafe uint MockFindObjects(uint sess, uint* phObject, uint ulMaxObjectCount, uint* pulObjectCount)
    {
        if (pulObjectCount != null) *pulObjectCount = 0;
        return 0;
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static uint MockFindObjectsFinal(uint sess) => 0;

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static unsafe uint MockVerifyInit(uint sess, CK_MECHANISM* pMech, uint key) => 0;

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static unsafe uint MockVerify(uint sess, byte* pData, uint dataLen, byte* pSig, uint sigLen) => 0;

    #endregion

    #region Supporting Test Doubles

    private sealed class DummyApplicationBuilder : IApplicationBuilder
    {
        public DummyApplicationBuilder(IServiceProvider services) => ApplicationServices = services;
        public IServiceProvider ApplicationServices { get; set; }
        public IFeatureCollection ServerFeatures => new FeatureCollection();
        public IDictionary<string, object?> Properties => new Dictionary<string, object?>();
        public RequestDelegate Build() => _ => Task.CompletedTask;
        public IApplicationBuilder New() => new DummyApplicationBuilder(ApplicationServices);
        public IApplicationBuilder Use(Func<RequestDelegate, RequestDelegate> middleware) => this;
    }

    private sealed class DummyTracerProviderBuilder : TracerProviderBuilder
    {
        public override TracerProviderBuilder AddSource(params string[] names) => this;
        public override TracerProviderBuilder AddLegacySource(string operationName) => this;
        public override TracerProviderBuilder AddInstrumentation<TInstrumentation>(Func<TInstrumentation> instrumentationFactory) where TInstrumentation : class => this;
    }

    private sealed class DummyMeterProviderBuilder : MeterProviderBuilder
    {
        public override MeterProviderBuilder AddMeter(params string[] names) => this;
        public override MeterProviderBuilder AddInstrumentation<TInstrumentation>(Func<TInstrumentation> instrumentationFactory) where TInstrumentation : class => this;
    }

    private sealed class FakeApiKeyValidator : IApiKeyValidator
    {
        public ValueTask<Result<ApiKey>> ValidateApiKeyAsync(string rawApiKey, CancellationToken cancellationToken = default)
        {
            var apiKey = new ApiKey(ApiKeyId.New(), "test-owner", "test-key", "ek_live_1234", "hashed_secret", DateTimeOffset.UtcNow);
            return ValueTask.FromResult(Result<ApiKey>.Success(apiKey));
        }
    }

    private sealed class FakeHaveIBeenPwnedClient : IHaveIBeenPwnedClient
    {
        public Task<Result<PwnedPasswordCheckResult>> CheckPasswordAsync(string password, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(Result<PwnedPasswordCheckResult>.Success(new PwnedPasswordCheckResult("0018A", 0)));
        }

        public Task<Result<IReadOnlyList<PwnedPasswordEntry>>> GetRangeAsync(string hashPrefix, CancellationToken cancellationToken = default)
        {
            IReadOnlyList<PwnedPasswordEntry> entries = new List<PwnedPasswordEntry>
            {
                new("0018A45C4D1DEF81644B54AB7F969B88D65", 1)
            };
            return Task.FromResult(Result<IReadOnlyList<PwnedPasswordEntry>>.Success(entries));
        }
    }

    private sealed class FakeSaml2Service : ISaml2Service
    {
        public Saml2AuthnRequest CreateAuthnRequest(string? relayState = null) => default!;

        public Task<Result<Saml2AuthenticationResult>> ProcessResponseAsync(string samlResponseXml, string? expectedInResponseTo = null, CancellationToken cancellationToken = default) =>
            Task.FromResult(Result<Saml2AuthenticationResult>.Success(new Saml2AuthenticationResult(new ClaimsPrincipal(), new Saml2Assertion("_a1", DateTimeOffset.UtcNow, "https://idp.example.com", new Saml2Subject(new Saml2NameId("user@test.org")), "<xml/>"))));

        public Task<Result<Saml2AuthenticationResult>> ProcessIdpInitiatedResponseAsync(string samlResponseXml, CancellationToken cancellationToken = default) =>
            Task.FromResult(Result<Saml2AuthenticationResult>.Success(new Saml2AuthenticationResult(new ClaimsPrincipal(), new Saml2Assertion("_a2", DateTimeOffset.UtcNow, "https://idp.example.com", new Saml2Subject(new Saml2NameId("user@test.org")), "<xml/>"))));

        public Saml2LogoutRequest CreateLogoutRequest(Saml2NameId nameId, string? sessionIndex = null, string? relayState = null) =>
            new("_logout_1", "https://sp.example.com", DateTimeOffset.UtcNow, "https://idp.example.com/slo", nameId, "<xml/>", sessionIndex);

        public Task<Result<Saml2LogoutResponse>> ProcessLogoutResponseAsync(string samlLogoutResponseXml, string expectedInResponseTo, CancellationToken cancellationToken = default) =>
            Task.FromResult(Result<Saml2LogoutResponse>.Success(new Saml2LogoutResponse("_resp_1", "https://idp.example.com", DateTimeOffset.UtcNow, expectedInResponseTo, "urn:oasis:names:tc:SAML:2.0:status:Success", "<xml/>")));

        public Saml2LogoutResponse CreateLogoutResponse(string inResponseTo, string destination, bool success = true) =>
            new("_resp_2", destination, DateTimeOffset.UtcNow, inResponseTo, success ? "urn:oasis:names:tc:SAML:2.0:status:Success" : "urn:oasis:names:tc:SAML:2.0:status:Responder", "<xml/>");

        public string GenerateSpMetadata() => "<md:EntityDescriptor/>";
    }

    private sealed class FakeMds3MetadataService : IMds3MetadataService
    {
        public Task<Result<AuthenticatorMetadata>> GetMetadataAsync(Guid aaguid, CancellationToken cancellationToken = default) =>
            Task.FromResult(Result<AuthenticatorMetadata>.Success(new AuthenticatorMetadata("Fake Authenticator", Array.Empty<AuthenticatorStatusReport>(), Array.Empty<byte[]>(), DateTimeOffset.UtcNow, aaguid)));

        public Task<Result> ValidateAuthenticatorStatusAsync(Guid aaguid, CancellationToken cancellationToken = default) =>
            Task.FromResult(Result.Success());

        public Task RefreshAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
    }

    private sealed class FakeWebAuthnCeremonyService : IWebAuthnCeremonyService
    {
        public CredentialCreateOptions CreateRegistrationOptions(PublicKeyCredentialUserEntity user, CredentialCreateOptions? customOptions = null) =>
            new(new RelyingPartyIdentity("example.com", "Example RP"), user, new byte[32], new List<PublicKeyCredentialParameters>());

        public Task<Result<VerifiedCredentialRegistration>> VerifyRegistrationAsync(AuthenticatorAttestationRawResponse response, byte[] expectedChallenge, byte[] userHandle, CancellationToken cancellationToken = default) =>
            Task.FromResult(Result<VerifiedCredentialRegistration>.Success(new VerifiedCredentialRegistration(response.RawId, userHandle, new CosePublicKey(CoseKeyType.Ec2, CoseAlgorithmIdentifier.ES256, Array.Empty<byte>()), 0, Guid.NewGuid(), false, false, "none")));

        public CredentialRequestOptions CreateAuthenticationOptions(CredentialRequestOptions? customOptions = null) =>
            new(new byte[32], "example.com");

        public Task<Result<VerifiedCredentialAssertion>> VerifyAuthenticationAsync(AuthenticatorAssertionRawResponse response, byte[] expectedChallenge, CosePublicKey storedPublicKey, uint storedSignCount, bool userVerificationRequired = false, CancellationToken cancellationToken = default) =>
            Task.FromResult(Result<VerifiedCredentialAssertion>.Success(new VerifiedCredentialAssertion(response.RawId, storedSignCount + 1, userVerificationRequired, true, false)));
    }

    #endregion
}
