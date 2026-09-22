// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.ArchitectureTests;

using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Reflection;
using EricksonLopez.Security.Abstractions.Primitives;
using EricksonLopez.Security.AspNetCore.Headers;
using EricksonLopez.Security.Cryptography;
using EricksonLopez.Security.Cryptography.Pkcs11.Hsm;
using EricksonLopez.Security.Cryptography.XmlDSig;
using EricksonLopez.Security.Mfa;
using EricksonLopez.Security.Network;
using EricksonLopez.Security.OpenTelemetry;
using EricksonLopez.Security.Pki;
using EricksonLopez.Security.Privacy.Hibp.Clients;
using EricksonLopez.Security.Saml2.Services;
using EricksonLopez.Security.Testing.Logging;
using EricksonLopez.Security.WebAuthn.Fido2.Mds3;
using EricksonLopez.Security.WebAuthn.Fido2.Services;
using EricksonLopez.Security.ZeroTrust;
using NetArchTest.Rules;
using Xunit;

[Trait("Category", "Architecture")]
public sealed class ArchitectureRulesTests
{
    private static readonly Assembly AbstractionsAssembly = typeof(ISecret).Assembly;
    private static readonly Assembly CoreAssembly = typeof(AesGcmEncryptionEngine).Assembly;
    private static readonly Assembly CryptographyAssembly = typeof(ChaCha20Poly1305EncryptionEngine).Assembly;
    private static readonly Assembly MfaAssembly = typeof(TotpService).Assembly;
    private static readonly Assembly NetworkAssembly = typeof(SafeSocketsHttpHandler).Assembly;
    private static readonly Assembly ZeroTrustAssembly = typeof(AbacPolicyEngine).Assembly;
    private static readonly Assembly PkiAssembly = typeof(CertificateChainValidator).Assembly;
    private static readonly Assembly Saml2Assembly = typeof(Saml2Service).Assembly;
    private static readonly Assembly WebAuthnFido2Assembly = typeof(WebAuthnCeremonyService).Assembly;
    private static readonly Assembly WebAuthnFido2Mds3Assembly = typeof(HttpMds3MetadataService).Assembly;
    private static readonly Assembly XmlDSigAssembly = typeof(XmlDigitalSignatureService).Assembly;
    private static readonly Assembly Pkcs11Assembly = typeof(Pkcs11SessionManager).Assembly;
    private static readonly Assembly PrivacyHibpAssembly = typeof(HaveIBeenPwnedClient).Assembly;
    private static readonly Assembly OpenTelemetryAssembly = typeof(SecurityOpenTelemetryExtensions).Assembly;
    private static readonly Assembly AspNetCoreAssembly = typeof(SecurityHeadersMiddleware).Assembly;
    private static readonly Assembly TestingAssembly = typeof(FakeLogger<>).Assembly;

    [Fact]
    [UnconditionalSuppressMessage("Trimming", "IL2026:RequiresUnreferencedCode", Justification = "Reflection used for architectural verification in test harness.")]
    public void Abstractions_ShouldNotDependOn_CoreOrAspNetCoreOrSatelliteLibraries()
    {
        var referencedAssemblies = AbstractionsAssembly.GetReferencedAssemblies()
            .Select(a => a.Name)
            .ToList();

        Assert.DoesNotContain("EricksonLopez.Security", referencedAssemblies);
        Assert.DoesNotContain("EricksonLopez.Security.AspNetCore", referencedAssemblies);
        Assert.DoesNotContain("Microsoft.AspNetCore", referencedAssemblies);
        Assert.DoesNotContain("EricksonLopez.Security.Cryptography", referencedAssemblies);
        Assert.DoesNotContain("EricksonLopez.Security.Network", referencedAssemblies);
    }

    [Fact]
    [UnconditionalSuppressMessage("Trimming", "IL2026:RequiresUnreferencedCode", Justification = "Reflection used for architectural verification in test harness.")]
    public void Core_ShouldNotDependOn_AspNetCoreOrCloudAdapters()
    {
        var referencedAssemblies = CoreAssembly.GetReferencedAssemblies()
            .Select(a => a.Name)
            .ToList();

        Assert.DoesNotContain("EricksonLopez.Security.AspNetCore", referencedAssemblies);
        Assert.DoesNotContain("Microsoft.AspNetCore", referencedAssemblies);
    }

    [Fact]
    [UnconditionalSuppressMessage("Trimming", "IL2026:RequiresUnreferencedCode", Justification = "Reflection used for architectural verification in test harness.")]
    public void DomainAssemblies_ShouldNotDependOn_CloudAdaptersOrAspNetCore()
    {
        var domainAssemblies = new[]
        {
            CoreAssembly,
            CryptographyAssembly,
            MfaAssembly,
            NetworkAssembly,
            ZeroTrustAssembly,
            PkiAssembly,
            Saml2Assembly,
            WebAuthnFido2Assembly,
            WebAuthnFido2Mds3Assembly,
            XmlDSigAssembly,
            Pkcs11Assembly,
            PrivacyHibpAssembly
        };

        var disallowedReferences = new[]
        {
            "EricksonLopez.Security.AspNetCore"
        };

        foreach (var assembly in domainAssemblies)
        {
            var referenced = assembly.GetReferencedAssemblies().Select(a => a.Name).ToList();
            foreach (var disallowed in disallowedReferences)
            {
                Assert.DoesNotContain(disallowed, referenced);
            }
        }
    }

    [Fact]
    public void SecurityEngines_ShouldBeSealed()
    {
        var result = Types.InAssemblies([CoreAssembly, CryptographyAssembly, ZeroTrustAssembly])
            .That()
            .AreClasses()
            .And()
            .AreNotAbstract()
            .And()
            .HaveNameEndingWith("Engine")
            .Should()
            .BeSealed()
            .GetResult();

        Assert.True(result.IsSuccessful, string.Join(", ", result.FailingTypeNames ?? []));
    }

    [Fact]
    public void SecurityServices_ShouldBeSealed()
    {
        var result = Types.InAssemblies([MfaAssembly, PkiAssembly, Saml2Assembly, WebAuthnFido2Assembly, WebAuthnFido2Mds3Assembly, XmlDSigAssembly])
            .That()
            .AreClasses()
            .And()
            .AreNotAbstract()
            .And()
            .HaveNameEndingWith("Service")
            .Should()
            .BeSealed()
            .GetResult();

        Assert.True(result.IsSuccessful, string.Join(", ", result.FailingTypeNames ?? []));
    }

    [Fact]
    public void Interfaces_ShouldStartWith_I()
    {
        var result = Types.InAssemblies([
            AbstractionsAssembly,
            CoreAssembly,
            CryptographyAssembly,
            MfaAssembly,
            ZeroTrustAssembly,
            PkiAssembly,
            NetworkAssembly,
            Saml2Assembly,
            WebAuthnFido2Assembly,
            WebAuthnFido2Mds3Assembly,
            XmlDSigAssembly,
            Pkcs11Assembly,
            PrivacyHibpAssembly,
            AspNetCoreAssembly,
            TestingAssembly
        ])
            .That()
            .AreInterfaces()
            .Should()
            .HaveNameStartingWith("I")
            .GetResult();

        Assert.True(result.IsSuccessful, "All interfaces must follow the 'I' prefix naming convention.");
    }

}
