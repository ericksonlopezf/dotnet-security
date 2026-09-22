// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Cryptography.Pkcs11.Tests;

using System;
using System.Linq;
using AwesomeAssertions;
using EricksonLopez.Security.Abstractions.Cryptography;
using EricksonLopez.Security.Cryptography.Pkcs11.Hsm;
using EricksonLopez.Security.Cryptography.Pkcs11.Interop;
using EricksonLopez.Security.Cryptography.Pkcs11.Signing;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

public sealed class Pkcs11ConstantsAndDiTests
{
    [Fact]
    public void Pkcs11Constants_Values_MatchCryptokiSpecification()
    {
        Pkcs11Constants.CKR_OK.Should().Be(0x00000000u);
        Pkcs11Constants.CKR_SESSION_HANDLE_INVALID.Should().Be(0x000000B3u);

        Pkcs11Constants.CKF_SERIAL_SESSION.Should().Be(0x00000004u);
        Pkcs11Constants.CKF_RW_SESSION.Should().Be(0x00000002u);

        Pkcs11Constants.CKS_RO_PUBLIC_SESSION.Should().Be(0u);
        Pkcs11Constants.CKS_RO_USER_FUNCTIONS.Should().Be(1u);
        Pkcs11Constants.CKS_RW_PUBLIC_SESSION.Should().Be(2u);
        Pkcs11Constants.CKS_RW_USER_FUNCTIONS.Should().Be(3u);

        Pkcs11Constants.CKU_SO.Should().Be(0u);
        Pkcs11Constants.CKU_USER.Should().Be(1u);

        Pkcs11Constants.CKM_RSA_PKCS.Should().Be(0x00000001u);
        Pkcs11Constants.CKM_SHA256_RSA_PKCS.Should().Be(0x00000040u);
        Pkcs11Constants.CKM_ECDSA.Should().Be(0x00001041u);
    }

    [Fact]
    public void CK_MECHANISM_Struct_FieldsCanBeAssigned()
    {
        var mech = new CK_MECHANISM
        {
            mechanism = Pkcs11Constants.CKM_SHA256_RSA_PKCS,
            pParameter = IntPtr.Zero,
            ulParameterLen = 0
        };

        mech.mechanism.Should().Be(Pkcs11Constants.CKM_SHA256_RSA_PKCS);
        mech.pParameter.Should().Be(IntPtr.Zero);
        mech.ulParameterLen.Should().Be(0u);
    }

    [Fact]
    public void DependencyInjection_AddEricksonLopezPkcs11_RegistersDescriptors()
    {
        var services = new ServiceCollection();
        services.AddEricksonLopezPkcs11("mock_pkcs11.dll", 1);

        services.Any(d => d.ServiceType == typeof(Pkcs11NativeLibrary)).Should().BeTrue();
        services.Any(d => d.ServiceType == typeof(Pkcs11SessionManager)).Should().BeTrue();
        services.Any(d => d.ServiceType == typeof(IDigitalSignatureEngine) && d.ImplementationType == typeof(Pkcs11DigitalSignatureEngine)).Should().BeTrue();
    }

    [Fact]
    public void DependencyInjection_AddEricksonLopezPkcs11_Guards_ThrowOnInvalidInput()
    {
        Assert.Throws<ArgumentNullException>(() => ((IServiceCollection)null!).AddEricksonLopezPkcs11("path", 1));
        Assert.Throws<ArgumentNullException>(() => new ServiceCollection().AddEricksonLopezPkcs11(null!, 1));
        Assert.Throws<ArgumentException>(() => new ServiceCollection().AddEricksonLopezPkcs11("", 1));
        Assert.Throws<ArgumentException>(() => new ServiceCollection().AddEricksonLopezPkcs11("   ", 1));
    }

    [Fact]
    public void DependencyInjection_ResolveServices_WhenSessionSucceeds_ReturnsInstances()
    {
        var services = new ServiceCollection();
        services.AddEricksonLopezPkcs11("mock.dll", 1);

        var mockLib = Pkcs11HsmAndSignatureEngineTests.CreateMockNativeLibrary();
        var nativeLibDesc = services.First(d => d.ServiceType == typeof(Pkcs11NativeLibrary));
        services.Remove(nativeLibDesc);
        services.AddSingleton(mockLib);

        var sp = services.BuildServiceProvider();

        var session = sp.GetRequiredService<Pkcs11SessionManager>();
        session.Should().NotBeNull();
        session.SessionId.Should().Be(999u);

        var engine = sp.GetRequiredService<IDigitalSignatureEngine>();
        engine.Should().NotBeNull();
        engine.Should().BeOfType<Pkcs11DigitalSignatureEngine>();
    }

    [Fact]
    public void DependencyInjection_ResolveServices_WhenSessionFails_ThrowsInvalidOperationException()
    {
        var services = new ServiceCollection();
        services.AddEricksonLopezPkcs11("mock.dll", 1);

        var mockLib = Pkcs11HsmAndSignatureEngineTests.CreateFailingSessionMockNativeLibrary();
        var nativeLibDesc = services.First(d => d.ServiceType == typeof(Pkcs11NativeLibrary));
        services.Remove(nativeLibDesc);
        services.AddSingleton(mockLib);

        var sp = services.BuildServiceProvider();

        Action act = () => _ = sp.GetRequiredService<Pkcs11SessionManager>();
        act.Should().Throw<InvalidOperationException>()
           .WithMessage("*Failed to initialize PKCS#11 session*");
    }
}
