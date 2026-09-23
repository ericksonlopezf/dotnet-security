// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.WebAuthn.Fido2.Tests;

using System;
using System.Collections.Generic;
using AwesomeAssertions;
using EricksonLopez.Security.WebAuthn.Fido2.Abstractions;
using EricksonLopez.Security.WebAuthn.Fido2.DependencyInjection;
using EricksonLopez.Security.WebAuthn.Fido2.Enums;
using EricksonLopez.Security.WebAuthn.Fido2.Models;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Xunit;

public sealed class WebAuthnModelAndExtensionsTests
{
    [Fact]
    public void Models_PropertiesAndRecords_InstantiateCorrectly()
    {
        var rp = new RelyingPartyIdentity("rp.com", "My RP", "https://rp.com/icon.png");
        rp.Id.Should().Be("rp.com");
        rp.Name.Should().Be("My RP");
        rp.Icon.Should().Be("https://rp.com/icon.png");

        var user = new PublicKeyCredentialUserEntity(new byte[] { 1, 2 }, "alice", "Alice", "https://alice.png");
        user.Id.Should().Equal(new byte[] { 1, 2 });
        user.Name.Should().Be("alice");
        user.DisplayName.Should().Be("Alice");
        user.Icon.Should().Be("https://alice.png");

        // Boundary tests for user id length (1..64)
        var maxUser = new PublicKeyCredentialUserEntity(new byte[64], "max", "Max User");
        maxUser.Id.Length.Should().Be(64);

        var exEmpty = Assert.Throws<ArgumentOutOfRangeException>(() => new PublicKeyCredentialUserEntity(Array.Empty<byte>(), "a", "b"));
        exEmpty.Message.Should().Contain("User ID must be between 1 and 64 bytes in length.");
        var exTooLong = Assert.Throws<ArgumentOutOfRangeException>(() => new PublicKeyCredentialUserEntity(new byte[65], "a", "b"));
        exTooLong.Message.Should().Contain("User ID must be between 1 and 64 bytes in length.");
        Assert.Throws<ArgumentNullException>(() => new PublicKeyCredentialUserEntity(null!, "a", "b"));
        Assert.Throws<ArgumentException>(() => new PublicKeyCredentialUserEntity(new byte[1], "", "b"));
        Assert.Throws<ArgumentException>(() => new PublicKeyCredentialUserEntity(new byte[1], "a", ""));

        var param = new PublicKeyCredentialParameters(CoseAlgorithmIdentifier.ES256);
        param.Type.Should().Be(PublicKeyCredentialType.PublicKey);
        param.Alg.Should().Be(CoseAlgorithmIdentifier.ES256);

        var descriptor = new PublicKeyCredentialDescriptor(
            new byte[] { 9, 8, 7 },
            new List<string> { "internal", "usb" });
        descriptor.Type.Should().Be(PublicKeyCredentialType.PublicKey);
        descriptor.Id.Should().Equal(new byte[] { 9, 8, 7 });
        descriptor.Transports.Should().NotBeNull();

        var regOptions = new CredentialCreateOptions(rp, user, new byte[32], new List<PublicKeyCredentialParameters> { param })
        {
            TimeoutMilliseconds = 30000,
            Attestation = AttestationConveyancePreference.Direct,
            ResidentKey = ResidentKeyRequirement.Required,
            UserVerification = UserVerificationRequirement.Required,
            ExcludeCredentials = new List<PublicKeyCredentialDescriptor> { descriptor },
            AuthenticatorAttachment = AuthenticatorAttachment.Platform
        };
        regOptions.AuthenticatorAttachment.Should().Be(AuthenticatorAttachment.Platform);
        regOptions.Rp.Should().Be(rp);
        regOptions.User.Should().Be(user);
        regOptions.TimeoutMilliseconds.Should().Be(30000);
        regOptions.Attestation.Should().Be(AttestationConveyancePreference.Direct);
        regOptions.ResidentKey.Should().Be(ResidentKeyRequirement.Required);
        regOptions.UserVerification.Should().Be(UserVerificationRequirement.Required);
        regOptions.ExcludeCredentials.Should().HaveCount(1);

        var reqOptions = new CredentialRequestOptions(new byte[32], "rp.com")
        {
            TimeoutMilliseconds = 15000,
            UserVerification = UserVerificationRequirement.Discouraged,
            AllowCredentials = new List<PublicKeyCredentialDescriptor> { descriptor }
        };
        reqOptions.RpId.Should().Be("rp.com");
        reqOptions.TimeoutMilliseconds.Should().Be(15000);
        reqOptions.UserVerification.Should().Be(UserVerificationRequirement.Discouraged);
        reqOptions.AllowCredentials.Should().HaveCount(1);

        var coseKey = new CosePublicKey(
            CoseKeyType.Ec2,
            CoseAlgorithmIdentifier.ES256,
            new byte[] { 0xAA },
            CoseEllipticCurve.P256,
            x: new byte[] { 1 },
            y: new byte[] { 2 },
            modulus: new byte[] { 3 },
            exponent: new byte[] { 4 });
        coseKey.KeyType.Should().Be(CoseKeyType.Ec2);
        coseKey.Algorithm.Should().Be(CoseAlgorithmIdentifier.ES256);
        coseKey.RawBytes.Should().Equal(new byte[] { 0xAA });
        coseKey.Curve.Should().Be(CoseEllipticCurve.P256);
        coseKey.X.Should().Equal(new byte[] { 1 });
        coseKey.Y.Should().Equal(new byte[] { 2 });
        coseKey.Modulus.Should().Equal(new byte[] { 3 });
        coseKey.Exponent.Should().Equal(new byte[] { 4 });

        var aaguid = Guid.NewGuid();
        var credData = new AttestedCredentialData(aaguid, new byte[] { 10 }, coseKey, new byte[] { 0xBB });
        credData.Aaguid.Should().Be(aaguid);
        credData.CredentialId.Should().Equal(new byte[] { 10 });
        credData.PublicKey.Should().Be(coseKey);
        credData.RawBytes.Should().Equal(new byte[] { 0xBB });

        var clientData = new CollectedClientData("webauthn.create", "challenge123", "https://example.com", new byte[] { 0xCC }, true);
        clientData.Type.Should().Be("webauthn.create");
        clientData.Challenge.Should().Be("challenge123");
        clientData.Origin.Should().Be("https://example.com");
        clientData.RawClientDataJson.Should().Equal(new byte[] { 0xCC });
        clientData.CrossOrigin.Should().BeTrue();

        var attStmt = new AttestationStatement("packed", new byte[] { 0xDD }, signature: new byte[] { 5 }, algorithm: -7, x5c: new List<byte[]> { new byte[] { 6 } });
        attStmt.Format.Should().Be("packed");
        attStmt.RawBytes.Should().Equal(new byte[] { 0xDD });
        attStmt.Signature.Should().Equal(new byte[] { 5 });
        attStmt.Algorithm.Should().Be(-7);
        attStmt.X5c.Should().HaveCount(1);

        var authData = new AuthenticatorData(
            new byte[32],
            AuthenticatorDataFlags.UserPresent | AuthenticatorDataFlags.UserVerified | AuthenticatorDataFlags.AttestedCredentialData | AuthenticatorDataFlags.ExtensionData | AuthenticatorDataFlags.BackupEligibility | AuthenticatorDataFlags.BackupState,
            15,
            new byte[] { 0xEE },
            credData,
            new byte[] { 0xFF });
        authData.SignCount.Should().Be(15u);
        authData.UserPresent.Should().BeTrue();
        authData.UserVerified.Should().BeTrue();
        authData.BackupEligibility.Should().BeTrue();
        authData.BackupState.Should().BeTrue();
        authData.ExtensionData.Should().Equal(new byte[] { 0xFF });

        var attObj = new AttestationObject(authData, attStmt, new byte[] { 0x11 });
        attObj.AuthenticatorData.Should().Be(authData);
        attObj.Statement.Should().Be(attStmt);
        attObj.Format.Should().Be("packed");
        attObj.RawBytes.Should().Equal(new byte[] { 0x11 });

        var verifiedReg = new VerifiedCredentialRegistration(
            new byte[] { 1 },
            new byte[] { 2 },
            coseKey,
            1,
            aaguid,
            true,
            false,
            "none");
        verifiedReg.CredentialId.Should().Equal(new byte[] { 1 });
        verifiedReg.UserHandle.Should().Equal(new byte[] { 2 });
        verifiedReg.PublicKey.Should().Be(coseKey);
        verifiedReg.SignCount.Should().Be(1u);
        verifiedReg.Aaguid.Should().Be(aaguid);
        verifiedReg.IsBackupEligible.Should().BeTrue();
        verifiedReg.IsBackedUp.Should().BeFalse();
        verifiedReg.AttestationFormat.Should().Be("none");

        var verifiedAssert = new VerifiedCredentialAssertion(
            new byte[] { 1 },
            10,
            true,
            true,
            false,
            new byte[] { 2 });
        verifiedAssert.CredentialId.Should().Equal(new byte[] { 1 });
        verifiedAssert.UpdatedSignCount.Should().Be(10u);
        verifiedAssert.UserVerified.Should().BeTrue();
        verifiedAssert.UserPresent.Should().BeTrue();
        verifiedAssert.IsBackedUp.Should().BeFalse();
        verifiedAssert.UserHandle.Should().Equal(new byte[] { 2 });
    }

    [Fact]
    public void DependencyInjection_AddWebAuthnFido2_RegistersAllServices()
    {
        var services = new ServiceCollection();
        services.AddWebAuthnFido2(options =>
        {
            options.RpId = "di.example.com";
            options.RpName = "DI RP";
        });

        var provider = services.BuildServiceProvider();

        provider.GetRequiredService<ICoseKeyParser>().Should().NotBeNull();
        provider.GetRequiredService<IAuthenticatorDataParser>().Should().NotBeNull();
        provider.GetRequiredService<IWebAuthnCeremonyService>().Should().NotBeNull();

        var verifiers = provider.GetServices<IAttestationVerifier>();
        verifiers.Should().HaveCount(5);

        var options = provider.GetRequiredService<IOptions<WebAuthnOptions>>().Value;
        options.RpId.Should().Be("di.example.com");
        options.RpName.Should().Be("DI RP");
    }

    [Fact]
    public void DependencyInjection_NullServices_ThrowsArgumentNullException()
    {
        var ex = Assert.Throws<ArgumentNullException>(() => WebAuthnServiceCollectionExtensions.AddWebAuthnFido2(null!));
        ex.ParamName.Should().Be("services");
    }

    [Fact]
    public void DependencyInjection_NullAction_RegistersDefaultsSuccessfully()
    {
        var services = new ServiceCollection();
        services.AddWebAuthnFido2(null);
        var provider = services.BuildServiceProvider();
        provider.GetRequiredService<IWebAuthnCeremonyService>().Should().NotBeNull();
    }

    [Fact]
    public void Models_EqualityAndComparisonOperators_DemonstratesValueSemantics()
    {
        var coseKey = new CosePublicKey(CoseKeyType.Ec2, CoseAlgorithmIdentifier.ES256, [1, 2], CoseEllipticCurve.P256, [3], [4], [5], [6]);
        var sameCoseKey = coseKey;
        var coseKey3 = new CosePublicKey(CoseKeyType.Rsa, CoseAlgorithmIdentifier.RS256, [7, 8], null, null, null, null, null);

        Assert.True(coseKey == sameCoseKey);
        Assert.False(coseKey == coseKey3);
        Assert.True(coseKey != coseKey3);
        Assert.True(coseKey.Equals((object)coseKey));
        Assert.False(coseKey.Equals((CosePublicKey?)null));
        Assert.False(coseKey.Equals((object?)null));
        Assert.False(coseKey.Equals(coseKey3));
        Assert.Equal(coseKey.GetHashCode(), coseKey.GetHashCode());
        Assert.NotNull(coseKey.ToString());

        var aaguid = Guid.NewGuid();
        var credData1 = new AttestedCredentialData(aaguid, [1, 2], coseKey, [3, 4]);
        var sameCredData = credData1;
        var credData3 = new AttestedCredentialData(Guid.NewGuid(), [9], coseKey, [8]);
        Assert.True(credData1 == sameCredData);
        Assert.True(credData1.Equals((object)credData1));
        Assert.False(credData1.Equals((AttestedCredentialData?)null));
        Assert.False(credData1.Equals((object?)null));
        Assert.False(credData1.Equals(credData3));
        Assert.Equal(credData1.GetHashCode(), credData1.GetHashCode());
        Assert.NotNull(credData1.ToString());

        var authData1 = new AuthenticatorData([1, 2], AuthenticatorDataFlags.UserPresent, 10, [3, 4], credData1);
        var sameAuthData = authData1;
        var authData3 = new AuthenticatorData([9, 8], AuthenticatorDataFlags.UserPresent, 20, [7, 6], credData3);
        Assert.True(authData1 == sameAuthData);
        Assert.True(authData1.Equals((object)authData1));
        Assert.False(authData1.Equals((AuthenticatorData?)null));
        Assert.False(authData1.Equals((object?)null));
        Assert.False(authData1.Equals(authData3));
        Assert.Equal(authData1.GetHashCode(), authData1.GetHashCode());
        Assert.NotNull(authData1.ToString());

        var stmt1 = new AttestationStatement("packed", [1], [2], -7, [[3]]);
        var sameStmt = stmt1;
        var stmt3 = new AttestationStatement("none", [9], null, null, null);
        Assert.True(stmt1 == sameStmt);
        Assert.True(stmt1.Equals((object)stmt1));
        Assert.False(stmt1.Equals((AttestationStatement?)null));
        Assert.False(stmt1.Equals((object?)null));
        Assert.False(stmt1.Equals(stmt3));
        Assert.Equal(stmt1.GetHashCode(), stmt1.GetHashCode());
        Assert.NotNull(stmt1.ToString());

        var attObj1 = new AttestationObject(authData1, stmt1, [1, 2]);
        var sameAttObj = attObj1;
        var attObj3 = new AttestationObject(authData3, stmt3, [9, 8]);
        Assert.True(attObj1 == sameAttObj);
        Assert.True(attObj1.Equals((object)attObj1));
        Assert.False(attObj1.Equals((AttestationObject?)null));
        Assert.False(attObj1.Equals((object?)null));
        Assert.False(attObj1.Equals(attObj3));
        Assert.Equal(attObj1.GetHashCode(), attObj1.GetHashCode());
        Assert.NotNull(attObj1.ToString());

        var vReg1 = new VerifiedCredentialRegistration([1], [2], coseKey, 5, aaguid, true, false, "packed");
        var sameVReg = vReg1;
        var vReg3 = new VerifiedCredentialRegistration([9], [8], coseKey, 10, Guid.NewGuid(), false, false, "none");
        Assert.True(vReg1 == sameVReg);
        Assert.True(vReg1.Equals((object)vReg1));
        Assert.False(vReg1.Equals((VerifiedCredentialRegistration?)null));
        Assert.False(vReg1.Equals((object?)null));
        Assert.False(vReg1.Equals(vReg3));
        Assert.Equal(vReg1.GetHashCode(), vReg1.GetHashCode());
        Assert.NotNull(vReg1.ToString());

        var vAss1 = new VerifiedCredentialAssertion([1], 5, true, true, false, [2]);
        var sameVAss = vAss1;
        var vAss3 = new VerifiedCredentialAssertion([9], 10, false, false, false, null);
        Assert.True(vAss1 == sameVAss);
        Assert.True(vAss1.Equals((object)vAss1));
        Assert.False(vAss1.Equals((VerifiedCredentialAssertion?)null));
        Assert.False(vAss1.Equals((object?)null));
        Assert.False(vAss1.Equals(vAss3));
        Assert.Equal(vAss1.GetHashCode(), vAss1.GetHashCode());
        Assert.NotNull(vAss1.ToString());
    }

    [Fact]
    public void Models_ConstructorNullValidation_ThrowsArgumentNullException()
    {
        var coseKey = new CosePublicKey(CoseKeyType.Ec2, CoseAlgorithmIdentifier.ES256, [1, 2]);
        var credData = new AttestedCredentialData(Guid.NewGuid(), [1], coseKey, [2]);
        var authData = new AuthenticatorData([1], AuthenticatorDataFlags.UserPresent, 0, [2]);
        var stmt = new AttestationStatement("none", [1]);

        Assert.Throws<ArgumentNullException>(() => new CosePublicKey(CoseKeyType.Ec2, CoseAlgorithmIdentifier.ES256, null!));

        Assert.Throws<ArgumentNullException>(() => new AttestedCredentialData(Guid.NewGuid(), null!, coseKey, [1]));
        Assert.Throws<ArgumentNullException>(() => new AttestedCredentialData(Guid.NewGuid(), [1], null!, [1]));
        Assert.Throws<ArgumentNullException>(() => new AttestedCredentialData(Guid.NewGuid(), [1], coseKey, null!));

        Assert.Throws<ArgumentNullException>(() => new AuthenticatorData(null!, AuthenticatorDataFlags.UserPresent, 0, [1]));
        Assert.Throws<ArgumentNullException>(() => new AuthenticatorData([1], AuthenticatorDataFlags.UserPresent, 0, null!));

        Assert.Throws<ArgumentNullException>(() => new AttestationObject(null!, stmt, [1]));
        Assert.Throws<ArgumentNullException>(() => new AttestationObject(authData, null!, [1]));
        Assert.Throws<ArgumentNullException>(() => new AttestationObject(authData, stmt, null!));

        Assert.Throws<ArgumentNullException>(() => new VerifiedCredentialRegistration(null!, [1], coseKey, 0, Guid.NewGuid(), false, false, "none"));
        Assert.Throws<ArgumentNullException>(() => new VerifiedCredentialRegistration([1], null!, coseKey, 0, Guid.NewGuid(), false, false, "none"));
        Assert.Throws<ArgumentNullException>(() => new VerifiedCredentialRegistration([1], [1], null!, 0, Guid.NewGuid(), false, false, "none"));
        Assert.Throws<ArgumentNullException>(() => new VerifiedCredentialRegistration([1], [1], coseKey, 0, Guid.NewGuid(), false, false, null!));

        Assert.Throws<ArgumentNullException>(() => new VerifiedCredentialAssertion(null!, 0, false, false, false));

        // AuthenticatorAssertionRawResponse
        Assert.Throws<ArgumentNullException>(() => new AuthenticatorAssertionRawResponse(null!, [1], [1], [1], [1]));
        Assert.Throws<ArgumentException>(() => new AuthenticatorAssertionRawResponse("   ", [1], [1], [1], [1]));
        Assert.Throws<ArgumentNullException>(() => new AuthenticatorAssertionRawResponse("id", null!, [1], [1], [1]));
        Assert.Throws<ArgumentNullException>(() => new AuthenticatorAssertionRawResponse("id", [1], null!, [1], [1]));
        Assert.Throws<ArgumentNullException>(() => new AuthenticatorAssertionRawResponse("id", [1], [1], null!, [1]));
        Assert.Throws<ArgumentNullException>(() => new AuthenticatorAssertionRawResponse("id", [1], [1], [1], null!));

        // AuthenticatorAttestationRawResponse
        Assert.Throws<ArgumentNullException>(() => new AuthenticatorAttestationRawResponse(null!, [1], [1], [1]));
        Assert.Throws<ArgumentException>(() => new AuthenticatorAttestationRawResponse("   ", [1], [1], [1]));
        Assert.Throws<ArgumentNullException>(() => new AuthenticatorAttestationRawResponse("id", null!, [1], [1]));
        Assert.Throws<ArgumentNullException>(() => new AuthenticatorAttestationRawResponse("id", [1], null!, [1]));
        Assert.Throws<ArgumentNullException>(() => new AuthenticatorAttestationRawResponse("id", [1], [1], null!));

        // CollectedClientData
        Assert.Throws<ArgumentNullException>(() => new CollectedClientData(null!, "c", "o", [1]));
        Assert.Throws<ArgumentException>(() => new CollectedClientData("   ", "c", "o", [1]));
        Assert.Throws<ArgumentNullException>(() => new CollectedClientData("t", null!, "o", [1]));
        Assert.Throws<ArgumentException>(() => new CollectedClientData("t", "   ", "o", [1]));
        Assert.Throws<ArgumentNullException>(() => new CollectedClientData("t", "c", null!, [1]));
        Assert.Throws<ArgumentException>(() => new CollectedClientData("t", "c", "   ", [1]));
        Assert.Throws<ArgumentNullException>(() => new CollectedClientData("t", "c", "o", null!));

        // CredentialCreateOptions
        var rpVal = new RelyingPartyIdentity("r", "R");
        var userVal = new PublicKeyCredentialUserEntity([1], "u", "U");
        Assert.Throws<ArgumentNullException>(() => new CredentialCreateOptions(null!, userVal, [1], []));
        Assert.Throws<ArgumentNullException>(() => new CredentialCreateOptions(rpVal, null!, [1], []));
        Assert.Throws<ArgumentNullException>(() => new CredentialCreateOptions(rpVal, userVal, null!, []));
        Assert.Throws<ArgumentNullException>(() => new CredentialCreateOptions(rpVal, userVal, [1], null!));

        // CredentialRequestOptions
        Assert.Throws<ArgumentNullException>(() => new CredentialRequestOptions(null!, "localhost"));
        Assert.Throws<ArgumentNullException>(() => new CredentialRequestOptions([1], null!));
        Assert.Throws<ArgumentException>(() => new CredentialRequestOptions([1], "   "));

        // PublicKeyCredentialDescriptor
        Assert.Throws<ArgumentNullException>(() => new PublicKeyCredentialDescriptor(null!));

        // RelyingPartyIdentity
        Assert.Throws<ArgumentNullException>(() => new RelyingPartyIdentity(null!, "Name"));
        Assert.Throws<ArgumentException>(() => new RelyingPartyIdentity("   ", "Name"));
        Assert.Throws<ArgumentNullException>(() => new RelyingPartyIdentity("id", null!));
        Assert.Throws<ArgumentException>(() => new RelyingPartyIdentity("id", "   "));

        // AttestationStatement
        Assert.Throws<ArgumentNullException>(() => new AttestationStatement(null!, [1]));
        Assert.Throws<ArgumentException>(() => new AttestationStatement("   ", [1]));
    }

    [Fact]
    public void Models_PropertyAssignments_Asserted()
    {
        var rawAssertion = new AuthenticatorAssertionRawResponse("id1", [1], [2], [3], [4]);
        rawAssertion.Id.Should().Be("id1");
        rawAssertion.RawId.Should().Equal([1]);
        rawAssertion.ClientDataJson.Should().Equal([2]);
        rawAssertion.AuthenticatorData.Should().Equal([3]);
        rawAssertion.Signature.Should().Equal([4]);

        var rawAttestation = new AuthenticatorAttestationRawResponse("id2", [5], [6], [7]);
        rawAttestation.Id.Should().Be("id2");
        rawAttestation.RawId.Should().Equal([5]);
        rawAttestation.ClientDataJson.Should().Equal([6]);
        rawAttestation.AttestationObject.Should().Equal([7]);

        var clientData = new CollectedClientData("webauthn.get", "challenge123", "https://localhost", [8], false);
        clientData.Type.Should().Be("webauthn.get");
        clientData.Challenge.Should().Be("challenge123");
        clientData.Origin.Should().Be("https://localhost");
        clientData.RawClientDataJson.Should().Equal([8]);
        clientData.CrossOrigin.Should().BeFalse();

        var rp = new RelyingPartyIdentity("rp1", "RP One", "https://icon");
        rp.Id.Should().Be("rp1");
        rp.Name.Should().Be("RP One");
        rp.Icon.Should().Be("https://icon");

        var user = new PublicKeyCredentialUserEntity([1], "user1", "User One", "https://uicon");
        user.Id.Should().Equal([1]);
        user.Name.Should().Be("user1");
        user.DisplayName.Should().Be("User One");
        user.Icon.Should().Be("https://uicon");

        var param = new PublicKeyCredentialParameters(CoseAlgorithmIdentifier.ES256);
        param.Alg.Should().Be(CoseAlgorithmIdentifier.ES256);
        param.Type.Should().Be(PublicKeyCredentialType.PublicKey);

        var descriptor = new PublicKeyCredentialDescriptor([9], ["internal"]);
        descriptor.Type.Should().Be(PublicKeyCredentialType.PublicKey);
        descriptor.Id.Should().Equal([9]);
        descriptor.Transports.Should().ContainSingle().Which.Should().Be("internal");

        var createOptions = new CredentialCreateOptions(rp, user, [10], [param])
        {
            TimeoutMilliseconds = 60000,
            Attestation = AttestationConveyancePreference.Direct,
            AuthenticatorAttachment = AuthenticatorAttachment.Platform,
            ResidentKey = ResidentKeyRequirement.Required,
            UserVerification = UserVerificationRequirement.Required,
            ExcludeCredentials = [descriptor]
        };
        createOptions.Rp.Should().Be(rp);
        createOptions.User.Should().Be(user);
        createOptions.Challenge.Should().Equal([10]);
        createOptions.PubKeyCredParams.Should().ContainSingle();
        createOptions.TimeoutMilliseconds.Should().Be(60000);
        createOptions.Attestation.Should().Be(AttestationConveyancePreference.Direct);
        createOptions.AuthenticatorAttachment.Should().Be(AuthenticatorAttachment.Platform);
        createOptions.ResidentKey.Should().Be(ResidentKeyRequirement.Required);
        createOptions.UserVerification.Should().Be(UserVerificationRequirement.Required);
        createOptions.ExcludeCredentials.Should().ContainSingle();

        var requestOptions = new CredentialRequestOptions([11], "localhost")
        {
            TimeoutMilliseconds = 30000,
            UserVerification = UserVerificationRequirement.Preferred,
            AllowCredentials = [descriptor]
        };
        requestOptions.Challenge.Should().Equal([11]);
        requestOptions.RpId.Should().Be("localhost");
        requestOptions.TimeoutMilliseconds.Should().Be(30000);
        requestOptions.UserVerification.Should().Be(UserVerificationRequirement.Preferred);
        requestOptions.AllowCredentials.Should().ContainSingle();

        var stmt = new AttestationStatement("packed", [12], [13], -7, [[14]]);
        stmt.Format.Should().Be("packed");
        stmt.RawBytes.Should().Equal([12]);
        stmt.Signature.Should().Equal([13]);
        stmt.Algorithm.Should().Be(-7);
        stmt.X5c.Should().ContainSingle();

        var options = new WebAuthnOptions();
        options.AllowedOrigins.Should().Contain("https://localhost");
        options.AllowedOrigins.Should().Contain("https://localhost:5001");
        options.AllowedOrigins.Should().Contain("http://localhost:5000");
        options.SupportedAlgorithms.Should().Contain(CoseAlgorithmIdentifier.ES256);

        var ex = Assert.Throws<ArgumentNullException>(() => ((Microsoft.Extensions.DependencyInjection.IServiceCollection)null!).AddWebAuthnFido2());
        ex.ParamName.Should().Be("services");
        ex.StackTrace.Should().Contain(nameof(WebAuthnServiceCollectionExtensions));
        ex.StackTrace.Should().NotContain("OptionsServiceCollectionExtensions");
    }
}
