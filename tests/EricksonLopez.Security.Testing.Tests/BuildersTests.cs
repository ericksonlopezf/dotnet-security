// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Testing.Tests;

using System;
using System.Formats.Cbor;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using AwesomeAssertions;
using EricksonLopez.Security.Testing.Builders;
using EricksonLopez.Security.WebAuthn.Fido2.Enums;
using EricksonLopez.Security.WebAuthn.Fido2.Parsers;
using Xunit;

public sealed class BuildersTests
{
    private static readonly string[] SampleGroupValues = ["Admin", "SuperUser"];
    private static readonly byte[] SampleCustomSig = [1, 2, 3];

    [Fact]
    public void SamlTestMessageBuilder_DefaultValues_GeneratesValidXml()
    {
        var builder = new SamlTestMessageBuilder();
        var xml = builder.BuildXml();

        xml.Should().NotBeNullOrWhiteSpace();
        xml.Should().Contain("<samlp:Response");
        xml.Should().NotContain("InResponseTo=");
        xml.Should().NotContain("Destination=");
        xml.Should().NotContain("<saml:SubjectConfirmation");
        xml.Should().NotContain("<saml:AuthnStatement");
        xml.Should().NotContain("<saml:AttributeStatement>");
        xml.Should().Contain("<saml:Issuer>https://idp.example.com</saml:Issuer>");
        xml.Should().Contain("StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\"");
        xml.Should().Contain("<saml:NameID>user@example.com</saml:NameID>");
        xml.Should().Contain("<saml:Audience>https://sp.example.com</saml:Audience>");
        xml.Should().Contain("IssueInstant=\"2026-08-31T00:00:00Z\"");
        xml.Should().Contain("NotBefore=\"2026-01-01T00:00:00Z\"");
        xml.Should().Contain("NotOnOrAfter=\"2030-01-01T00:00:00Z\"");
        var doc = System.Xml.Linq.XDocument.Parse(xml);
        doc.Root.Should().NotBeNull();
        doc.Root!.Name.LocalName.Should().Be("Response");
        doc.Root.Attribute("ID")!.Value.Should().StartWith("_resp_").And.HaveLength(38);

        var assertionElem = doc.Descendants().First(e => e.Name.LocalName == "Assertion");
        assertionElem.Attribute("ID")!.Value.Should().StartWith("_assert_").And.HaveLength(40);
    }

    [Fact]
    public void SamlTestMessageBuilder_EmptyRecipientSubjectConfirmation_DoesNotEmitSubjectConfirmation()
    {
        var xml = new SamlTestMessageBuilder().WithSubjectConfirmation("", DateTimeOffset.UtcNow).BuildXml();
        xml.Should().NotContain("<saml:SubjectConfirmation");
    }

    [Fact]
    public void SamlTestMessageBuilder_CustomValues_EmitsExpectedXmlElements()
    {
        var now = DateTimeOffset.UtcNow;
        var notBefore = now.AddMinutes(-5);
        var notAfter = now.AddMinutes(10);

        var xml = new SamlTestMessageBuilder()
            .WithResponseId("_custom_resp_1")
            .WithInResponseTo("_orig_req_1")
            .WithIssuer("https://custom-idp.com")
            .WithAssertionIssuer("https://custom-assert-idp.com")
            .WithStatusCode("urn:oasis:names:tc:SAML:2.0:status:Responder")
            .WithSecondaryStatusCode("urn:oasis:names:tc:SAML:2.0:status:AuthnFailed")
            .WithStatusMessage("Authentication failed")
            .WithAssertionId("_custom_assert_1")
            .WithSubject("admin@custom.com")
            .WithAudience("https://custom-sp.com")
            .WithIssueInstant(now)
            .WithConditions(notBefore, notAfter)
            .WithAttribute("Role", "SecurityAdmin")
            .WithAttribute("Department", "SecOps")
            .BuildXml();

        xml.Should().Contain("ID=\"_custom_resp_1\"");
        xml.Should().Contain("InResponseTo=\"_orig_req_1\"");
        xml.Should().Contain("<saml:Issuer>https://custom-idp.com</saml:Issuer>");
        xml.Should().Contain("<saml:Issuer>https://custom-assert-idp.com</saml:Issuer>");
        xml.Should().Contain("StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Responder\"");
        xml.Should().Contain("StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:AuthnFailed\"");
        xml.Should().Contain("<samlp:StatusMessage>Authentication failed</samlp:StatusMessage>");
        xml.Should().Contain("<saml:NameID>admin@custom.com</saml:NameID>");
        xml.Should().Contain("<saml:Audience>https://custom-sp.com</saml:Audience>");
        xml.Should().Contain("<saml:Attribute Name=\"Role\"><saml:AttributeValue>SecurityAdmin</saml:AttributeValue></saml:Attribute>");
        xml.Should().Contain("<saml:AttributeStatement>");
        xml.Should().Contain("</saml:AttributeStatement>");

        var doc = System.Xml.Linq.XDocument.Parse(xml);
        doc.Root.Should().NotBeNull();
        doc.Descendants().Should().Contain(e => e.Name.LocalName == "AttributeStatement");
    }

    [Fact]
    public void SamlTestMessageBuilder_WithoutAssertion_OmitsAssertionElement()
    {
        var xml = new SamlTestMessageBuilder()
            .WithoutAssertion()
            .BuildXml();

        xml.Should().Contain("<samlp:Response");
        xml.Should().NotContain("<saml:Assertion");
    }

    [Fact]
    public void SamlTestMessageBuilder_OmissionsAndSpecialElements_ProducesExpectedXml()
    {
        var now = DateTimeOffset.UtcNow;
        var confDate = now.AddMinutes(5);

        // 1. With SubjectConfirmation and AuthnStatement present
        var xml = new SamlTestMessageBuilder()
            .WithDestination("https://sp.example.com/acs")
            .WithSubjectConfirmation("https://sp.example.com/acs", confDate)
            .WithAuthnStatement(now, "session-xyz-123")
            .WithAttribute("Group", SampleGroupValues, "UserGroups")
            .WithAttribute("Group", "Auditor")
            .BuildXml();

        xml.Should().Contain("Destination=\"https://sp.example.com/acs\"");
        xml.Should().Contain("<saml:Subject>");
        xml.Should().Contain("<saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\">");
        xml.Should().Contain($"<saml:SubjectConfirmationData Recipient=\"https://sp.example.com/acs\" NotOnOrAfter=\"{confDate:yyyy-MM-ddTHH:mm:ssZ}\"/>");
        xml.Should().Contain("<saml:AuthnStatement");
        xml.Should().Contain("SessionIndex=\"session-xyz-123\"");
        xml.Should().Contain($"AuthnInstant=\"{now:yyyy-MM-ddTHH:mm:ssZ}\"");
        xml.Should().Contain("FriendlyName=\"UserGroups\"");
        xml.Should().Contain("<saml:AttributeValue>Admin</saml:AttributeValue>");
        xml.Should().Contain("<saml:AttributeValue>SuperUser</saml:AttributeValue>");
        xml.Should().Contain("<saml:AttributeValue>Auditor</saml:AttributeValue>");

        // Test AuthnStatement without session index (kills mutant 258: no stray text after AuthnInstant)
        var xmlNoSession = new SamlTestMessageBuilder()
            .WithAuthnStatement(now)
            .BuildXml();

        xmlNoSession.Should().Contain($"<saml:AuthnStatement AuthnInstant=\"{now:yyyy-MM-ddTHH:mm:ssZ}\"/>");
        xmlNoSession.Should().NotContain("SessionIndex=");

        // Test Omissions independently
        var xmlOmitted = new SamlTestMessageBuilder()
            .WithoutStatus()
            .WithoutSubject()
            .WithoutConditions()
            .BuildXml();

        xmlOmitted.Should().NotContain("<samlp:Status>");
        xmlOmitted.Should().NotContain("<saml:Subject>");
        xmlOmitted.Should().NotContain("<saml:Conditions");
    }

    [Fact]
    public void Fido2AttestationTestBuilder_Ec2Attestation_BuildsValidStatementAndAuthData()
    {
        var builder = new Fido2AttestationTestBuilder()
            .WithEc2Key(CoseEllipticCurve.P256, CoseAlgorithmIdentifier.ES256)
            .WithSignCount(42)
            .WithFormat("packed");

        var (statement, authData, clientDataHash) = builder.Build();

        statement.Should().NotBeNull();
        statement.Format.Should().Be("packed");
        statement.Signature.Should().NotBeEmpty();
        authData.SignCount.Should().Be(42);
        System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(authData.RawBytes.AsSpan(33, 4)).Should().Be(42);
        authData.AttestedCredentialData.Should().NotBeNull();
        authData.AttestedCredentialData!.PublicKey.Algorithm.Should().Be(CoseAlgorithmIdentifier.ES256);
        clientDataHash.Should().HaveCount(32);

        // Cryptographically verify ECDsa signature on authData + clientDataHash
        var ecKey = authData.AttestedCredentialData.PublicKey;
        using var ecdsa = ECDsa.Create(new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            Q = new ECPoint { X = ecKey.X, Y = ecKey.Y }
        });
        var signedData = new byte[37 + clientDataHash.Length];
        Buffer.BlockCopy(authData.RawBytes, 0, signedData, 0, 37);
        Buffer.BlockCopy(clientDataHash, 0, signedData, 37, clientDataHash.Length);
        ecdsa.VerifyData(signedData, statement.Signature, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence).Should().BeTrue();
    }

    [Fact]
    public void Fido2AttestationTestBuilder_RsaAttestation_BuildsValidStatementAndAuthData()
    {
        var builder = new Fido2AttestationTestBuilder()
            .WithRsaKey(CoseAlgorithmIdentifier.RS256)
            .WithSignCount(100);

        var (statement, authData, clientDataHash) = builder.Build();

        statement.Should().NotBeNull();
        statement.Signature.Should().NotBeEmpty();
        authData.SignCount.Should().Be(100);
        System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(authData.RawBytes.AsSpan(33, 4)).Should().Be(100);
        authData.AttestedCredentialData!.PublicKey.KeyType.Should().Be(CoseKeyType.Rsa);

        // Cryptographically verify RSA signature on authData + clientDataHash
        var rsaKey = authData.AttestedCredentialData.PublicKey;
        using var rsa = RSA.Create();
        rsa.ImportParameters(new RSAParameters { Modulus = rsaKey.Modulus, Exponent = rsaKey.Exponent });
        var signedData = new byte[37 + clientDataHash.Length];
        Buffer.BlockCopy(authData.RawBytes, 0, signedData, 0, 37);
        Buffer.BlockCopy(clientDataHash, 0, signedData, 37, clientDataHash.Length);
        rsa.VerifyData(signedData, statement.Signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1).Should().BeTrue();
    }

    [Fact]
    public void Fido2AttestationTestBuilder_RawCeremonyResponses_BuildsConsistentStructures()
    {
        var customAaguid = Guid.NewGuid();
        byte[] customCredId = [11, 22, 33, 44, 55];
        var builder = new Fido2AttestationTestBuilder()
            .WithAaguid(customAaguid)
            .WithCredentialId(customCredId)
            .WithSignCount(77);

        byte[] challenge = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];

        // 1. Attestation response verification
        var (attestationRaw, attestationKey) = builder.BuildRawAttestationResponse(challenge, rpId: "auth.example.com", origin: "https://auth.example.com");
        attestationRaw.Should().NotBeNull();
        attestationRaw.RawId.Should().Equal(customCredId);
        attestationKey.Should().NotBeNull();

        // CBOR structure validation
        var reader = new CborReader(attestationRaw.AttestationObject);
        reader.ReadStartMap().Should().Be(3);
        reader.ReadTextString().Should().Be("fmt");
        reader.ReadTextString().Should().Be("packed");
        reader.ReadTextString().Should().Be("attStmt");
        reader.ReadStartMap().Should().Be(0);
        reader.ReadEndMap();
        reader.ReadTextString().Should().Be("authData");
        var authDataBytes = reader.ReadByteString();
        reader.ReadEndMap();

        var parser = new AuthenticatorDataParser(new CoseKeyParser());
        var parsedResult = parser.Parse(authDataBytes);
        parsedResult.IsSuccess.Should().BeTrue();
        var parsedAuth = parsedResult.Value;
        parsedAuth.RpIdHash.Should().Equal(SHA256.HashData(Encoding.UTF8.GetBytes("auth.example.com")));
        parsedAuth.Flags.Should().HaveFlag(AuthenticatorDataFlags.AttestedCredentialData);
        parsedAuth.SignCount.Should().Be(77u);
        parsedAuth.AttestedCredentialData!.Aaguid.Should().Be(customAaguid);
        parsedAuth.AttestedCredentialData.CredentialId.Should().Equal(customCredId);
        parsedAuth.AttestedCredentialData.PublicKey.X.Should().Equal(attestationKey.X);
        parsedAuth.AttestedCredentialData.PublicKey.Y.Should().Equal(attestationKey.Y);
        parsedAuth.AttestedCredentialData.PublicKey.Curve.Should().Be(CoseEllipticCurve.P256);

        var clientDataStr = Encoding.UTF8.GetString(attestationRaw.ClientDataJson);
        clientDataStr.Should().Contain("\"type\":\"webauthn.create\"");
        clientDataStr.Should().Contain("\"origin\":\"https://auth.example.com\"");

        // 2. Assertion response verification
        byte[] userHandle = [42, 43, 44];
        var (assertionRaw, assertionKey) = builder.BuildRawAssertionResponse(challenge, rpId: "auth.example.com", origin: "https://auth.example.com", userHandle: userHandle);
        assertionRaw.Should().NotBeNull();
        assertionRaw.RawId.Should().Equal(customCredId);
        assertionRaw.UserHandle.Should().Equal(userHandle);

        var assertionAuthResult = parser.Parse(assertionRaw.AuthenticatorData);
        assertionAuthResult.IsSuccess.Should().BeTrue();
        assertionAuthResult.Value.RpIdHash.Should().Equal(SHA256.HashData(Encoding.UTF8.GetBytes("auth.example.com")));
        assertionAuthResult.Value.SignCount.Should().Be(77u);

        var assertionClientStr = Encoding.UTF8.GetString(assertionRaw.ClientDataJson);
        assertionClientStr.Should().Contain("\"type\":\"webauthn.get\"");
        assertionClientStr.Should().Contain("\"origin\":\"https://auth.example.com\"");

        // Cryptographically verify assertion signature
        using var ecdsaAssert = ECDsa.Create(new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            Q = new ECPoint { X = assertionKey.X, Y = assertionKey.Y }
        });
        var clientHash = SHA256.HashData(assertionRaw.ClientDataJson);
        var assertionPayload = new byte[37 + clientHash.Length];
        Buffer.BlockCopy(assertionRaw.AuthenticatorData, 0, assertionPayload, 0, 37);
        Buffer.BlockCopy(clientHash, 0, assertionPayload, 37, clientHash.Length);
        ecdsaAssert.VerifyData(assertionPayload, assertionRaw.Signature, HashAlgorithmName.SHA256).Should().BeTrue();
    }

    [Fact]
    public void Fido2AttestationTestBuilder_AdvancedCurvesAndKeyTypes_BuildsValidStatements()
    {
        var customGuid = Guid.NewGuid();
        byte[] customCred = [10, 20, 30, 40];
        byte[] customClientHash = new byte[32];
        customClientHash[0] = 0xAA;

        // Test P-384 / ES384
        var p384Builder = new Fido2AttestationTestBuilder()
            .WithEc2Key(CoseEllipticCurve.P384, CoseAlgorithmIdentifier.ES384)
            .WithAaguid(customGuid)
            .WithCredentialId(customCred)
            .WithFlags(AuthenticatorDataFlags.UserPresent | AuthenticatorDataFlags.UserVerified)
            .WithClientDataHash(customClientHash);

        var (stmt384, authData384, clientHash384) = p384Builder.Build();
        stmt384.Algorithm.Should().Be((long)CoseAlgorithmIdentifier.ES384);
        stmt384.Signature.Should().NotBeEmpty();
        authData384.AttestedCredentialData!.Aaguid.Should().Be(customGuid);
        authData384.AttestedCredentialData.CredentialId.Should().BeEquivalentTo(customCred);
        authData384.Flags.Should().HaveFlag(AuthenticatorDataFlags.UserVerified);
        clientHash384[0].Should().Be(0xAA);

        // Cryptographically verify P-384 signature
        var p384Key = authData384.AttestedCredentialData.PublicKey;
        using var ecdsa384 = ECDsa.Create(new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP384,
            Q = new ECPoint { X = p384Key.X, Y = p384Key.Y }
        });
        var signedData384 = new byte[37 + clientHash384.Length];
        Buffer.BlockCopy(authData384.RawBytes, 0, signedData384, 0, 37);
        Buffer.BlockCopy(clientHash384, 0, signedData384, 37, clientHash384.Length);
        ecdsa384.VerifyData(signedData384, stmt384.Signature, HashAlgorithmName.SHA384, DSASignatureFormat.Rfc3279DerSequence).Should().BeTrue();

        // Test P-521 / ES512
        var p521Builder = new Fido2AttestationTestBuilder()
            .WithEc2Key(CoseEllipticCurve.P521, CoseAlgorithmIdentifier.ES512);

        var (stmt521, authData521, clientHash521) = p521Builder.Build();
        stmt521.Algorithm.Should().Be((long)CoseAlgorithmIdentifier.ES512);
        stmt521.Signature.Should().NotBeEmpty();

        var p521Key = authData521.AttestedCredentialData!.PublicKey;
        using var ecdsa521 = ECDsa.Create(new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP521,
            Q = new ECPoint { X = p521Key.X, Y = p521Key.Y }
        });
        var signedData521 = new byte[37 + clientHash521.Length];
        Buffer.BlockCopy(authData521.RawBytes, 0, signedData521, 0, 37);
        Buffer.BlockCopy(clientHash521, 0, signedData521, 37, clientHash521.Length);
        ecdsa521.VerifyData(signedData521, stmt521.Signature, HashAlgorithmName.SHA512, DSASignatureFormat.Rfc3279DerSequence).Should().BeTrue();

        // Test RSA / PS256 (RSASignaturePadding.Pss)
        var rsaPs256Builder = new Fido2AttestationTestBuilder()
            .WithRsaKey(CoseAlgorithmIdentifier.PS256)
            .WithClientDataHash(customClientHash);

        var (stmtPs256, authDataRsa, clientHashRsa) = rsaPs256Builder.Build();
        stmtPs256.Algorithm.Should().Be((long)CoseAlgorithmIdentifier.PS256);
        stmtPs256.Signature.Should().NotBeEmpty();
        authDataRsa.AttestedCredentialData!.PublicKey.KeyType.Should().Be(CoseKeyType.Rsa);

        var rsaKey = authDataRsa.AttestedCredentialData.PublicKey;
        using var rsaPs256 = RSA.Create();
        rsaPs256.ImportParameters(new RSAParameters { Modulus = rsaKey.Modulus, Exponent = rsaKey.Exponent });
        var signedDataRsa = new byte[37 + clientHashRsa.Length];
        Buffer.BlockCopy(authDataRsa.RawBytes, 0, signedDataRsa, 0, 37);
        Buffer.BlockCopy(clientHashRsa, 0, signedDataRsa, 37, clientHashRsa.Length);
        rsaPs256.VerifyData(signedDataRsa, stmtPs256.Signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pss).Should().BeTrue();

        // Test transition from RSA to EC2 (kills mutant 26)
        var transitionBuilder = new Fido2AttestationTestBuilder()
            .WithRsaKey(CoseAlgorithmIdentifier.RS256)
            .WithEc2Key(CoseEllipticCurve.P256, CoseAlgorithmIdentifier.ES256);

        var (_, transitionAuth, _) = transitionBuilder.Build();
        transitionAuth.AttestedCredentialData!.PublicKey.KeyType.Should().Be(CoseKeyType.Ec2);
    }

    [Fact]
    public void Fido2AttestationTestBuilder_ValidationAndCborHelpers_BehavesAsExpected()
    {
        var builder = new Fido2AttestationTestBuilder();

        var actNullCred = () => builder.WithCredentialId(null!);
        actNullCred.Should().Throw<ArgumentNullException>();

        var actNullHash = () => builder.WithClientDataHash(null!);
        actNullHash.Should().Throw<ArgumentNullException>();

        var actNullAuthData = () => Fido2AttestationTestBuilder.BuildCborAttestationObject(null!);
        actNullAuthData.Should().Throw<ArgumentNullException>().WithParameterName("authData");

        byte[] fakeAuthData = new byte[37];
        var defaultCbor = Fido2AttestationTestBuilder.BuildCborAttestationObject(fakeAuthData, "none");
        defaultCbor.Should().NotBeEmpty();

        var defaultReader = new CborReader(defaultCbor);
        defaultReader.ReadStartMap().Should().Be(3);
        defaultReader.ReadTextString().Should().Be("fmt");
        defaultReader.ReadTextString().Should().Be("none");
        defaultReader.ReadTextString().Should().Be("authData");
        defaultReader.ReadByteString().Should().Equal(fakeAuthData);
        defaultReader.ReadTextString().Should().Be("attStmt");
        defaultReader.ReadStartMap().Should().Be(0);
        defaultReader.ReadEndMap();
        defaultReader.ReadEndMap();

        var customCbor = Fido2AttestationTestBuilder.BuildCborAttestationObject(fakeAuthData, "custom", writer =>
        {
            writer.WriteStartMap(1);
            writer.WriteTextString("sig");
            writer.WriteByteString(SampleCustomSig);
            writer.WriteEndMap();
        });
        customCbor.Should().NotBeEmpty();

        var customReader = new CborReader(customCbor);
        customReader.ReadStartMap().Should().Be(3);
        customReader.ReadTextString().Should().Be("fmt");
        customReader.ReadTextString().Should().Be("custom");
        customReader.ReadTextString().Should().Be("authData");
        customReader.ReadByteString().Should().Equal(fakeAuthData);
        customReader.ReadTextString().Should().Be("attStmt");
        customReader.ReadStartMap().Should().Be(1);
        customReader.ReadTextString().Should().Be("sig");
        customReader.ReadByteString().Should().Equal(SampleCustomSig);
        customReader.ReadEndMap();
        customReader.ReadEndMap();
    }
}
