// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Saml2.Tests;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Threading.Tasks;
using System.Xml;
using AwesomeAssertions;
using EricksonLopez.Result;
using EricksonLopez.Security.Saml2.Abstractions;
using EricksonLopez.Security.Saml2.Claims;
using EricksonLopez.Security.Saml2.Cryptography;
using EricksonLopez.Security.Saml2.Enums;
using EricksonLopez.Security.Saml2.Models;
using EricksonLopez.Security.Saml2.Services;
using EricksonLopez.Security.Saml2.Xsw;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Xunit;

using EricksonLopez.Security.Saml2.Tests.Fixtures;
using EricksonLopez.Security.Testing.Builders;
using EricksonLopez.Security.Testing.Logging;
using Microsoft.Extensions.Time.Testing;

public sealed class Saml2ServiceTests : IClassFixture<SamlTestCertificatesFixture>
{
    private readonly Saml2Service _service;
    private readonly Saml2Options _options;
    private readonly X509Certificate2 _idpCert;
    private readonly X509Certificate2 _spCert;
    private readonly X509Certificate2 _spDecCert;
    private readonly Saml2SignatureValidator _sigValidator;
    private readonly Saml2AssertionDecryptor _decryptor;
    private readonly FakeLogger<Saml2Service> _logger;

    public Saml2ServiceTests(SamlTestCertificatesFixture fixture)
    {
        ArgumentNullException.ThrowIfNull(fixture);
        _idpCert = fixture.IdpCert;
        _spCert = fixture.SpCert;
        _spDecCert = fixture.SpDecCert;

        _options = new Saml2Options
        {
            SpEntityId = "https://sp.example.com",
            IdpEntityId = "https://idp.example.com",
            IdpSingleSignOnUrl = "https://idp.example.com/sso",
            IdpSingleLogoutUrl = "https://idp.example.com/slo",
            AssertionConsumerServiceUrl = "https://sp.example.com/saml/acs",
            SpSingleLogoutUrl = "https://sp.example.com/saml/slo",
            IdpSigningCertificate = _idpCert,
            SpSigningCertificate = _spCert,
            SpDecryptionCertificate = _spDecCert,
            RequireSignedMessages = false,
            AllowIdpInitiatedSso = true,
            RequireAssertionExpiration = false
        };

        var xswValidator = new Saml2XswValidator();
        _sigValidator = new Saml2SignatureValidator();
        _decryptor = new Saml2AssertionDecryptor();
        var claimsMapper = new Saml2ClaimsMapper();

        _logger = new FakeLogger<Saml2Service>();

        _service = new Saml2Service(
            Options.Create(_options),
            xswValidator,
            _sigValidator,
            _decryptor,
            claimsMapper,
            _logger);
    }

    [Theory]
    [InlineData(Saml2NameIdFormat.EmailAddress, "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress")]
    [InlineData(Saml2NameIdFormat.Persistent, "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent")]
    [InlineData(Saml2NameIdFormat.Transient, "urn:oasis:names:tc:SAML:2.0:nameid-format:transient")]
    [InlineData(Saml2NameIdFormat.X509SubjectName, "urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName")]
    [InlineData(Saml2NameIdFormat.Unspecified, "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified")]
    public void CreateAuthnRequest_FormatsAndOptions_GeneratesValidXml(Saml2NameIdFormat format, string expectedFormatUri)
    {
        _options.DefaultNameIdFormat = format;
        _options.SignAuthnRequests = true;

        var request = _service.CreateAuthnRequest(relayState: "custom-state-123");

        request.Should().NotBeNull();
        request.Id.Should().StartWith("_");
        request.Id.Length.Should().Be(33);
        request.Issuer.Should().Be("https://sp.example.com");
        request.Destination.Should().Be("https://idp.example.com/sso");
        request.AssertionConsumerServiceUrl.Should().Be("https://sp.example.com/saml/acs");
        request.RelayState.Should().Be("custom-state-123");
        request.RawXml.Should().Contain("<samlp:AuthnRequest");
        request.RawXml.Should().Contain("<samlp:NameIDPolicy");
        request.RawXml.Should().Contain("Version=\"2.0\"");
        request.RawXml.Should().Contain($"ID=\"{request.Id}\"");
        request.RawXml.Should().Contain("IssueInstant=\"");
        request.RawXml.Should().Contain($"IssueInstant=\"{request.IssueInstant:o}\"");
        request.RawXml.Should().Contain($"Destination=\"{request.Destination}\"");
        request.RawXml.Should().Contain($"AssertionConsumerServiceURL=\"{request.AssertionConsumerServiceUrl}\"");
        request.RawXml.Should().Contain("ProtocolBinding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\"");
        request.RawXml.Should().Contain("AllowCreate=\"true\"");
        request.RawXml.Should().Contain(expectedFormatUri);
        request.RawXml.Should().Contain("<Signature");
        request.RawXml.Should().Contain("https://sp.example.com</saml:Issuer>");
    }

    [Fact]
    public void CreateAuthnRequest_WithoutSigningOrRelayState_GeneratesUnsignedXml()
    {
        _options.SignAuthnRequests = false;

        var request = _service.CreateAuthnRequest(relayState: null);

        request.Should().NotBeNull();
        request.RelayState.Should().BeNull();
        request.RawXml.Should().NotContain("<Signature");
    }

    [Fact]
    public void CreateLogoutRequest_GeneratesValidXmlMessage()
    {
        _options.SignLogoutRequests = true;
        var nameId = new Saml2NameId("user@example.com", Saml2NameIdFormat.EmailAddress);

        var request = _service.CreateLogoutRequest(nameId, sessionIndex: "_session_456", relayState: "state456");

        request.Should().NotBeNull();
        request.Id.Should().StartWith("_");
        request.Id.Length.Should().Be(33);
        request.Issuer.Should().Be("https://sp.example.com");
        request.Destination.Should().Be("https://idp.example.com/slo");
        request.SessionIndex.Should().Be("_session_456");
        request.RawXml.Should().Contain("<samlp:LogoutRequest");
        request.RawXml.Should().Contain("Version=\"2.0\"");
        request.RawXml.Should().Contain($"ID=\"{request.Id}\"");
        request.RawXml.Should().Contain("IssueInstant=\"");
        request.RawXml.Should().Contain($"IssueInstant=\"{request.IssueInstant:o}\"");
        request.RawXml.Should().Contain("<saml:NameID");
        request.RawXml.Should().Contain($"Destination=\"{request.Destination}\"");
        request.RawXml.Should().Contain("user@example.com");
        request.RawXml.Should().Contain("RelayState=\"state456\"");
        request.RawXml.Should().Contain("https://sp.example.com</saml:Issuer>");
        request.RawXml.Should().Contain("<samlp:SessionIndex>_session_456</samlp:SessionIndex>");
        request.RawXml.Should().Contain("<Signature");
        _logger.Messages.Should().Contain(m => m.Contains("SAML LogoutRequest created"));
    }

    [Fact]
    public void CreateLogoutRequest_WithoutSessionIndexOrRelayState_GeneratesUnsignedXml()
    {
        _options.SignLogoutRequests = false;
        var nameId = new Saml2NameId("user@example.com", Saml2NameIdFormat.EmailAddress);

        var request = _service.CreateLogoutRequest(nameId, sessionIndex: null, relayState: null);

        request.Should().NotBeNull();
        request.SessionIndex.Should().BeNull();
        request.RawXml.Should().NotContain("SessionIndex");
        request.RawXml.Should().NotContain("RelayState");
        request.RawXml.Should().NotContain("<Signature");
    }

    [Fact]
    public void CreateLogoutRequest_MissingIdpSingleLogoutUrl_ThrowsInvalidOperationException()
    {
        _options.IdpSingleLogoutUrl = null;
        var nameId = new Saml2NameId("user@example.com", Saml2NameIdFormat.EmailAddress);

        var ex = Assert.Throws<InvalidOperationException>(() => _service.CreateLogoutRequest(nameId));
        ex.Message.Should().Contain("IdpSingleLogoutUrl must be configured");
    }

    [Fact]
    public void CreateLogoutRequest_NullNameId_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => _service.CreateLogoutRequest(null!));
    }

    [Fact]
    public void CreateLogoutResponse_GeneratesValidXmlMessage()
    {
        _options.SignLogoutRequests = true;
        var response = _service.CreateLogoutResponse(inResponseTo: "_logout_req_123", destination: "https://idp.example.com/slo", success: true);

        response.Should().NotBeNull();
        response.Id.Should().StartWith("_");
        response.InResponseTo.Should().Be("_logout_req_123");
        response.Issuer.Should().Be("https://sp.example.com");
        response.RawXml.Should().Contain("<samlp:LogoutResponse");
        response.RawXml.Should().Contain("urn:oasis:names:tc:SAML:2.0:status:Success");
        response.RawXml.Should().Contain("<Signature");

        _options.SignLogoutRequests = false;
        var failResponse = _service.CreateLogoutResponse(inResponseTo: "_logout_req_123", destination: "https://idp.example.com/slo", success: false);
        failResponse.StatusCode.Should().Contain("Responder");
        failResponse.RawXml.Should().NotContain("<Signature");
    }

    [Fact]
    public void CreateLogoutResponse_NullArguments_ThrowsArgumentException()
    {
        Assert.Throws<ArgumentNullException>(() => _service.CreateLogoutResponse(null!, "https://dest"));
        Assert.Throws<ArgumentNullException>(() => _service.CreateLogoutResponse("_1", null!));
    }

    [Fact]
    public void GenerateSpMetadata_GeneratesValidEntityDescriptor()
    {
        _options.SignAuthnRequests = true;
        _options.RequireSignedMessages = true;

        var metadata = _service.GenerateSpMetadata();

        metadata.Should().NotBeNull();
        metadata.Should().Contain("<md:EntityDescriptor");
        metadata.Should().Contain("\r\n  <md:SPSSODescriptor");
        metadata.Should().Contain("entityID=\"https://sp.example.com\"");
        metadata.Should().Contain("xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\"");
        metadata.Should().Contain("xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"");
        metadata.Should().Contain("<md:SPSSODescriptor");
        metadata.Should().Contain("AuthnRequestsSigned=\"true\"");
        metadata.Should().Contain("WantAssertionsSigned=\"true\"");
        metadata.Should().Contain("protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\"");
        metadata.Should().Contain("<md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>");
        metadata.Should().Contain("AssertionConsumerService");
        metadata.Should().Contain("Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\"");
        metadata.Should().Contain("index=\"1\"");
        metadata.Should().Contain("isDefault=\"true\"");
        metadata.Should().Contain("SingleLogoutService");
        metadata.Should().Contain("Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\"");
        metadata.Should().Contain("<md:KeyDescriptor use=\"signing\">");
        metadata.Should().Contain("KeyDescriptor use=\"signing\"");
        metadata.Should().Contain("KeyDescriptor use=\"encryption\"");
        metadata.Should().Contain("<ds:KeyInfo");
        metadata.Should().Contain("<ds:X509Data");
        metadata.Should().Contain("<ds:X509Certificate");
        metadata.Should().Contain(Convert.ToBase64String(_spCert.RawData));
        metadata.Should().Contain(Convert.ToBase64String(_spDecCert.RawData));
    }

    [Fact]
    public void GenerateSpMetadata_UnsignedAndNoCertificates_OmitsOptionalKeyDescriptors()
    {
        _options.SignAuthnRequests = false;
        _options.RequireSignedMessages = false;
        _options.SpSigningCertificate = null;
        _options.SpDecryptionCertificate = null;
        _options.SpSingleLogoutUrl = null;

        var metadata = _service.GenerateSpMetadata();

        metadata.Should().NotBeNull();
        metadata.Should().Contain("AuthnRequestsSigned=\"false\"");
        metadata.Should().Contain("WantAssertionsSigned=\"false\"");
        metadata.Should().NotContain("KeyDescriptor");
        metadata.Should().NotContain("SingleLogoutService");
    }

    [Fact]
    public async Task ProcessResponseAsync_ValidResponse_ReturnsAuthenticatedPrincipal()
    {
        var xml = new SamlTestMessageBuilder()
            .WithResponseId("_resp1")
            .WithAssertionId("_assert1")
            .WithSubject("john.doe@example.com")
            .WithSubjectConfirmation("https://sp.example.com/saml/acs", new DateTimeOffset(2030, 1, 1, 0, 0, 0, TimeSpan.Zero))
            .WithConditions(new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero), new DateTimeOffset(2030, 1, 1, 0, 0, 0, TimeSpan.Zero))
            .WithAudience("https://sp.example.com")
            .WithAuthnStatement(new DateTimeOffset(2026, 8, 31, 0, 0, 0, TimeSpan.Zero), "_session_789")
            .WithAttribute("name", "John Doe", "Full Name")
            .WithAttribute("role", ["Admin", "Superuser"])
            .BuildXml();

        var result = await _service.ProcessResponseAsync(xml);

        result.IsSuccess.Should().BeTrue();
        result.Value.NameId.Should().Be("john.doe@example.com");
        result.Value.Principal.FindFirst(ClaimTypes.NameIdentifier)?.Value.Should().Be("john.doe@example.com");
        result.Value.Principal.FindFirst(ClaimTypes.Name)?.Value.Should().Be("John Doe");
        result.Value.Principal.FindAll(ClaimTypes.Role).Should().HaveCount(2);
        result.Value.Assertion.AuthnStatement?.SessionIndex.Should().Be("_session_789");
    }

    [Fact]
    public async Task ProcessResponseAsync_Base64Encoded_ReturnsAuthenticatedPrincipal()
    {
        var xml = new SamlTestMessageBuilder()
            .WithResponseId("_resp1")
            .WithAssertionId("_assert1")
            .WithSubject("b64.user@example.com")
            .BuildXml();

        var base64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(xml));
        var result = await _service.ProcessResponseAsync(base64);

        result.IsSuccess.Should().BeTrue();
        result.Value.NameId.Should().Be("b64.user@example.com");
    }

    [Fact]
    public async Task ProcessResponseAsync_MissingNameId_ReturnsFailure()
    {
        var xml = @"<samlp:Response xmlns:samlp=""urn:oasis:names:tc:SAML:2.0:protocol"" xmlns:saml=""urn:oasis:names:tc:SAML:2.0:assertion"" ID=""_resp1"" Version=""2.0"">
  <saml:Issuer>https://idp.example.com</saml:Issuer>
  <samlp:Status><samlp:StatusCode Value=""urn:oasis:names:tc:SAML:2.0:status:Success""/></samlp:Status>
  <saml:Assertion ID=""_assert1"" Version=""2.0"">
    <saml:Issuer>https://idp.example.com</saml:Issuer>
    <saml:Subject></saml:Subject>
  </saml:Assertion>
</samlp:Response>";

        var result = await _service.ProcessResponseAsync(xml);

        result.IsFailure.Should().BeTrue();
        result.Error.Description.Should().Contain("Assertion missing required <saml:NameID>");
    }

    [Fact]
    public async Task ProcessResponseAsync_NotBeforeInFuture_ReturnsFailure()
    {
        var future = DateTimeOffset.UtcNow.AddHours(2).ToString("o");
        var xml = $@"<samlp:Response xmlns:samlp=""urn:oasis:names:tc:SAML:2.0:protocol"" xmlns:saml=""urn:oasis:names:tc:SAML:2.0:assertion"" ID=""_resp1"" Version=""2.0"">
  <saml:Issuer>https://idp.example.com</saml:Issuer>
  <samlp:Status><samlp:StatusCode Value=""urn:oasis:names:tc:SAML:2.0:status:Success""/></samlp:Status>
  <saml:Assertion ID=""_assert1"" Version=""2.0"">
    <saml:Issuer>https://idp.example.com</saml:Issuer>
    <saml:Subject><saml:NameID>future@example.com</saml:NameID></saml:Subject>
    <saml:Conditions NotBefore=""{future}""/>
  </saml:Assertion>
</samlp:Response>";

        var result = await _service.ProcessResponseAsync(xml);

        result.IsFailure.Should().BeTrue();
        result.Error.Description.Should().Contain("not yet valid");
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public async Task ProcessResponseAsync_EmptyOrWhitespace_ThrowsArgumentException(string emptyXml)
    {
        await Assert.ThrowsAsync<ArgumentException>(() => _service.ProcessResponseAsync(emptyXml));
    }

    [Fact]
    public async Task ProcessResponseAsync_Null_ThrowsArgumentNullException()
    {
        await Assert.ThrowsAsync<ArgumentNullException>(() => _service.ProcessResponseAsync(null!));
    }

    [Fact]
    public async Task ProcessResponseAsync_MalformedXml_ReturnsFailure()
    {
        var result = await _service.ProcessResponseAsync("not valid xml <<<");
        result.IsFailure.Should().BeTrue();
        result.Error.Description.Should().Contain("Failed to process SAML response");
    }

    [Fact]
    public async Task ProcessResponseAsync_ErrorStatus_ReturnsFailure()
    {
        var xml = new SamlTestMessageBuilder()
            .WithResponseId("_resp_err")
            .WithStatusCode("urn:oasis:names:tc:SAML:2.0:status:Responder")
            .WithSecondaryStatusCode("urn:oasis:names:tc:SAML:2.0:status:AuthnFailed")
            .WithStatusMessage("User authentication failed at IdP.")
            .WithoutAssertion()
            .BuildXml();

        var result = await _service.ProcessResponseAsync(xml);

        result.IsFailure.Should().BeTrue();
        result.Error.Code.Should().Be("Security.PolicyViolation");
        result.Error.Description.Should().Contain("SAML.Status");
        result.Error.Description.Should().Contain("User authentication failed");
    }

    [Fact]
    public async Task ProcessResponseAsync_IssuerMismatch_ReturnsFailure()
    {
        var xml = new SamlTestMessageBuilder()
            .WithIssuer("https://untrusted-idp.example.com")
            .BuildXml();

        var result = await _service.ProcessResponseAsync(xml);

        result.IsFailure.Should().BeTrue();
        result.Error.Code.Should().Be("Security.PolicyViolation");
        result.Error.Description.Should().Contain("SAML.Issuer");
        result.Error.Description.Should().Contain("Response issuer mismatch");
    }

    [Fact]
    public async Task ProcessResponseAsync_InResponseToMismatch_ReturnsFailure()
    {
        var xml = new SamlTestMessageBuilder()
            .WithInResponseTo("_wrong_req_id")
            .BuildXml();

        var result = await _service.ProcessResponseAsync(xml, expectedInResponseTo: "_expected_req_id");

        result.IsFailure.Should().BeTrue();
        result.Error.Code.Should().Be("Security.PolicyViolation");
        result.Error.Description.Should().Contain("SAML.InResponseTo");
        result.Error.Description.Should().Contain("InResponseTo mismatch: expected '_expected_req_id', got '_wrong_req_id'.");
    }

    [Fact]
    public async Task ProcessResponseAsync_InResponseToMatches_ProceedsValidation()
    {
        var xml = new SamlTestMessageBuilder()
            .WithInResponseTo("_matching_req_id")
            .BuildXml();

        var result = await _service.ProcessResponseAsync(xml, expectedInResponseTo: "_matching_req_id");

        result.IsSuccess.Should().BeTrue();
    }

    [Fact]
    public async Task ProcessResponseAsync_AudienceMismatch_ReturnsFailure()
    {
        var xml = @"<samlp:Response xmlns:samlp=""urn:oasis:names:tc:SAML:2.0:protocol"" xmlns:saml=""urn:oasis:names:tc:SAML:2.0:assertion"" ID=""_resp1"" Version=""2.0"" IssueInstant=""2026-08-31T00:00:00Z"">
  <saml:Issuer>https://idp.example.com</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value=""urn:oasis:names:tc:SAML:2.0:status:Success""/>
  </samlp:Status>
  <saml:Assertion ID=""_assert_aud"" Version=""2.0"" IssueInstant=""2026-08-31T00:00:00Z"">
    <saml:Issuer>https://idp.example.com</saml:Issuer>
    <saml:Subject>
      <saml:NameID>john.doe@example.com</saml:NameID>
    </saml:Subject>
    <saml:Conditions NotBefore=""2026-01-01T00:00:00Z"" NotOnOrAfter=""2030-01-01T00:00:00Z"">
      <saml:AudienceRestriction>
        <saml:Audience>https://wrong-sp.example.com</saml:Audience>
      </saml:AudienceRestriction>
    </saml:Conditions>
  </saml:Assertion>
</samlp:Response>";

        var result = await _service.ProcessResponseAsync(xml);

        result.IsFailure.Should().BeTrue();
        result.Error.Code.Should().Be("Security.PolicyViolation");
        result.Error.Description.Should().Contain("SAML.Audience");
        result.Error.Description.Should().Contain("Assertion audience does not match");
    }

    [Fact]
    public async Task ProcessResponseAsync_ExpiredAssertion_ReturnsFailure()
    {
        var xml = @"<samlp:Response xmlns:samlp=""urn:oasis:names:tc:SAML:2.0:protocol"" xmlns:saml=""urn:oasis:names:tc:SAML:2.0:assertion"" ID=""_resp1"" Version=""2.0"" IssueInstant=""2020-01-01T00:00:00Z"">
  <saml:Issuer>https://idp.example.com</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value=""urn:oasis:names:tc:SAML:2.0:status:Success""/>
  </samlp:Status>
  <saml:Assertion ID=""_assert_exp"" Version=""2.0"" IssueInstant=""2020-01-01T00:00:00Z"">
    <saml:Issuer>https://idp.example.com</saml:Issuer>
    <saml:Subject>
      <saml:NameID>john.doe@example.com</saml:NameID>
    </saml:Subject>
    <saml:Conditions NotBefore=""2020-01-01T00:00:00Z"" NotOnOrAfter=""2020-01-01T01:00:00Z"">
      <saml:AudienceRestriction>
        <saml:Audience>https://sp.example.com</saml:Audience>
      </saml:AudienceRestriction>
    </saml:Conditions>
  </saml:Assertion>
</samlp:Response>";

        var result = await _service.ProcessResponseAsync(xml);

        result.IsFailure.Should().BeTrue();
        result.Error.Code.Should().Be("Security.TokenExpired");
        result.Error.Description.Should().Contain("Assertion has expired");
    }

    [Fact]
    public async Task ProcessIdpInitiatedResponseAsync_Disabled_ReturnsFailure()
    {
        _options.AllowIdpInitiatedSso = false;
        var xml = @"<samlp:Response xmlns:samlp=""urn:oasis:names:tc:SAML:2.0:protocol""/>";

        var result = await _service.ProcessIdpInitiatedResponseAsync(xml);

        result.IsFailure.Should().BeTrue();
        result.Error.Code.Should().Be("Security.PolicyViolation");
        result.Error.Description.Should().Contain("SAML.IdpInitiated");
        result.Error.Description.Should().Contain("IdP-initiated SSO is disabled");
    }

    [Fact]
    public async Task ProcessIdpInitiatedResponseAsync_WithInResponseTo_ReturnsFailure()
    {
        var xml = @"<samlp:Response xmlns:samlp=""urn:oasis:names:tc:SAML:2.0:protocol"" xmlns:saml=""urn:oasis:names:tc:SAML:2.0:assertion"" ID=""_resp1"" InResponseTo=""_unexpected_id"" Version=""2.0"">
  <saml:Issuer>https://idp.example.com</saml:Issuer>
  <samlp:Status><samlp:StatusCode Value=""urn:oasis:names:tc:SAML:2.0:status:Success""/></samlp:Status>
  <saml:Assertion ID=""_assert1"" Version=""2.0"">
    <saml:Issuer>https://idp.example.com</saml:Issuer>
    <saml:Subject><saml:NameID>user@example.com</saml:NameID></saml:Subject>
  </saml:Assertion>
</samlp:Response>";

        var result = await _service.ProcessIdpInitiatedResponseAsync(xml);

        result.IsFailure.Should().BeTrue();
        result.Error.Code.Should().Be("Security.PolicyViolation");
        result.Error.Description.Should().Contain("SAML.IdpInitiated");
        result.Error.Description.Should().Contain("Unexpected InResponseTo");
    }

    [Fact]
    public async Task ProcessIdpInitiatedResponseAsync_ReplayAttack_ReturnsFailure()
    {
        var xml = @"<samlp:Response xmlns:samlp=""urn:oasis:names:tc:SAML:2.0:protocol"" xmlns:saml=""urn:oasis:names:tc:SAML:2.0:assertion"" ID=""_resp_replay"" Version=""2.0"">
  <saml:Issuer>https://idp.example.com</saml:Issuer>
  <samlp:Status><samlp:StatusCode Value=""urn:oasis:names:tc:SAML:2.0:status:Success""/></samlp:Status>
  <saml:Assertion ID=""_assert_replay_1"" Version=""2.0"">
    <saml:Issuer>https://idp.example.com</saml:Issuer>
    <saml:Subject><saml:NameID>user@example.com</saml:NameID></saml:Subject>
    <saml:Conditions NotBefore=""2026-01-01T00:00:00Z"" NotOnOrAfter=""2030-01-01T00:00:00Z""/>
  </saml:Assertion>
</samlp:Response>";

        var res1 = await _service.ProcessIdpInitiatedResponseAsync(xml);
        res1.IsSuccess.Should().BeTrue();

        // Second time using identical assertion ID
        var res2 = await _service.ProcessIdpInitiatedResponseAsync(xml);
        res2.IsFailure.Should().BeTrue();
        res2.Error.Code.Should().Be("Security.PolicyViolation");
        res2.Error.Description.Should().Contain("SAML.ReplayAttack");
        res2.Error.Description.Should().Contain("Replay attack mitigated");
        _logger.Messages.Should().Contain(m => m.Contains("SAML assertion replay attack detected. AssertionId=_assert_replay_1 was already processed."));
    }

    [Fact]
    public async Task ProcessResponseAsync_SubjectConfirmation_RecipientMismatch_ReturnsFailure()
    {
        var xml = @"<samlp:Response xmlns:samlp=""urn:oasis:names:tc:SAML:2.0:protocol"" xmlns:saml=""urn:oasis:names:tc:SAML:2.0:assertion"" ID=""_resp1"" Version=""2.0"">
  <saml:Issuer>https://idp.example.com</saml:Issuer>
  <samlp:Status><samlp:StatusCode Value=""urn:oasis:names:tc:SAML:2.0:status:Success""/></samlp:Status>
  <saml:Assertion ID=""_assert_sub_rec"" Version=""2.0"">
    <saml:Issuer>https://idp.example.com</saml:Issuer>
    <saml:Subject>
      <saml:NameID>user@example.com</saml:NameID>
      <saml:SubjectConfirmation Method=""urn:oasis:names:tc:SAML:2.0:cm:bearer"">
        <saml:SubjectConfirmationData Recipient=""https://wrong-sp.example.com/acs""/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore=""2026-01-01T00:00:00Z"" NotOnOrAfter=""2030-01-01T00:00:00Z""/>
  </saml:Assertion>
</samlp:Response>";

        var result = await _service.ProcessResponseAsync(xml);

        result.IsFailure.Should().BeTrue();
        result.Error.Code.Should().Be("Security.PolicyViolation");
        result.Error.Description.Should().Contain("SAML.Recipient");
        result.Error.Description.Should().Contain("Recipient mismatch");
    }

    [Fact]
    public async Task ProcessLogoutResponseAsync_ValidResponse_ReturnsSuccess()
    {
        var xml = @"<samlp:LogoutResponse xmlns:samlp=""urn:oasis:names:tc:SAML:2.0:protocol"" xmlns:saml=""urn:oasis:names:tc:SAML:2.0:assertion"" ID=""_lo_resp_ok"" InResponseTo=""_my_lo_req"" Version=""2.0"" IssueInstant=""2026-09-03T12:00:00Z"">
  <saml:Issuer>https://idp.example.com</saml:Issuer>
  <samlp:Status><samlp:StatusCode Value=""urn:oasis:names:tc:SAML:2.0:status:Success""/></samlp:Status>
</samlp:LogoutResponse>";

        var result = await _service.ProcessLogoutResponseAsync(xml, expectedInResponseTo: "_my_lo_req");

        result.IsSuccess.Should().BeTrue();
        result.Value.Id.Should().Be("_lo_resp_ok");
        result.Value.InResponseTo.Should().Be("_my_lo_req");
        result.Value.StatusCode.Should().Be("urn:oasis:names:tc:SAML:2.0:status:Success");
        result.Value.IssueInstant.Should().Be(DateTimeOffset.Parse("2026-09-03T12:00:00Z"));
        result.Value.IsSuccess.Should().BeTrue();
    }

    [Fact]
    public async Task ProcessLogoutResponseAsync_InResponseToMismatch_ReturnsFailure()
    {
        var xml = @"<samlp:LogoutResponse xmlns:samlp=""urn:oasis:names:tc:SAML:2.0:protocol"" xmlns:saml=""urn:oasis:names:tc:SAML:2.0:assertion"" ID=""_lo_resp_ok"" InResponseTo=""_wrong_req"" Version=""2.0"">
  <saml:Issuer>https://idp.example.com</saml:Issuer>
  <samlp:Status><samlp:StatusCode Value=""urn:oasis:names:tc:SAML:2.0:status:Success""/></samlp:Status>
</samlp:LogoutResponse>";

        var result = await _service.ProcessLogoutResponseAsync(xml, expectedInResponseTo: "_expected_req");

        result.IsFailure.Should().BeTrue();
        result.Error.Code.Should().Be("Security.PolicyViolation");
        result.Error.Description.Should().Contain("SAML.SLO.InResponseTo");
        result.Error.Description.Should().Contain("InResponseTo mismatch");
    }

    [Fact]
    public async Task ProcessLogoutResponseAsync_IdpError_ReturnsFailure()
    {
        var xml = @"<samlp:LogoutResponse xmlns:samlp=""urn:oasis:names:tc:SAML:2.0:protocol"" xmlns:saml=""urn:oasis:names:tc:SAML:2.0:assertion"" ID=""_lo_resp_err"" InResponseTo=""_req_1"" Version=""2.0"">
  <saml:Issuer>https://idp.example.com</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value=""urn:oasis:names:tc:SAML:2.0:status:Responder""/>
    <samlp:StatusMessage>Logout session not found.</samlp:StatusMessage>
  </samlp:Status>
</samlp:LogoutResponse>";

        var result = await _service.ProcessLogoutResponseAsync(xml, expectedInResponseTo: "_req_1");

        result.IsFailure.Should().BeTrue();
        result.Error.Code.Should().Be("Security.PolicyViolation");
        result.Error.Description.Should().Contain("SAML.SLO.Status");
        result.Error.Description.Should().Contain("Logout session not found");
        _logger.Messages.Should().Contain(m => m.Contains("SAML SLO: IdP returned non-success status. StatusCode=urn:oasis:names:tc:SAML:2.0:status:Responder, Message=Logout session not found."));
    }

    [Fact]
    public async Task ProcessResponseAsync_RequireSignedMessages_WithValidSignature_Succeeds()
    {
        _options.RequireSignedMessages = true;

        var xml = @"<samlp:Response xmlns:samlp=""urn:oasis:names:tc:SAML:2.0:protocol"" xmlns:saml=""urn:oasis:names:tc:SAML:2.0:assertion"" ID=""_resp_signed"" Version=""2.0"" IssueInstant=""2026-08-31T00:00:00Z"">
  <saml:Issuer>https://idp.example.com</saml:Issuer>
  <samlp:Status><samlp:StatusCode Value=""urn:oasis:names:tc:SAML:2.0:status:Success""/></samlp:Status>
  <saml:Assertion ID=""_assert_signed"" Version=""2.0"" IssueInstant=""2026-08-31T00:00:00Z"">
    <saml:Issuer>https://idp.example.com</saml:Issuer>
    <saml:Subject><saml:NameID>alice@example.com</saml:NameID></saml:Subject>
    <saml:Conditions NotBefore=""2026-01-01T00:00:00Z"" NotOnOrAfter=""2030-01-01T00:00:00Z"">
      <saml:AudienceRestriction><saml:Audience>https://sp.example.com</saml:Audience></saml:AudienceRestriction>
    </saml:Conditions>
  </saml:Assertion>
</samlp:Response>";

        var doc = new XmlDocument { XmlResolver = null, PreserveWhitespace = true };
        doc.LoadXml(xml);

        // Sign the response root with IdP private key
        _sigValidator.SignElement(doc.DocumentElement!, _idpCert);

        var result = await _service.ProcessResponseAsync(doc.OuterXml);

        result.IsSuccess.Should().BeTrue();
        result.Value.NameId.Should().Be("alice@example.com");
    }

    [Fact]
    public async Task ProcessResponseAsync_RequireSignedMessages_MissingIdpCert_ReturnsFailure()
    {
        _options.RequireSignedMessages = true;
        _options.IdpSigningCertificate = null;

        var xml = @"<samlp:Response xmlns:samlp=""urn:oasis:names:tc:SAML:2.0:protocol"" xmlns:saml=""urn:oasis:names:tc:SAML:2.0:assertion"" ID=""_resp1"" Version=""2.0"">
  <saml:Issuer>https://idp.example.com</saml:Issuer>
  <samlp:Status><samlp:StatusCode Value=""urn:oasis:names:tc:SAML:2.0:status:Success""/></samlp:Status>
  <saml:Assertion ID=""_assert1"" Version=""2.0"">
    <saml:Issuer>https://idp.example.com</saml:Issuer>
    <saml:Subject><saml:NameID>user@example.com</saml:NameID></saml:Subject>
  </saml:Assertion>
</samlp:Response>";

        var result = await _service.ProcessResponseAsync(xml);

        result.IsFailure.Should().BeTrue();
        result.Error.Description.Should().Contain("IdpSigningCertificate is not configured");
    }

    [Fact]
    public async Task ProcessResponseAsync_RequireSignedMessages_UnsignedResponse_ReturnsFailure()
    {
        _options.RequireSignedMessages = true;

        var xml = @"<samlp:Response xmlns:samlp=""urn:oasis:names:tc:SAML:2.0:protocol"" xmlns:saml=""urn:oasis:names:tc:SAML:2.0:assertion"" ID=""_resp1"" Version=""2.0"">
  <saml:Issuer>https://idp.example.com</saml:Issuer>
  <samlp:Status><samlp:StatusCode Value=""urn:oasis:names:tc:SAML:2.0:status:Success""/></samlp:Status>
  <saml:Assertion ID=""_assert1"" Version=""2.0"">
    <saml:Issuer>https://idp.example.com</saml:Issuer>
    <saml:Subject><saml:NameID>user@example.com</saml:NameID></saml:Subject>
  </saml:Assertion>
</samlp:Response>";

        var result = await _service.ProcessResponseAsync(xml);

        result.IsFailure.Should().BeTrue();
        result.Error.Code.Should().Be("Security.DecryptionFailed");
        result.Error.Description.Should().Contain("Neither Assertion nor Response contains a valid XMLDSig signature");
    }

    [Fact]
    public async Task ProcessResponseAsync_EncryptedAssertion_WithoutDecryptionCertificate_ReturnsFailure()
    {
        _options.SpDecryptionCertificate = null;

        var xml = @"<samlp:Response xmlns:samlp=""urn:oasis:names:tc:SAML:2.0:protocol"" xmlns:saml=""urn:oasis:names:tc:SAML:2.0:assertion"" ID=""_resp1"" Version=""2.0"">
  <saml:Issuer>https://idp.example.com</saml:Issuer>
  <samlp:Status><samlp:StatusCode Value=""urn:oasis:names:tc:SAML:2.0:status:Success""/></samlp:Status>
  <saml:EncryptedAssertion ID=""_enc1""/>
</samlp:Response>";

        var result = await _service.ProcessResponseAsync(xml);

        result.IsFailure.Should().BeTrue();
        result.Error.Description.Should().Contain("no SpDecryptionCertificate configured");
    }

    [Fact]
    public void Constructor_NullArguments_ThrowsArgumentNullException()
    {
        var options = Options.Create(new Saml2Options());
        var xsw = new Saml2XswValidator();
        var sig = new Saml2SignatureValidator();
        var dec = new Saml2AssertionDecryptor();
        var map = new Saml2ClaimsMapper();

        Assert.Throws<ArgumentNullException>(() => new Saml2Service(null!, xsw, sig, dec, map));
        Assert.Throws<ArgumentNullException>(() => new Saml2Service(options, null!, sig, dec, map));
        Assert.Throws<ArgumentNullException>(() => new Saml2Service(options, xsw, null!, dec, map));
        Assert.Throws<ArgumentNullException>(() => new Saml2Service(options, xsw, sig, null!, map));
        Assert.Throws<ArgumentNullException>(() => new Saml2Service(options, xsw, sig, dec, null!));
    }

    [Fact]
    public async Task ProcessResponseAsync_CancelledToken_ThrowsOperationCanceledException()
    {
        var xml = new SamlTestMessageBuilder().BuildXml();
        using var cts = new System.Threading.CancellationTokenSource();
        cts.Cancel();

        await Assert.ThrowsAsync<OperationCanceledException>(() =>
            _service.ProcessResponseAsync(xml, cancellationToken: cts.Token));
    }

    [Theory]
    [InlineData(Saml2NameIdFormat.Transient, "transient")]
    [InlineData(Saml2NameIdFormat.Persistent, "persistent")]
    [InlineData(Saml2NameIdFormat.Unspecified, "unspecified")]
    [InlineData((Saml2NameIdFormat)999, "unspecified")]
    public void GenerateSpMetadata_OtherFormatsAndSlo_IncludesUrnAndSlo(Saml2NameIdFormat format, string expected)
    {
        _options.DefaultNameIdFormat = format;
        _options.SpSingleLogoutUrl = "https://sp.example.com/saml/slo";
        _options.SpDecryptionCertificate = _spDecCert;
        var metadata = _service.GenerateSpMetadata();
        metadata.Should().StartWith("<?xml version=\"1.0\" encoding=\"utf-16\"?>");
        metadata.Should().Contain("\r\n");
        metadata.Should().Contain("xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\"");
        metadata.Should().Contain("xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"");
        metadata.Should().Contain("<md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://sp.example.com/saml/slo\" />");
        metadata.Should().Contain("<md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"https://sp.example.com/saml/slo\" />");
        metadata.Should().Contain("<md:AssertionConsumerService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://sp.example.com/saml/acs\" index=\"1\" isDefault=\"true\" />");
        metadata.Should().Contain(expected);
        metadata.Should().Contain("use=\"encryption\"");
        metadata.Should().Contain($"entityID=\"{_options.SpEntityId}\"");
        metadata.Should().Contain("AuthnRequestsSigned=\"false\"");
        metadata.Should().Contain("WantAssertionsSigned=\"false\"");
        metadata.Should().Contain("protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\"");
    }

    [Fact]
    public void CreateLogoutResponse_Signed_IncludesSignature()
    {
        _options.SignLogoutRequests = true;
        _options.SpSigningCertificate = _spCert;
        var response = _service.CreateLogoutResponse("_req1", "https://idp.example.com/slo", success: true);
        response.RawXml.Should().Contain("Version=\"2.0\"");
        response.Id.Should().StartWith("_");
        response.Id.Length.Should().Be(33);
        response.RawXml.Should().Contain($"ID=\"{response.Id}\"");
        response.RawXml.Should().Contain("InResponseTo=\"_req1\"");
        response.RawXml.Should().Contain("Destination=\"https://idp.example.com/slo\"");
        response.RawXml.Should().Contain("IssueInstant=\"");
        response.RawXml.Should().Contain($"IssueInstant=\"{response.IssueInstant:o}\"");
        response.RawXml.Should().Contain("https://sp.example.com</saml:Issuer>");
        response.RawXml.Should().Contain("<samlp:Status");
        response.RawXml.Should().Contain("<samlp:StatusCode");
        response.RawXml.Should().Contain("</samlp:Status>");
        response.RawXml.Should().Contain("<Signature");
    }

    [Fact]
    public async Task ProcessResponseAsync_XmlWithoutRoot_ReturnsFailure()
    {
        var result = await _service.ProcessResponseAsync("<!-- comment only -->");
        result.IsFailure.Should().BeTrue();
        result.Error.Description.Should().Contain("Root element is missing");
    }

    [Fact]
    public async Task ProcessResponseAsync_ErrorStatusWithMessage_ReturnsFailure()
    {
        var xml = @"<samlp:Response xmlns:samlp=""urn:oasis:names:tc:SAML:2.0:protocol"" xmlns:saml=""urn:oasis:names:tc:SAML:2.0:assertion"" ID=""_resp1"" Version=""2.0"">
  <samlp:Status>
    <samlp:StatusCode Value=""urn:oasis:names:tc:SAML:2.0:status:Requester""/>
    <samlp:StatusMessage>Authentication failed at IdP.</samlp:StatusMessage>
  </samlp:Status>
</samlp:Response>";
        var result = await _service.ProcessResponseAsync(xml);
        result.IsFailure.Should().BeTrue();
        result.Error.Code.Should().Be("Security.PolicyViolation");
        result.Error.Description.Should().Contain("SAML.Status");
        result.Error.Description.Should().Contain("Authentication failed at IdP.");
    }

    [Fact]
    public async Task ProcessResponseAsync_ResponseIssuerMismatch_ReturnsFailure()
    {
        _options.IdpEntityId = "https://idp.example.com";
        var xml = @"<samlp:Response xmlns:samlp=""urn:oasis:names:tc:SAML:2.0:protocol"" xmlns:saml=""urn:oasis:names:tc:SAML:2.0:assertion"" ID=""_resp1"" Version=""2.0"">
  <saml:Issuer>https://idp.rogue.com</saml:Issuer>
  <samlp:Status><samlp:StatusCode Value=""urn:oasis:names:tc:SAML:2.0:status:Success""/></samlp:Status>
  <saml:Assertion ID=""_a1""><saml:Issuer>https://idp.example.com</saml:Issuer><saml:Subject><saml:NameID>u</saml:NameID></saml:Subject></saml:Assertion>
</samlp:Response>";
        var result = await _service.ProcessResponseAsync(xml);
        result.IsFailure.Should().BeTrue();
        result.Error.Code.Should().Be("Security.PolicyViolation");
        result.Error.Description.Should().Contain("SAML.Issuer");
        result.Error.Description.Should().Contain("Response issuer mismatch");
    }

    [Fact]
    public async Task ProcessResponseAsync_AssertionIssuerMismatch_ReturnsFailure()
    {
        _options.IdpEntityId = "https://idp.example.com";
        var xml = @"<samlp:Response xmlns:samlp=""urn:oasis:names:tc:SAML:2.0:protocol"" xmlns:saml=""urn:oasis:names:tc:SAML:2.0:assertion"" ID=""_resp1"" Version=""2.0"">
  <saml:Issuer>https://idp.example.com</saml:Issuer>
  <samlp:Status><samlp:StatusCode Value=""urn:oasis:names:tc:SAML:2.0:status:Success""/></samlp:Status>
  <saml:Assertion ID=""_a1""><saml:Issuer>https://idp.rogue.com</saml:Issuer><saml:Subject><saml:NameID>u</saml:NameID></saml:Subject></saml:Assertion>
</samlp:Response>";
        var result = await _service.ProcessResponseAsync(xml);
        result.IsFailure.Should().BeTrue();
        result.Error.Code.Should().Be("Security.PolicyViolation");
        result.Error.Description.Should().Contain("SAML.Issuer");
        result.Error.Description.Should().Contain("Assertion Issuer mismatch");
    }

    [Fact]
    public async Task ProcessResponseAsync_EmptySubjectElement_ReturnsFailure()
    {
        var xml = @"<samlp:Response xmlns:samlp=""urn:oasis:names:tc:SAML:2.0:protocol"" xmlns:saml=""urn:oasis:names:tc:SAML:2.0:assertion"" ID=""_resp1"" Version=""2.0"">
  <samlp:Status><samlp:StatusCode Value=""urn:oasis:names:tc:SAML:2.0:status:Success""/></samlp:Status>
  <saml:Assertion ID=""_a1""><saml:Issuer>https://idp.example.com</saml:Issuer><saml:Subject></saml:Subject></saml:Assertion>
</samlp:Response>";
        var result = await _service.ProcessResponseAsync(xml);
        result.IsFailure.Should().BeTrue();
        result.Error.Description.Should().Contain("Assertion missing required <saml:NameID>");
    }

    [Fact]
    public async Task ProcessResponseAsync_DecryptionFailure_ReturnsFailure()
    {
        var xml = @"<samlp:Response xmlns:samlp=""urn:oasis:names:tc:SAML:2.0:protocol"" xmlns:saml=""urn:oasis:names:tc:SAML:2.0:assertion"" ID=""_resp1"" Version=""2.0"">
  <samlp:Status><samlp:StatusCode Value=""urn:oasis:names:tc:SAML:2.0:status:Success""/></samlp:Status>
  <saml:EncryptedAssertion ID=""_enc1""><invalid/></saml:EncryptedAssertion>
</samlp:Response>";
        var result = await _service.ProcessResponseAsync(xml);
        result.IsFailure.Should().BeTrue();
    }

    [Fact]
    public async Task ProcessResponseAsync_WithAuthnStatementAndAttributes_Parsed()
    {
        var xml = @"<samlp:Response xmlns:samlp=""urn:oasis:names:tc:SAML:2.0:protocol"" xmlns:saml=""urn:oasis:names:tc:SAML:2.0:assertion"" ID=""_resp1"" Version=""2.0"">
  <saml:Issuer>https://idp.example.com</saml:Issuer>
  <samlp:Status><samlp:StatusCode Value=""urn:oasis:names:tc:SAML:2.0:status:Success""/></samlp:Status>
  <saml:Assertion ID=""_a1"" Version=""2.0"">
    <saml:Issuer>https://idp.example.com</saml:Issuer>
    <saml:Subject>
      <saml:NameID>alice@example.com</saml:NameID>
    </saml:Subject>
    <saml:AuthnStatement AuthnInstant=""2026-09-01T12:00:00Z"" SessionIndex=""sess_42""/>
    <saml:AttributeStatement>
      <saml:Attribute Name=""roles"" FriendlyName=""Roles"">
        <saml:AttributeValue>Admin</saml:AttributeValue>
        <saml:AttributeValue></saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute Name="""">
        <saml:AttributeValue>Ignored</saml:AttributeValue>
      </saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>";
        var result = await _service.ProcessResponseAsync(xml);
        result.IsSuccess.Should().BeTrue();
        result.Value.Assertion.Id.Should().Be("_a1");
        result.Value.Assertion.AuthnStatement.Should().NotBeNull();
        result.Value.Assertion.AuthnStatement!.SessionIndex.Should().Be("sess_42");
        result.Value.Assertion.AuthnStatement.AuthnInstant.Should().Be(DateTimeOffset.Parse("2026-09-01T12:00:00Z"));
        result.Value.Assertion.Attributes.Should().ContainSingle(a => a.Name == "roles");
        result.Value.Assertion.Attributes.First(a => a.Name == "roles").FriendlyName.Should().Be("Roles");
    }

    [Fact]
    public async Task ProcessResponseAsync_WithoutAssertionId_GeneratesFallbackId()
    {
        var xml = @"<samlp:Response xmlns:samlp=""urn:oasis:names:tc:SAML:2.0:protocol"" xmlns:saml=""urn:oasis:names:tc:SAML:2.0:assertion"" ID=""_resp1"" Version=""2.0"">
  <saml:Issuer>https://idp.example.com</saml:Issuer>
  <samlp:Status><samlp:StatusCode Value=""urn:oasis:names:tc:SAML:2.0:status:Success""/></samlp:Status>
  <saml:Assertion Version=""2.0"">
    <saml:Issuer>https://idp.example.com</saml:Issuer>
    <saml:Subject><saml:NameID>alice@example.com</saml:NameID></saml:Subject>
  </saml:Assertion>
</samlp:Response>";
        var result = await _service.ProcessResponseAsync(xml);
        result.IsSuccess.Should().BeTrue();
        result.Value.Assertion.Id.Should().NotBeNullOrWhiteSpace();
        result.Value.Assertion.Id.Length.Should().Be(32);
    }

    [Fact]
    public async Task ProcessIdpInitiatedResponseAsync_Base64Encoded_Success()
    {
        var xml = new SamlTestMessageBuilder().WithAssertionId("_b64_assert_" + Guid.NewGuid().ToString("N")).BuildXml();
        var b64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(xml));
        var result = await _service.ProcessIdpInitiatedResponseAsync(b64);
        result.IsSuccess.Should().BeTrue();
    }

    [Fact]
    public async Task ProcessIdpInitiatedResponseAsync_DuplicateAssertionId_ReturnsFailure()
    {
        var uniqueId = "_replay_assert_" + Guid.NewGuid().ToString("N");
        var xml = new SamlTestMessageBuilder().WithAssertionId(uniqueId).BuildXml();
        var firstResult = await _service.ProcessIdpInitiatedResponseAsync(xml);
        firstResult.IsSuccess.Should().BeTrue();

        var replayResult = await _service.ProcessIdpInitiatedResponseAsync(xml);
        replayResult.IsFailure.Should().BeTrue();
        replayResult.Error.Description.Should().Contain("Replay attack mitigated");
    }

    [Fact]
    public async Task ProcessIdpInitiatedResponseAsync_MalformedAndNoRootXml_ReturnsFailure()
    {
        var malformed = await _service.ProcessIdpInitiatedResponseAsync("<invalid xml");
        malformed.IsFailure.Should().BeTrue();

        var noRoot = await _service.ProcessIdpInitiatedResponseAsync("<!-- comment only -->");
        noRoot.IsFailure.Should().BeTrue();
        noRoot.Error.Description.Should().Contain("Root element is missing");
    }

    [Fact]
    public async Task ProcessLogoutResponseAsync_Base64Encoded_Success()
    {
        var xml = @"<samlp:LogoutResponse xmlns:samlp=""urn:oasis:names:tc:SAML:2.0:protocol"" xmlns:saml=""urn:oasis:names:tc:SAML:2.0:assertion"" ID=""_lr1"" InResponseTo=""_req1"">
  <saml:Issuer>https://idp.example.com</saml:Issuer>
  <samlp:Status><samlp:StatusCode Value=""urn:oasis:names:tc:SAML:2.0:status:Success""/></samlp:Status>
</samlp:LogoutResponse>";
        var b64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(xml));
        var result = await _service.ProcessLogoutResponseAsync(b64, "_req1");
        result.IsSuccess.Should().BeTrue();
        result.Value.Id.Should().Be("_lr1");
        _logger.Messages.Should().Contain(m => m.Contains("SAML SLO completed successfully"));
    }

    [Fact]
    public async Task ProcessLogoutResponseAsync_InResponseToDifferent_ReturnsFailure()
    {
        var xml = @"<samlp:LogoutResponse xmlns:samlp=""urn:oasis:names:tc:SAML:2.0:protocol"" xmlns:saml=""urn:oasis:names:tc:SAML:2.0:assertion"" ID=""_lr1"" InResponseTo=""_other"">
  <saml:Issuer>https://idp.example.com</saml:Issuer>
  <samlp:Status><samlp:StatusCode Value=""urn:oasis:names:tc:SAML:2.0:status:Success""/></samlp:Status>
</samlp:LogoutResponse>";
        var result = await _service.ProcessLogoutResponseAsync(xml, "_expected");
        result.IsFailure.Should().BeTrue();
        result.Error.Description.Should().Contain("InResponseTo mismatch");
    }

    [Fact]
    public async Task ProcessLogoutResponseAsync_MalformedAndNoRoot_ReturnsFailure()
    {
        var malformed = await _service.ProcessLogoutResponseAsync("<invalid", "_req1");
        malformed.IsFailure.Should().BeTrue();

        var noRoot = await _service.ProcessLogoutResponseAsync("<!-- comment only -->", "_req1");
        noRoot.IsFailure.Should().BeTrue();
        noRoot.Error.Description.Should().Contain("Root element is missing");
    }

    [Fact]
    public async Task ProcessLogoutResponseAsync_ErrorStatus_ReturnsFailure()
    {
        var xml = @"<samlp:LogoutResponse xmlns:samlp=""urn:oasis:names:tc:SAML:2.0:protocol"" xmlns:saml=""urn:oasis:names:tc:SAML:2.0:assertion"" ID=""_lr1"" InResponseTo=""_req1"">
  <saml:Issuer>https://idp.example.com</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value=""urn:oasis:names:tc:SAML:2.0:status:Requester""/>
    <samlp:StatusMessage>SLO rejected</samlp:StatusMessage>
  </samlp:Status>
</samlp:LogoutResponse>";
        var result = await _service.ProcessLogoutResponseAsync(xml, "_req1");
        result.IsFailure.Should().BeTrue();
        result.Error.Description.Should().Contain("SLO rejected");
    }

    [Fact]
    public async Task ProcessLogoutResponseAsync_RequireSignedMessages_ValidatesSignature()
    {
        _options.RequireSignedMessages = true;
        _options.IdpSigningCertificate = _idpCert;

        try
        {
            var xml = @"<samlp:LogoutResponse xmlns:samlp=""urn:oasis:names:tc:SAML:2.0:protocol"" xmlns:saml=""urn:oasis:names:tc:SAML:2.0:assertion"" ID=""_lr_sig"" InResponseTo=""_req1"">
  <saml:Issuer>https://idp.example.com</saml:Issuer>
  <samlp:Status><samlp:StatusCode Value=""urn:oasis:names:tc:SAML:2.0:status:Success""/></samlp:Status>
</samlp:LogoutResponse>";

            var doc = new XmlDocument { XmlResolver = null, PreserveWhitespace = true };
            doc.LoadXml(xml);
            _sigValidator.SignElement(doc.DocumentElement!, _idpCert);

            var validResult = await _service.ProcessLogoutResponseAsync(doc.OuterXml, "_req1");
            validResult.IsSuccess.Should().BeTrue();

            // Tamper
            var tamperedDoc = new XmlDocument { XmlResolver = null, PreserveWhitespace = true };
            tamperedDoc.LoadXml(doc.OuterXml);
            tamperedDoc.DocumentElement!.SetAttribute("InResponseTo", "_req1_tampered");

            var invalidResult = await _service.ProcessLogoutResponseAsync(tamperedDoc.OuterXml, "_req1_tampered");
            invalidResult.IsFailure.Should().BeTrue();
            invalidResult.Error.Description.Should().Contain("signature verification failed");
        }
        finally
        {
            _options.RequireSignedMessages = false;
        }
    }

    [Fact]
    public async Task ProcessResponseAsync_MultipleAssertions_XswAttack_ReturnsFailure()
    {
        var xml = @"<samlp:Response xmlns:samlp=""urn:oasis:names:tc:SAML:2.0:protocol"" xmlns:saml=""urn:oasis:names:tc:SAML:2.0:assertion"" ID=""_resp1"" Version=""2.0"">
  <samlp:Status><samlp:StatusCode Value=""urn:oasis:names:tc:SAML:2.0:status:Success""/></samlp:Status>
  <saml:Assertion ID=""_a1""/>
  <saml:Assertion ID=""_a2""/>
</samlp:Response>";
        var result = await _service.ProcessResponseAsync(xml);
        result.IsFailure.Should().BeTrue();
        result.Error.Code.Should().Be("Security.PolicyViolation");
    }

    [Fact]
    public async Task ProcessResponseAsync_EncryptedAssertion_SuccessfullyDecryptedAndProcessed()
    {
        var assertionXml = @"<saml:Assertion xmlns:saml=""urn:oasis:names:tc:SAML:2.0:assertion"" ID=""_decrypted_assert"" Version=""2.0"">
  <saml:Issuer>https://idp.example.com</saml:Issuer>
  <saml:Subject>
    <saml:NameID>john.doe@example.com</saml:NameID>
  </saml:Subject>
</saml:Assertion>";

        var plainDoc = new XmlDocument { XmlResolver = null };
        plainDoc.LoadXml(assertionXml);

        using var aes = Aes.Create();
        aes.KeySize = 256;
        aes.GenerateKey();

        var encryptedXml = new EncryptedXml();
        var encryptedBytes = encryptedXml.EncryptData(plainDoc.DocumentElement!, aes, false);

        var encryptedData = new EncryptedData
        {
            Type = EncryptedXml.XmlEncElementUrl,
            EncryptionMethod = new EncryptionMethod(EncryptedXml.XmlEncAES256Url)
        };

        var rsaKey = _spDecCert.GetRSAPrivateKey()!;
        var encryptedKey = new EncryptedKey
        {
            EncryptionMethod = new EncryptionMethod(EncryptedXml.XmlEncRSA15Url),
            CipherData = new CipherData(EncryptedXml.EncryptKey(aes.Key, rsaKey, false))
        };
        encryptedData.KeyInfo.AddClause(new KeyInfoEncryptedKey(encryptedKey));
        encryptedData.CipherData.CipherValue = encryptedBytes;

        var envelopeDoc = new XmlDocument { XmlResolver = null };
        var respElem = envelopeDoc.CreateElement("samlp", "Response", "urn:oasis:names:tc:SAML:2.0:protocol");
        respElem.SetAttribute("ID", "_resp1");
        respElem.SetAttribute("Version", "2.0");
        var statusElem = envelopeDoc.CreateElement("samlp", "Status", "urn:oasis:names:tc:SAML:2.0:protocol");
        var statusCodeElem = envelopeDoc.CreateElement("samlp", "StatusCode", "urn:oasis:names:tc:SAML:2.0:protocol");
        statusCodeElem.SetAttribute("Value", "urn:oasis:names:tc:SAML:2.0:status:Success");
        statusElem.AppendChild(statusCodeElem);
        respElem.AppendChild(statusElem);

        var encAssertionElem = envelopeDoc.CreateElement("saml", "EncryptedAssertion", "urn:oasis:names:tc:SAML:2.0:assertion");
        encAssertionElem.AppendChild(envelopeDoc.ImportNode(encryptedData.GetXml(), true));
        respElem.AppendChild(encAssertionElem);
        envelopeDoc.AppendChild(respElem);

        var result = await _service.ProcessResponseAsync(envelopeDoc.OuterXml);
        result.IsSuccess.Should().BeTrue();
        result.Value.Assertion.Id.Should().Be("_decrypted_assert");
        result.Value.NameId.Should().Be("john.doe@example.com");
    }

    [Fact]
    public async Task ProcessIdpInitiatedResponseAsync_PrunesExpiredAssertionIds()
    {
        _options.IdpInitiatedSsoMaxAssertionAge = TimeSpan.FromMilliseconds(-1000);
        var xml1 = new SamlTestMessageBuilder().WithAssertionId("_expired_assert_1").BuildXml();
        var result1 = await _service.ProcessIdpInitiatedResponseAsync(xml1);
        result1.IsSuccess.Should().BeTrue();

        var xml2 = new SamlTestMessageBuilder().WithAssertionId("_assert_2").BuildXml();
        var result2 = await _service.ProcessIdpInitiatedResponseAsync(xml2);
        result2.IsSuccess.Should().BeTrue();

        // Resending xml1 must succeed because it was pruned from seen assertions
        var result3 = await _service.ProcessIdpInitiatedResponseAsync(xml1);
        result3.IsSuccess.Should().BeTrue();
    }

    [Fact]
    public void CreateAuthnRequest_SignTrueButCertNull_DoesNotSign()
    {
        _options.SignAuthnRequests = true;
        _options.SpSigningCertificate = null;
        var request = _service.CreateAuthnRequest();
        request.RawXml.Should().NotContain("<Signature");
    }

    [Fact]
    public void CreateLogoutRequest_SignTrueButCertNull_DoesNotSign()
    {
        _options.SignLogoutRequests = true;
        _options.SpSigningCertificate = null;
        var request = _service.CreateLogoutRequest(new Saml2NameId("user"));
        request.RawXml.Should().NotContain("<Signature");
    }

    [Fact]
    public void CreateLogoutResponse_SignFalse_DoesNotSign()
    {
        _options.SignLogoutRequests = false;
        var response = _service.CreateLogoutResponse("_req1", "https://idp.example.com/slo");
        response.RawXml.Should().NotContain("<Signature");
    }

    [Fact]
    public async Task ProcessResponseAsync_EdgeCasesInAttributesAndIssuers_Success()
    {
        _options.IdpEntityId = string.Empty;
        _options.RequireSignedMessages = false;
        var xml = @"<samlp:Response xmlns:samlp=""urn:oasis:names:tc:SAML:2.0:protocol"" xmlns:saml=""urn:oasis:names:tc:SAML:2.0:assertion"" ID=""_resp1"" Version=""2.0"">
  <samlp:Status><samlp:StatusCode Value=""urn:oasis:names:tc:SAML:2.0:status:Success""/></samlp:Status>
  <saml:Assertion Version=""2.0"">
    <saml:Issuer>https://idp.example.com</saml:Issuer>
    <saml:Subject>
      <saml:NameID>user@test.com</saml:NameID>
    </saml:Subject>
    <saml:Conditions NotBefore=""2026-01-01T00:00:00Z"" NotOnOrAfter=""2030-01-01T00:00:00Z"">
      <saml:AudienceRestriction>
        <saml:Audience/>
        <saml:Audience>https://sp.example.com</saml:Audience>
      </saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AuthnStatement AuthnInstant=""invalid-date""/>
  </saml:Assertion>
</samlp:Response>";
        var result = await _service.ProcessResponseAsync(xml);
        result.IsSuccess.Should().BeTrue(result.IsFailure ? result.Error.Description : string.Empty);
        result.Value.Assertion.Id.Should().NotBeNullOrEmpty();
        result.Value.Assertion.Issuer.Should().Be("https://idp.example.com");
    }

    [Fact]
    public async Task ProcessLogoutResponseAsync_MissingAttributes_UsesFallbacks()
    {
        var xml = @"<samlp:LogoutResponse xmlns:samlp=""urn:oasis:names:tc:SAML:2.0:protocol"" xmlns:saml=""urn:oasis:names:tc:SAML:2.0:assertion"" InResponseTo=""_req1"">
  <saml:Issuer>https://idp.example.com</saml:Issuer>
  <samlp:Status/>
</samlp:LogoutResponse>";
        var result = await _service.ProcessLogoutResponseAsync(xml, "_req1");
        result.IsFailure.Should().BeTrue();
    }

    [Fact]
    public void CreateLogoutRequest_DisabledLogger_DoesNotLog()
    {
        var serviceWithNullLogger = new Saml2Service(
            Options.Create(_options),
            new Saml2XswValidator(),
            _sigValidator,
            _decryptor,
            new Saml2ClaimsMapper(),
            NullLogger<Saml2Service>.Instance);

        var req = serviceWithNullLogger.CreateLogoutRequest(new Saml2NameId("alice"));
        req.Id.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public void CreateLogoutResponse_SignTrueCertNull_DoesNotSign()
    {
        _options.SignLogoutRequests = true;
        _options.SpSigningCertificate = null;
        var resp = _service.CreateLogoutResponse("_req1", "https://idp.example.com/slo");
        resp.RawXml.Should().NotContain("<Signature");
    }

    [Fact]
    public async Task ProcessLogoutResponseAsync_WithIssueInstantAndEmptyStatusCode_Handled()
    {
        var xml = @"<samlp:LogoutResponse xmlns:samlp=""urn:oasis:names:tc:SAML:2.0:protocol"" xmlns:saml=""urn:oasis:names:tc:SAML:2.0:assertion"" ID=""_lr2"" InResponseTo=""_req1"" IssueInstant=""2026-09-01T12:00:00Z"">
  <saml:Issuer>https://idp.example.com</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode/>
    <samlp:StatusMessage/>
  </samlp:Status>
</samlp:LogoutResponse>";
        var result = await _service.ProcessLogoutResponseAsync(xml, "_req1");
        result.IsFailure.Should().BeTrue();
    }

    [Fact]
    public void Constructor_NullLogger_DefaultsToNullLogger()
    {
        var svc = new Saml2Service(
            Options.Create(_options),
            new Saml2XswValidator(),
            _sigValidator,
            _decryptor,
            new Saml2ClaimsMapper(),
            logger: null);
        svc.Should().NotBeNull();
        var req = svc.CreateAuthnRequest();
        req.Should().NotBeNull();
    }

    [Fact]
    public async Task ProcessResponseAsync_NotBeforeBoundary_ValidAndInvalid()
    {
        var now = DateTimeOffset.UtcNow;
        var validNb = now.AddMinutes(5).ToString("O");
        var validXml = $@"<samlp:Response xmlns:samlp=""urn:oasis:names:tc:SAML:2.0:protocol"" xmlns:saml=""urn:oasis:names:tc:SAML:2.0:assertion"" ID=""_r_nb1"" Version=""2.0"">
  <samlp:Status><samlp:StatusCode Value=""urn:oasis:names:tc:SAML:2.0:status:Success""/></samlp:Status>
  <saml:Assertion ID=""_a_nb1"" Version=""2.0"">
    <saml:Issuer>https://idp.example.com</saml:Issuer>
    <saml:Subject><saml:NameID>u</saml:NameID></saml:Subject>
    <saml:Conditions NotBefore=""{validNb}"" NotOnOrAfter=""{now.AddHours(1):O}"">
      <saml:AudienceRestriction><saml:Audience>https://sp.example.com</saml:Audience></saml:AudienceRestriction>
    </saml:Conditions>
  </saml:Assertion>
</samlp:Response>";
        var validResult = await _service.ProcessResponseAsync(validXml);
        validResult.IsSuccess.Should().BeTrue();

        var invalidNb = now.AddMinutes(5).AddSeconds(5).ToString("O");
        var invalidXml = $@"<samlp:Response xmlns:samlp=""urn:oasis:names:tc:SAML:2.0:protocol"" xmlns:saml=""urn:oasis:names:tc:SAML:2.0:assertion"" ID=""_r_nb2"" Version=""2.0"">
  <samlp:Status><samlp:StatusCode Value=""urn:oasis:names:tc:SAML:2.0:status:Success""/></samlp:Status>
  <saml:Assertion ID=""_a_nb2"" Version=""2.0"">
    <saml:Issuer>https://idp.example.com</saml:Issuer>
    <saml:Subject><saml:NameID>u</saml:NameID></saml:Subject>
    <saml:Conditions NotBefore=""{invalidNb}"" NotOnOrAfter=""{now.AddHours(1):O}"">
      <saml:AudienceRestriction><saml:Audience>https://sp.example.com</saml:Audience></saml:AudienceRestriction>
    </saml:Conditions>
  </saml:Assertion>
</samlp:Response>";
        var invalidResult = await _service.ProcessResponseAsync(invalidXml);
        invalidResult.IsFailure.Should().BeTrue();
        invalidResult.Error.Description.Should().Contain("Assertion is not yet valid");
    }

    [Fact]
    public async Task ProcessResponseAsync_NotOnOrAfterBoundary_ValidAndExpired()
    {
        var now = DateTimeOffset.UtcNow;
        var expNoa = now.AddMinutes(-5).ToString("O");
        var expiredXml = $@"<samlp:Response xmlns:samlp=""urn:oasis:names:tc:SAML:2.0:protocol"" xmlns:saml=""urn:oasis:names:tc:SAML:2.0:assertion"" ID=""_r_noa1"" Version=""2.0"">
  <samlp:Status><samlp:StatusCode Value=""urn:oasis:names:tc:SAML:2.0:status:Success""/></samlp:Status>
  <saml:Assertion ID=""_a_noa1"" Version=""2.0"">
    <saml:Issuer>https://idp.example.com</saml:Issuer>
    <saml:Subject><saml:NameID>u</saml:NameID></saml:Subject>
    <saml:Conditions NotBefore=""{now.AddHours(-1):O}"" NotOnOrAfter=""{expNoa}"">
      <saml:AudienceRestriction><saml:Audience>https://sp.example.com</saml:Audience></saml:AudienceRestriction>
    </saml:Conditions>
  </saml:Assertion>
</samlp:Response>";
        var expiredResult = await _service.ProcessResponseAsync(expiredXml);
        expiredResult.IsFailure.Should().BeTrue();
        expiredResult.Error.Description.Should().Contain("Assertion has expired");

        var validNoa = now.AddMinutes(-5).AddSeconds(5).ToString("O");
        var validXml = $@"<samlp:Response xmlns:samlp=""urn:oasis:names:tc:SAML:2.0:protocol"" xmlns:saml=""urn:oasis:names:tc:SAML:2.0:assertion"" ID=""_r_noa2"" Version=""2.0"">
  <samlp:Status><samlp:StatusCode Value=""urn:oasis:names:tc:SAML:2.0:status:Success""/></samlp:Status>
  <saml:Assertion ID=""_a_noa2"" Version=""2.0"">
    <saml:Issuer>https://idp.example.com</saml:Issuer>
    <saml:Subject><saml:NameID>u</saml:NameID></saml:Subject>
    <saml:Conditions NotBefore=""{now.AddHours(-1):O}"" NotOnOrAfter=""{validNoa}"">
      <saml:AudienceRestriction><saml:Audience>https://sp.example.com</saml:Audience></saml:AudienceRestriction>
    </saml:Conditions>
  </saml:Assertion>
</samlp:Response>";
        var validResult = await _service.ProcessResponseAsync(validXml);
        validResult.IsSuccess.Should().BeTrue();
    }

    [Fact]
    public async Task ProcessResponseAsync_MultipleAudiencesFirstMatches_BreaksEarly()
    {
        var xml = @"<samlp:Response xmlns:samlp=""urn:oasis:names:tc:SAML:2.0:protocol"" xmlns:saml=""urn:oasis:names:tc:SAML:2.0:assertion"" ID=""_resp_aud"" Version=""2.0"">
  <samlp:Status><samlp:StatusCode Value=""urn:oasis:names:tc:SAML:2.0:status:Success""/></samlp:Status>
  <saml:Assertion ID=""_a_aud"" Version=""2.0"">
    <saml:Issuer>https://idp.example.com</saml:Issuer>
    <saml:Subject><saml:NameID>user@test.com</saml:NameID></saml:Subject>
    <saml:Conditions NotBefore=""2026-01-01T00:00:00Z"" NotOnOrAfter=""2030-01-01T00:00:00Z"">
      <saml:AudienceRestriction>
        <saml:Audience>https://sp.example.com</saml:Audience>
        <saml:Audience>https://second-sp.example.com</saml:Audience>
      </saml:AudienceRestriction>
    </saml:Conditions>
  </saml:Assertion>
</samlp:Response>";
        var result = await _service.ProcessResponseAsync(xml);
        result.IsSuccess.Should().BeTrue();
    }

    [Fact]
    public async Task Saml2Service_ParameterGuards_ThrowExceptions()
    {
        await Assert.ThrowsAnyAsync<ArgumentException>(() => _service.ProcessIdpInitiatedResponseAsync(null!));
        await Assert.ThrowsAnyAsync<ArgumentException>(() => _service.ProcessIdpInitiatedResponseAsync("   "));

        using var cts1 = new System.Threading.CancellationTokenSource();
        cts1.Cancel();
        await Assert.ThrowsAsync<OperationCanceledException>(() => _service.ProcessIdpInitiatedResponseAsync("<xml/>", cts1.Token));

        await Assert.ThrowsAnyAsync<ArgumentException>(() => _service.ProcessLogoutResponseAsync(null!, "_expected"));
        await Assert.ThrowsAnyAsync<ArgumentException>(() => _service.ProcessLogoutResponseAsync("   ", "_expected"));
        await Assert.ThrowsAnyAsync<ArgumentException>(() => _service.ProcessLogoutResponseAsync("<xml/>", null!));
        await Assert.ThrowsAnyAsync<ArgumentException>(() => _service.ProcessLogoutResponseAsync("<xml/>", "   "));

        using var cts2 = new System.Threading.CancellationTokenSource();
        cts2.Cancel();
        await Assert.ThrowsAsync<OperationCanceledException>(() => _service.ProcessLogoutResponseAsync("<xml/>", "_expected", cts2.Token));

        Assert.ThrowsAny<ArgumentException>(() => _service.CreateLogoutResponse(null!, "https://idp.example.com"));
        var exEmptyInResp = Assert.Throws<ArgumentException>(() => _service.CreateLogoutResponse(string.Empty, "https://idp.example.com"));
        exEmptyInResp.StackTrace.Should().NotContain("Saml2LogoutResponse..ctor");
        Assert.ThrowsAny<ArgumentException>(() => _service.CreateLogoutResponse("   ", "https://idp.example.com"));
        Assert.ThrowsAny<ArgumentException>(() => _service.CreateLogoutResponse("_inResp", null!));
        var exEmptyDest = Assert.Throws<ArgumentException>(() => _service.CreateLogoutResponse("_inResp", string.Empty));
        exEmptyDest.StackTrace.Should().NotContain("Saml2LogoutResponse..ctor");
        Assert.ThrowsAny<ArgumentException>(() => _service.CreateLogoutResponse("_inResp", "   "));
    }

    [Fact]
    public async Task ProcessResponseAsync_EncryptedAssertionDecryptionFails_ReturnsFailure()
    {
        _options.SpDecryptionCertificate = _spDecCert;
        var xml = @"<samlp:Response xmlns:samlp=""urn:oasis:names:tc:SAML:2.0:protocol"" xmlns:saml=""urn:oasis:names:tc:SAML:2.0:assertion"" ID=""_resp1"" Version=""2.0"">
  <saml:Issuer>https://idp.example.com</saml:Issuer>
  <samlp:Status><samlp:StatusCode Value=""urn:oasis:names:tc:SAML:2.0:status:Success""/></samlp:Status>
  <saml:EncryptedAssertion>
    <xenc:EncryptedData xmlns:xenc=""http://www.w3.org/2001/04/xmlenc#""/>
  </saml:EncryptedAssertion>
</samlp:Response>";
        var result = await _service.ProcessResponseAsync(xml);
        result.IsFailure.Should().BeTrue();
        result.Error.Code.Should().Be("Security.DecryptionFailed");
    }

    [Fact]
    public async Task ProcessLogoutResponseAsync_MissingIdAttribute_GeneratesNewId()
    {
        var xml = @"<samlp:LogoutResponse xmlns:samlp=""urn:oasis:names:tc:SAML:2.0:protocol"" xmlns:saml=""urn:oasis:names:tc:SAML:2.0:assertion"" InResponseTo=""_req1"">
  <saml:Issuer>https://idp.example.com</saml:Issuer>
  <samlp:Status><samlp:StatusCode Value=""urn:oasis:names:tc:SAML:2.0:status:Success""/></samlp:Status>
</samlp:LogoutResponse>";
        var result = await _service.ProcessLogoutResponseAsync(xml, "_req1");
        result.IsSuccess.Should().BeTrue();
        result.Value.Id.Should().NotBeNullOrWhiteSpace();
        result.Value.Id.Length.Should().Be(32);
    }

    [Fact]
    public async Task ProcessLogoutResponseAsync_MissingStatusCodeValueAttribute_ReturnsInvalidTokenFailure()
    {
        var xml = @"<samlp:LogoutResponse xmlns:samlp=""urn:oasis:names:tc:SAML:2.0:protocol"" xmlns:saml=""urn:oasis:names:tc:SAML:2.0:assertion"" ID=""_lo_resp_nostatus"" InResponseTo=""_req1"" Version=""2.0"">
  <saml:Issuer>https://idp.example.com</saml:Issuer>
  <samlp:Status><samlp:StatusCode/></samlp:Status>
</samlp:LogoutResponse>";

        var result = await _service.ProcessLogoutResponseAsync(xml, "_req1");
        result.IsFailure.Should().BeTrue();
        result.Error.Code.Should().Be("Security.InvalidToken");
        result.Error.Description.Should().Contain("Failed to process SAML LogoutResponse");
    }

    [Fact]
    public async Task ProcessResponseAsync_MissingStatusCodeValueAttribute_FailsWithEmptyStatusInDescription()
    {
        var xml = @"<samlp:Response xmlns:samlp=""urn:oasis:names:tc:SAML:2.0:protocol"" xmlns:saml=""urn:oasis:names:tc:SAML:2.0:assertion"" ID=""_resp1"" Version=""2.0"">
  <saml:Issuer>https://idp.example.com</saml:Issuer>
  <samlp:Status><samlp:StatusCode/></samlp:Status>
  <saml:Assertion Version=""2.0"">
    <saml:Issuer>https://idp.example.com</saml:Issuer>
    <saml:Subject><saml:NameID>alice@example.com</saml:NameID></saml:Subject>
  </saml:Assertion>
</samlp:Response>";
        var result = await _service.ProcessResponseAsync(xml);
        result.IsFailure.Should().BeTrue();
        result.Error.Code.Should().Be("Security.PolicyViolation");
        result.Error.Description.Should().Contain("SAML IdP returned error status: ''.");
    }

    [Fact]
    public async Task ProcessResponseAsync_MissingAssertionIssuer_FailsWithEmptyAssertionIssuerMismatch()
    {
        var xml = @"<samlp:Response xmlns:samlp=""urn:oasis:names:tc:SAML:2.0:protocol"" xmlns:saml=""urn:oasis:names:tc:SAML:2.0:assertion"" ID=""_resp1"" Version=""2.0"">
  <saml:Issuer>https://idp.example.com</saml:Issuer>
  <samlp:Status><samlp:StatusCode Value=""urn:oasis:names:tc:SAML:2.0:status:Success""/></samlp:Status>
  <saml:Assertion Version=""2.0"">
    <saml:Subject><saml:NameID>alice@example.com</saml:NameID></saml:Subject>
  </saml:Assertion>
</samlp:Response>";
        var result = await _service.ProcessResponseAsync(xml);
        result.IsFailure.Should().BeTrue();
        result.Error.Code.Should().Be("Security.PolicyViolation");
        result.Error.Description.Should().Contain("Assertion Issuer mismatch: expected 'https://idp.example.com', got ''.");
    }

    [Fact]
    public async Task ProcessLogoutResponseAsync_MissingIssuerElement_FailsWithInvalidTokenForIssuer()
    {
        var xml = @"<samlp:LogoutResponse xmlns:samlp=""urn:oasis:names:tc:SAML:2.0:protocol"" xmlns:saml=""urn:oasis:names:tc:SAML:2.0:assertion"" ID=""_lo_resp_noissuer"" InResponseTo=""_req1"" Version=""2.0"">
  <samlp:Status><samlp:StatusCode Value=""urn:oasis:names:tc:SAML:2.0:status:Success""/></samlp:Status>
</samlp:LogoutResponse>";

        var result = await _service.ProcessLogoutResponseAsync(xml, "_req1");
        result.IsFailure.Should().BeTrue();
        result.Error.Code.Should().Be("Security.InvalidToken");
        result.Error.Description.Should().Contain("Parameter 'issuer'");
    }

    [Fact]
    public void ValidateAssertionTimestamps_NotBeforeInFutureBeyondSkew_ReturnsFailure()
    {
        var xml = @"<saml:Assertion xmlns:saml=""urn:oasis:names:tc:SAML:2.0:assertion"">
  <saml:Conditions NotBefore=""2026-09-03T12:05:00Z"" NotOnOrAfter=""2026-09-03T12:30:00Z""/>
</saml:Assertion>";
        var doc = new XmlDocument();
        doc.LoadXml(xml);
        var nsMgr = new XmlNamespaceManager(doc.NameTable);
        nsMgr.AddNamespace("saml", "urn:oasis:names:tc:SAML:2.0:assertion");

        var now = DateTimeOffset.Parse("2026-09-03T12:00:00Z");
        var skew = TimeSpan.FromMinutes(2); // now + skew = 12:02, which is < 12:05

        var result = Saml2Service.ValidateAssertionTimestamps(doc.DocumentElement!, nsMgr, now, skew);
        result.IsFailure.Should().BeTrue();
        result.Error.Code.Should().Be("Security.PolicyViolation");
        result.Error.Description.Should().Contain("SAML.Timestamp");
        result.Error.Description.Should().Contain("Assertion is not yet valid");
    }

    [Fact]
    public void ValidateAssertionTimestamps_NotOnOrAfterInPastBeyondSkew_ReturnsFailure()
    {
        var xml = @"<saml:Assertion xmlns:saml=""urn:oasis:names:tc:SAML:2.0:assertion"">
  <saml:Conditions NotBefore=""2026-09-03T11:00:00Z"" NotOnOrAfter=""2026-09-03T11:55:00Z""/>
</saml:Assertion>";
        var doc = new XmlDocument();
        doc.LoadXml(xml);
        var nsMgr = new XmlNamespaceManager(doc.NameTable);
        nsMgr.AddNamespace("saml", "urn:oasis:names:tc:SAML:2.0:assertion");

        var now = DateTimeOffset.Parse("2026-09-03T12:00:00Z");
        var skew = TimeSpan.FromMinutes(2); // now - skew = 11:58, which is >= 11:55

        var result = Saml2Service.ValidateAssertionTimestamps(doc.DocumentElement!, nsMgr, now, skew);
        result.IsFailure.Should().BeTrue();
        result.Error.Code.Should().Be("Security.TokenExpired");
        result.Error.Description.Should().Contain("Assertion has expired");
    }

    [Fact]
    public void ValidateAssertionTimestamps_WithinAllowedSkew_ReturnsSuccess()
    {
        var xml = @"<saml:Assertion xmlns:saml=""urn:oasis:names:tc:SAML:2.0:assertion"">
  <saml:Conditions NotBefore=""2026-09-03T12:01:00Z"" NotOnOrAfter=""2026-09-03T12:05:00Z""/>
</saml:Assertion>";
        var doc = new XmlDocument();
        doc.LoadXml(xml);
        var nsMgr = new XmlNamespaceManager(doc.NameTable);
        nsMgr.AddNamespace("saml", "urn:oasis:names:tc:SAML:2.0:assertion");

        var now = DateTimeOffset.Parse("2026-09-03T12:00:00Z");
        var skew = TimeSpan.FromMinutes(2); // now + skew = 12:02 >= 12:01, now - skew = 11:58 < 12:05

        var result = Saml2Service.ValidateAssertionTimestamps(doc.DocumentElement!, nsMgr, now, skew);
        result.IsSuccess.Should().BeTrue();
    }

    [Fact]
    public void ValidateAssertionTimestamps_NoTimestamps_FailsByDefault_SucceedsWhenOptional()
    {
        var xml = @"<saml:Assertion xmlns:saml=""urn:oasis:names:tc:SAML:2.0:assertion"">
  <saml:Conditions/>
</saml:Assertion>";
        var doc = new XmlDocument();
        doc.LoadXml(xml);
        var nsMgr = new XmlNamespaceManager(doc.NameTable);
        nsMgr.AddNamespace("saml", "urn:oasis:names:tc:SAML:2.0:assertion");

        // By default, missing NotOnOrAfter is rejected per SAML 2.0 Core Section 2.5.1.2
        var defaultResult = Saml2Service.ValidateAssertionTimestamps(doc.DocumentElement!, nsMgr, DateTimeOffset.UtcNow, TimeSpan.FromMinutes(2));
        defaultResult.IsFailure.Should().BeTrue();
        defaultResult.Error.Code.Should().Be("Security.PolicyViolation");

        // When requireExpiration is explicitly false, it is accepted
        var optionalResult = Saml2Service.ValidateAssertionTimestamps(doc.DocumentElement!, nsMgr, DateTimeOffset.UtcNow, TimeSpan.FromMinutes(2), requireExpiration: false);
        optionalResult.IsSuccess.Should().BeTrue();
    }

    [Fact]
    public void PruneExpiredAssertionIds_WithTimeProvider_RemovesExpiredOnly()
    {
        var fakeTime = new FakeTimeProvider(DateTimeOffset.Parse("2026-09-03T12:00:00Z"));
        var service = new Saml2Service(
            Options.Create(_options),
            new Saml2XswValidator(),
            _sigValidator,
            _decryptor,
            new Saml2ClaimsMapper(),
            _logger,
            fakeTime);

        // Prune initially
        service.PruneExpiredAssertionIds();

        // Advance time
        fakeTime.Advance(TimeSpan.FromHours(2));
        service.PruneExpiredAssertionIds();
        service.Should().NotBeNull();
    }

    [Theory]
    [InlineData(true, "urn:oasis:names:tc:SAML:2.0:status:Success")]
    [InlineData(false, "urn:oasis:names:tc:SAML:2.0:status:Responder")]
    public void CreateLogoutResponse_GeneratesValidXmlWithSuccessAndFailure(bool success, string expectedStatus)
    {
        var fakeTime = new FakeTimeProvider(DateTimeOffset.Parse("2026-09-03T12:00:00Z"));
        var service = new Saml2Service(
            Options.Create(_options),
            new Saml2XswValidator(),
            _sigValidator,
            _decryptor,
            new Saml2ClaimsMapper(),
            _logger,
            fakeTime);

        var response = service.CreateLogoutResponse("_inResponseTo_123", "https://idp.example.com/slo", success);

        response.Should().NotBeNull();
        response.InResponseTo.Should().Be("_inResponseTo_123");
        response.RawXml.Should().Contain("Destination=\"https://idp.example.com/slo\"");
        response.StatusCode.Should().Be(expectedStatus);
        response.IsSuccess.Should().Be(success);
        response.IssueInstant.Should().Be(DateTimeOffset.Parse("2026-09-03T12:00:00Z"));
        response.RawXml.Should().Contain(expectedStatus);
        response.RawXml.Should().Contain("InResponseTo=\"_inResponseTo_123\"");
    }


    [Fact]
    public void ValidateAssertionTimestamps_ExactBoundaryValues_EvaluatesCorrectly()
    {
        var doc = new XmlDocument();
        var nsMgr = new XmlNamespaceManager(doc.NameTable);
        nsMgr.AddNamespace("saml", "urn:oasis:names:tc:SAML:2.0:assertion");

        var now = DateTimeOffset.Parse("2026-09-03T12:00:00Z");
        var skew = TimeSpan.FromMinutes(2); // 12:02

        // Exact boundary: NotBefore = now + skew (12:02). now + skew < notBefore is FALSE, so it is valid.
        var xmlValidNb = @"<saml:Assertion xmlns:saml=""urn:oasis:names:tc:SAML:2.0:assertion"">
  <saml:Conditions NotBefore=""2026-09-03T12:02:00Z"" NotOnOrAfter=""2026-09-03T12:30:00Z""/>
</saml:Assertion>";
        doc.LoadXml(xmlValidNb);
        var resultNb = Saml2Service.ValidateAssertionTimestamps(doc.DocumentElement!, nsMgr, now, skew);
        resultNb.IsSuccess.Should().BeTrue();

        // Exact boundary: NotOnOrAfter = now - skew (11:58). now - skew >= notOnOrAfter is TRUE, so it has expired.
        var xmlExpiredNoa = @"<saml:Assertion xmlns:saml=""urn:oasis:names:tc:SAML:2.0:assertion"">
  <saml:Conditions NotBefore=""2026-09-03T11:00:00Z"" NotOnOrAfter=""2026-09-03T11:58:00Z""/>
</saml:Assertion>";
        doc.LoadXml(xmlExpiredNoa);
        var resultNoa = Saml2Service.ValidateAssertionTimestamps(doc.DocumentElement!, nsMgr, now, skew);
        resultNoa.IsFailure.Should().BeTrue();
        resultNoa.Error.Code.Should().Be("Security.TokenExpired");
    }

    [Fact]
    public async Task PruneExpiredAssertionIds_ExactBoundaryTime_RemovesWhenNowExceedsExpiration()
    {
        var fakeTime = new FakeTimeProvider(DateTimeOffset.Parse("2026-09-03T12:00:00Z"));
        _options.IdpInitiatedSsoMaxAssertionAge = TimeSpan.FromMinutes(5);
        var service = new Saml2Service(
            Options.Create(_options),
            new Saml2XswValidator(),
            _sigValidator,
            _decryptor,
            new Saml2ClaimsMapper(),
            _logger,
            fakeTime);

        // Process assertion at 12:00:00. Expires at 12:05:00.
        var xml = new SamlTestMessageBuilder().WithAssertionId("_boundary_assert").BuildXml();
        var res1 = await service.ProcessIdpInitiatedResponseAsync(xml);
        res1.IsSuccess.Should().BeTrue();

        // At exactly 12:05:00, kvp.Value == now (not strictly less than now, so must NOT be pruned)
        fakeTime.Advance(TimeSpan.FromMinutes(5));
        service.PruneExpiredAssertionIds();

        // Still retained, so replaying it must be rejected as replay attack
        var replayAtBoundary = await service.ProcessIdpInitiatedResponseAsync(xml);
        replayAtBoundary.IsFailure.Should().BeTrue();
        replayAtBoundary.Error.Description.Should().Contain("Replay attack");

        // At 12:05:01, now is strictly greater than 12:05:00 (kvp.Value < now is true, so must be pruned)
        fakeTime.Advance(TimeSpan.FromSeconds(1));
        service.PruneExpiredAssertionIds();

        // Should now be pruned, so replaying it succeeds
        var res2 = await service.ProcessIdpInitiatedResponseAsync(xml);
        res2.IsSuccess.Should().BeTrue(res2.IsFailure ? res2.Error.Description : string.Empty);
    }
}
