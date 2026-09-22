// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Saml2.Tests;

using System;
using System.Xml;
using AwesomeAssertions;
using EricksonLopez.Security.Saml2.Xsw;
using Xunit;

public sealed class Saml2XswValidatorTests
{
    private readonly Saml2XswValidator _validator = new();

    [Fact]
    public void ValidateAndExtractAssertion_ValidResponse_ReturnsSuccess()
    {
        var xml = @"<samlp:Response xmlns:samlp=""urn:oasis:names:tc:SAML:2.0:protocol"" xmlns:saml=""urn:oasis:names:tc:SAML:2.0:assertion"" ID=""_resp1"" Version=""2.0"" IssueInstant=""2026-08-31T00:00:00Z"">
  <saml:Issuer>https://idp.example.com</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value=""urn:oasis:names:tc:SAML:2.0:status:Success""/>
  </samlp:Status>
  <saml:Assertion ID=""_assert1"" Version=""2.0"" IssueInstant=""2026-08-31T00:00:00Z"">
    <saml:Issuer>https://idp.example.com</saml:Issuer>
    <saml:Subject>
      <saml:NameID>user@example.com</saml:NameID>
    </saml:Subject>
  </saml:Assertion>
</samlp:Response>";

        var doc = new XmlDocument { XmlResolver = null };
        doc.LoadXml(xml);

        var result = _validator.ValidateAndExtractAssertion(doc);

        result.IsSuccess.Should().BeTrue();
        result.Value.GetAttribute("ID").Should().Be("_assert1");
    }

    [Fact]
    public void ValidateAndExtractAssertion_AssertionAsRootElement_ReturnsSuccess()
    {
        var xml = @"<saml:Assertion xmlns:saml=""urn:oasis:names:tc:SAML:2.0:assertion"" ID=""_assert_root"" Version=""2.0"">
  <saml:Issuer>https://idp.example.com</saml:Issuer>
</saml:Assertion>";

        var doc = new XmlDocument { XmlResolver = null };
        doc.LoadXml(xml);

        var result = _validator.ValidateAndExtractAssertion(doc);

        result.IsSuccess.Should().BeTrue();
        result.Value.GetAttribute("ID").Should().Be("_assert_root");
    }

    [Fact]
    public void ValidateAndExtractAssertion_DuplicateId_ReturnsFailure_XswMitigation()
    {
        // Attack scenario: Attacker duplicates ID="_assert1" on another element
        var xml = @"<samlp:Response xmlns:samlp=""urn:oasis:names:tc:SAML:2.0:protocol"" xmlns:saml=""urn:oasis:names:tc:SAML:2.0:assertion"" ID=""_assert1"" Version=""2.0"" IssueInstant=""2026-08-31T00:00:00Z"">
  <saml:Issuer>https://idp.example.com</saml:Issuer>
  <saml:Assertion ID=""_assert1"" Version=""2.0"" IssueInstant=""2026-08-31T00:00:00Z"">
    <saml:Issuer>https://idp.example.com</saml:Issuer>
    <saml:Subject>
      <saml:NameID>user@example.com</saml:NameID>
    </saml:Subject>
  </saml:Assertion>
</samlp:Response>";

        var doc = new XmlDocument { XmlResolver = null };
        doc.LoadXml(xml);

        var result = _validator.ValidateAndExtractAssertion(doc);

        result.IsFailure.Should().BeTrue();
        result.Error.Code.Should().Be("Security.PolicyViolation");
        result.Error.Description.Should().Contain("SAML.XSW");
        result.Error.Description.Should().Contain("Duplicate ID");
    }

    [Fact]
    public void ValidateAndExtractAssertion_DuplicateLowercaseId_ReturnsFailure()
    {
        var xml = @"<samlp:Response xmlns:samlp=""urn:oasis:names:tc:SAML:2.0:protocol"" xmlns:saml=""urn:oasis:names:tc:SAML:2.0:assertion"" id=""_dup_id"" Version=""2.0"">
  <saml:Assertion id=""_dup_id"" Version=""2.0"">
    <saml:Issuer>https://idp.example.com</saml:Issuer>
  </saml:Assertion>
</samlp:Response>";

        var doc = new XmlDocument { XmlResolver = null };
        doc.LoadXml(xml);

        var result = _validator.ValidateAndExtractAssertion(doc);

        result.IsFailure.Should().BeTrue();
        result.Error.Code.Should().Be("Security.PolicyViolation");
        result.Error.Description.Should().Contain("SAML.XSW");
        result.Error.Description.Should().Contain("Duplicate ID");
    }

    [Fact]
    public void ValidateAndExtractAssertion_MultipleAssertions_ReturnsFailure_XswMitigation()
    {
        var xml = @"<samlp:Response xmlns:samlp=""urn:oasis:names:tc:SAML:2.0:protocol"" xmlns:saml=""urn:oasis:names:tc:SAML:2.0:assertion"" ID=""_resp1"" Version=""2.0"" IssueInstant=""2026-08-31T00:00:00Z"">
  <saml:Issuer>https://idp.example.com</saml:Issuer>
  <saml:Assertion ID=""_legit"" Version=""2.0"" IssueInstant=""2026-08-31T00:00:00Z"">
    <saml:Issuer>https://idp.example.com</saml:Issuer>
    <saml:Subject>
      <saml:NameID>legit@example.com</saml:NameID>
    </saml:Subject>
  </saml:Assertion>
  <saml:Assertion ID=""_forged"" Version=""2.0"" IssueInstant=""2026-08-31T00:00:00Z"">
    <saml:Issuer>https://idp.example.com</saml:Issuer>
    <saml:Subject>
      <saml:NameID>admin@example.com</saml:NameID>
    </saml:Subject>
  </saml:Assertion>
</samlp:Response>";

        var doc = new XmlDocument { XmlResolver = null };
        doc.LoadXml(xml);

        var result = _validator.ValidateAndExtractAssertion(doc);

        result.IsFailure.Should().BeTrue();
        result.Error.Code.Should().Be("Security.PolicyViolation");
        result.Error.Description.Should().Contain("SAML.XSW");
        result.Error.Description.Should().Contain("Multiple assertions found");
    }

    [Fact]
    public void ValidateAndExtractAssertion_PlainAndEncryptedAssertion_ReturnsFailure()
    {
        var xml = @"<samlp:Response xmlns:samlp=""urn:oasis:names:tc:SAML:2.0:protocol"" xmlns:saml=""urn:oasis:names:tc:SAML:2.0:assertion"" ID=""_resp1"">
  <saml:Assertion ID=""_plain""/>
  <saml:EncryptedAssertion ID=""_enc""/>
</samlp:Response>";

        var doc = new XmlDocument { XmlResolver = null };
        doc.LoadXml(xml);

        var result = _validator.ValidateAndExtractAssertion(doc);

        result.IsFailure.Should().BeTrue();
        result.Error.Code.Should().Be("Security.PolicyViolation");
        result.Error.Description.Should().Contain("SAML.XSW");
        result.Error.Description.Should().Contain("Multiple assertions found");
    }

    [Fact]
    public void ValidateAndExtractAssertion_DisplacedAssertion_ReturnsFailure_XswMitigation()
    {
        var xml = @"<samlp:Response xmlns:samlp=""urn:oasis:names:tc:SAML:2.0:protocol"" xmlns:saml=""urn:oasis:names:tc:SAML:2.0:assertion"" ID=""_resp1"">
  <samlp:Extensions>
    <saml:Assertion ID=""_displaced"" Version=""2.0"">
      <saml:Issuer>https://idp.example.com</saml:Issuer>
    </saml:Assertion>
  </samlp:Extensions>
</samlp:Response>";

        var doc = new XmlDocument { XmlResolver = null };
        doc.LoadXml(xml);

        var result = _validator.ValidateAndExtractAssertion(doc);

        result.IsFailure.Should().BeTrue();
        result.Error.Code.Should().Be("Security.PolicyViolation");
        result.Error.Description.Should().Contain("SAML.XSW");
        result.Error.Description.Should().Contain("not a direct child of Response");
    }

    [Fact]
    public void ValidateAndExtractAssertion_NoAssertions_ReturnsFailure()
    {
        var xml = @"<samlp:Response xmlns:samlp=""urn:oasis:names:tc:SAML:2.0:protocol"" ID=""_resp1"">
</samlp:Response>";

        var doc = new XmlDocument { XmlResolver = null };
        doc.LoadXml(xml);

        var result = _validator.ValidateAndExtractAssertion(doc);

        result.IsFailure.Should().BeTrue();
        result.Error.Description.Should().Contain("No SAML assertion found");
    }

    [Fact]
    public void ValidateAndExtractAssertion_EmptyDocumentWithoutRoot_ReturnsFailure()
    {
        var doc = new XmlDocument();

        var result = _validator.ValidateAndExtractAssertion(doc);

        result.IsFailure.Should().BeTrue();
        result.Error.Description.Should().Contain("no root element");
    }

    [Fact]
    public void ValidateAndExtractAssertion_EncryptedAssertionAsRoot_ReturnsSuccess()
    {
        var xml = @"<saml:EncryptedAssertion xmlns:saml=""urn:oasis:names:tc:SAML:2.0:assertion"" ID=""_enc_root""/>";
        var doc = new XmlDocument { XmlResolver = null };
        doc.LoadXml(xml);
        var result = _validator.ValidateAndExtractAssertion(doc);
        result.IsSuccess.Should().BeTrue();
        result.Value.GetAttribute("ID").Should().Be("_enc_root");
    }

    [Fact]
    public void ValidateAndExtractAssertion_EncryptedAssertionAsChildOfResponse_ReturnsSuccess()
    {
        var xml = @"<samlp:Response xmlns:samlp=""urn:oasis:names:tc:SAML:2.0:protocol"" xmlns:saml=""urn:oasis:names:tc:SAML:2.0:assertion"" ID=""_resp1"">
  <saml:EncryptedAssertion ID=""_enc_child""/>
</samlp:Response>";
        var doc = new XmlDocument { XmlResolver = null };
        doc.LoadXml(xml);
        var result = _validator.ValidateAndExtractAssertion(doc);
        result.IsSuccess.Should().BeTrue();
        result.Value.GetAttribute("ID").Should().Be("_enc_child");
    }

    [Fact]
    public void ValidateAndExtractAssertion_UnknownRootElement_ReturnsFailure()
    {
        var xml = @"<UnknownRoot xmlns:saml=""urn:oasis:names:tc:SAML:2.0:assertion"">
  <saml:Assertion ID=""_a1""/>
</UnknownRoot>";
        var doc = new XmlDocument { XmlResolver = null };
        doc.LoadXml(xml);
        var result = _validator.ValidateAndExtractAssertion(doc);
        result.IsFailure.Should().BeTrue();
        result.Error.Description.Should().Contain("not a direct child of Response");
    }

    [Fact]
    public void ValidateAndExtractAssertion_AssertionRootWrongNamespace_ReturnsFailure()
    {
        var xml = @"<saml:Assertion xmlns:saml=""urn:wrong:namespace"" ID=""_a1""/>";
        var doc = new XmlDocument { XmlResolver = null };
        doc.LoadXml(xml);
        var result = _validator.ValidateAndExtractAssertion(doc);
        result.IsFailure.Should().BeTrue();
    }

    [Fact]
    public void ValidateAndExtractAssertion_ResponseRootWrongNamespace_ReturnsFailure()
    {
        var xml = @"<samlp:Response xmlns:samlp=""urn:wrong:namespace"" xmlns:saml=""urn:oasis:names:tc:SAML:2.0:assertion"" ID=""_r1"">
  <saml:Assertion ID=""_a1""/>
</samlp:Response>";
        var doc = new XmlDocument { XmlResolver = null };
        doc.LoadXml(xml);
        var result = _validator.ValidateAndExtractAssertion(doc);
        result.IsFailure.Should().BeTrue();
    }

    [Fact]
    public void ValidateAndExtractAssertion_DuplicateLowerId_ReturnsFailure()
    {
        var xml1 = @"<samlp:Response xmlns:samlp=""urn:oasis:names:tc:SAML:2.0:protocol"" xmlns:saml=""urn:oasis:names:tc:SAML:2.0:assertion"" id=""dup_id"">
  <saml:Assertion id=""dup_id""/>
</samlp:Response>";
        var doc1 = new XmlDocument { XmlResolver = null };
        doc1.LoadXml(xml1);
        _validator.ValidateAndExtractAssertion(doc1).IsFailure.Should().BeTrue();
    }

    [Fact]
    public void ValidateAndExtractAssertion_RootLocalNameNotAssertionOrResponse_ReturnsFailure()
    {
        var xml = @"<saml:SomeOtherElement xmlns:saml=""urn:oasis:names:tc:SAML:2.0:assertion"" ID=""_other"">
  <saml:Assertion ID=""_a1""/>
</saml:SomeOtherElement>";
        var doc = new XmlDocument { XmlResolver = null };
        doc.LoadXml(xml);
        var result = _validator.ValidateAndExtractAssertion(doc);
        result.IsFailure.Should().BeTrue();
    }

    [Fact]
    public void ValidateAndExtractAssertion_NullDocument_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => _validator.ValidateAndExtractAssertion(null!));
    }
}
