// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Saml2.Tests;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using AwesomeAssertions;
using EricksonLopez.Security.Saml2.Claims;
using EricksonLopez.Security.Saml2.Enums;
using EricksonLopez.Security.Saml2.Models;
using Xunit;

public sealed class Saml2ClaimsMapperTests
{
    private readonly Saml2ClaimsMapper _mapper = new();

    [Fact]
    public void MapToPrincipal_StandardAttributes_MapsToExpectedClaimTypes()
    {
        var options = new Saml2Options
        {
            NameIdClaimType = ClaimTypes.NameIdentifier
        };

        var subject = new Saml2Subject(new Saml2NameId("alice@example.com", Saml2NameIdFormat.EmailAddress));
        var authnStatement = new Saml2AuthnStatement(DateTimeOffset.UtcNow, sessionIndex: "_session_123");
        var attributes = new List<Saml2Attribute>
        {
            new("email", ["alice@example.com"]),
            new("name", ["Alice Wonderland"]),
            new("givenname", ["Alice"]),
            new("surname", ["Wonderland"]),
            new("role", ["Admin", "User"]),
            new("upn", ["alice@corp.local"]),
            new("custom_tenant", ["tenant-42"])
        };

        var assertion = new Saml2Assertion(
            id: "_assert1",
            issueInstant: DateTimeOffset.UtcNow,
            issuer: "https://idp.example.com",
            subject: subject,
            rawXml: "<xml/>",
            authnStatement: authnStatement,
            attributes: attributes);

        var principal = _mapper.MapToPrincipal(assertion, options);

        principal.Should().NotBeNull();
        principal.Identity.Should().NotBeNull();
        principal.Identity!.AuthenticationType.Should().Be("SAML2");

        principal.FindFirst(ClaimTypes.NameIdentifier).Should().NotBeNull();
        principal.FindFirst(ClaimTypes.NameIdentifier)!.Value.Should().Be("alice@example.com");
        principal.FindFirst(ClaimTypes.Email).Should().NotBeNull();
        principal.FindFirst(ClaimTypes.Email)!.Value.Should().Be("alice@example.com");
        principal.FindFirst(ClaimTypes.Name).Should().NotBeNull();
        principal.FindFirst(ClaimTypes.Name)!.Value.Should().Be("Alice Wonderland");
        principal.FindFirst(ClaimTypes.GivenName).Should().NotBeNull();
        principal.FindFirst(ClaimTypes.GivenName)!.Value.Should().Be("Alice");
        principal.FindFirst(ClaimTypes.Surname).Should().NotBeNull();
        principal.FindFirst(ClaimTypes.Surname)!.Value.Should().Be("Wonderland");
        principal.FindAll(ClaimTypes.Role).Select(c => c.Value).Should().Contain(["Admin", "User"]);
        principal.FindFirst(ClaimTypes.Upn).Should().NotBeNull();
        principal.FindFirst(ClaimTypes.Upn)!.Value.Should().Be("alice@corp.local");
        principal.FindFirst("custom_tenant").Should().NotBeNull();
        principal.FindFirst("custom_tenant")!.Value.Should().Be("tenant-42");
        principal.FindFirst(ClaimTypes.AuthenticationInstant).Should().NotBeNull();
        var sessionClaim = principal.FindFirst("http://schemas.microsoft.com/ws/2008/06/identity/claims/sessionindex");
        sessionClaim.Should().NotBeNull();
        sessionClaim!.Value.Should().Be("_session_123");
        sessionClaim.ValueType.Should().Be(ClaimValueTypes.String);
        sessionClaim.Issuer.Should().Be("https://idp.example.com");
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void MapToPrincipal_NullOrEmptySessionIndex_DoesNotAddSessionIndexClaim(string? sessionIndex)
    {
        var instant = new DateTimeOffset(2026, 9, 3, 12, 0, 0, TimeSpan.Zero);
        var assertion = new Saml2Assertion(
            id: "_assert1",
            issueInstant: DateTimeOffset.UtcNow,
            issuer: "https://idp.example.com",
            subject: new Saml2Subject(new Saml2NameId("user@example.com")),
            rawXml: "<xml/>",
            authnStatement: new Saml2AuthnStatement(instant, sessionIndex: sessionIndex));

        var principal = _mapper.MapToPrincipal(assertion, new Saml2Options());

        principal.FindFirst("http://schemas.microsoft.com/ws/2008/06/identity/claims/sessionindex").Should().BeNull();
        var instantClaim = principal.FindFirst(ClaimTypes.AuthenticationInstant);
        instantClaim.Should().NotBeNull();
        instantClaim!.Value.Should().Be(instant.ToString("o"));
        instantClaim.ValueType.Should().Be(ClaimValueTypes.DateTime);
    }

    [Theory]
    [InlineData("email", "val1", ClaimTypes.Email)]
    [InlineData("mail", "val2", ClaimTypes.Email)]
    [InlineData("emailaddress", "val3", ClaimTypes.Email)]
    [InlineData("name", "val5", ClaimTypes.Name)]
    [InlineData("displayname", "val6", ClaimTypes.Name)]
    [InlineData("givenname", "val8", ClaimTypes.GivenName)]
    [InlineData("surname", "val10", ClaimTypes.Surname)]
    [InlineData("sn", "val11", ClaimTypes.Surname)]
    [InlineData("role", "val13", ClaimTypes.Role)]
    [InlineData("roles", "val14", ClaimTypes.Role)]
    [InlineData("upn", "val16", ClaimTypes.Upn)]
    public void MapToPrincipal_StandardClaimMappings_MapsEachKeyToExpectedClaimType(string samlAttributeName, string attributeValue, string expectedClaimType)
    {
        var subject = new Saml2Subject(new Saml2NameId("user@example.com"));
        var assertion = new Saml2Assertion(
            id: "_id",
            issueInstant: DateTimeOffset.UtcNow,
            issuer: "https://idp.example.com",
            subject: subject,
            rawXml: "<xml/>",
            attributes: [new Saml2Attribute(samlAttributeName, [attributeValue])]);

        var principal = _mapper.MapToPrincipal(assertion, new Saml2Options());

        var claim = principal.FindFirst(expectedClaimType);
        claim.Should().NotBeNull();
        claim!.Value.Should().Be(attributeValue);
    }

    [Fact]
    public void MapToPrincipal_NameId_MapsWithConfiguredClaimTypeAndIssuer()
    {
        var options = new Saml2Options { NameIdClaimType = "custom_name_id" };
        var subject = new Saml2Subject(new Saml2NameId("subject_val"));
        var assertion = new Saml2Assertion("_id", DateTimeOffset.UtcNow, "https://my-idp.com", subject, "<xml/>");

        var principal = _mapper.MapToPrincipal(assertion, options);

        var claim = principal.FindFirst("custom_name_id");
        claim.Should().NotBeNull();
        claim!.Value.Should().Be("subject_val");
        claim.Issuer.Should().Be("https://my-idp.com");
    }

    [Fact]
    public void MapToPrincipal_AlternativeClaimNames_MapsCorrectly()
    {
        var options = new Saml2Options();
        var subject = new Saml2Subject(new Saml2NameId("bob@example.com", Saml2NameIdFormat.EmailAddress));
        var attributes = new List<Saml2Attribute>
        {
            new("mail", ["bob@example.com"]),
            new("displayname", ["Bob Builder"]),
            new("sn", ["Builder"]),
            new("roles", ["Engineer"]),
            new("http://schemas.microsoft.com/ws/2008/06/identity/claims/role", ["Manager"])
        };

        var assertion = new Saml2Assertion(
            id: "_assert2",
            issueInstant: DateTimeOffset.UtcNow,
            issuer: "https://idp.example.com",
            subject: subject,
            rawXml: "<xml/>",
            attributes: attributes);

        var principal = _mapper.MapToPrincipal(assertion, options);

        principal.FindFirst(ClaimTypes.Email)?.Value.Should().Be("bob@example.com");
        principal.FindFirst(ClaimTypes.Name)?.Value.Should().Be("Bob Builder");
        principal.FindFirst(ClaimTypes.Surname)?.Value.Should().Be("Builder");
        principal.FindAll(ClaimTypes.Role).Select(c => c.Value).Should().Contain(["Engineer", "Manager"]);
    }

    [Fact]
    public void MapToPrincipal_NullArguments_ThrowsArgumentNullException()
    {
        var subject = new Saml2Subject(new Saml2NameId("u", Saml2NameIdFormat.Unspecified));
        var assertion = new Saml2Assertion("_1", DateTimeOffset.UtcNow, "idp", subject, "<xml/>");
        var options = new Saml2Options();

        Assert.Throws<ArgumentNullException>(() => _mapper.MapToPrincipal(null!, options));
        Assert.Throws<ArgumentNullException>(() => _mapper.MapToPrincipal(assertion, null!));
    }
}
