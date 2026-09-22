// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Saml2.Tests;

using System;
using System.Collections.Generic;
using System.Security.Claims;
using AwesomeAssertions;
using EricksonLopez.Security.Saml2.Abstractions;
using EricksonLopez.Security.Saml2.DependencyInjection;
using EricksonLopez.Security.Saml2.Enums;
using EricksonLopez.Security.Saml2.Models;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Xunit;

public sealed class Saml2ModelAndExtensionsTests
{
    [Fact]
    public void Saml2Enums_Values_AreDefined()
    {
        ((int)Saml2Binding.HttpPost).Should().Be(1);
        ((int)Saml2Binding.HttpRedirect).Should().Be(2);
        ((int)Saml2Binding.HttpArtifact).Should().Be(3);
        ((int)Saml2Binding.Soap).Should().Be(4);

        ((int)Saml2NameIdFormat.Unspecified).Should().Be(0);
        ((int)Saml2NameIdFormat.EmailAddress).Should().Be(1);
        ((int)Saml2NameIdFormat.Persistent).Should().Be(2);
        ((int)Saml2NameIdFormat.Transient).Should().Be(3);
        ((int)Saml2NameIdFormat.X509SubjectName).Should().Be(4);

        ((int)Saml2SignatureLocation.Response).Should().Be(1);
        ((int)Saml2SignatureLocation.Assertion).Should().Be(2);
        ((int)Saml2SignatureLocation.Both).Should().Be(3);

        ((int)Saml2StatusCode.Success).Should().Be(1);
        ((int)Saml2StatusCode.Requester).Should().Be(2);
        ((int)Saml2StatusCode.Responder).Should().Be(3);
        ((int)Saml2StatusCode.VersionMismatch).Should().Be(4);
        ((int)Saml2StatusCode.AuthnFailed).Should().Be(5);
    }

    [Fact]
    public void Saml2Options_DefaultsAndProperties_Work()
    {
        var options = new Saml2Options();

        options.SpEntityId.Should().Be("https://localhost/saml2/sp");
        options.IdpEntityId.Should().BeEmpty();
        options.IdpSingleSignOnUrl.Should().BeEmpty();
        options.AssertionConsumerServiceUrl.Should().Be("https://localhost/saml2/acs");
        options.AuthnRequestBinding.Should().Be(Saml2Binding.HttpRedirect);
        options.AllowedClockSkew.Should().Be(TimeSpan.FromMinutes(5));
        options.RequireSignedMessages.Should().BeTrue();
        options.SignAuthnRequests.Should().BeFalse();
        options.SignLogoutRequests.Should().BeFalse();
        options.DefaultNameIdFormat.Should().Be(Saml2NameIdFormat.EmailAddress);
        options.NameIdClaimType.Should().Be("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier");

        // Can mutate properties
        options.SpEntityId = "https://sp.test";
        options.IdpEntityId = "https://idp.test";
        options.AllowedClockSkew = TimeSpan.FromMinutes(2);
        options.RequireSignedMessages = false;
        options.SignAuthnRequests = true;
        options.SignLogoutRequests = true;
        options.AllowIdpInitiatedSso = true;
        options.IdpInitiatedSsoMaxAssertionAge = TimeSpan.FromMinutes(10);

        options.SpEntityId.Should().Be("https://sp.test");
        options.IdpEntityId.Should().Be("https://idp.test");
        options.AllowedClockSkew.Should().Be(TimeSpan.FromMinutes(2));
        options.RequireSignedMessages.Should().BeFalse();
        options.SignAuthnRequests.Should().BeTrue();
        options.SignLogoutRequests.Should().BeTrue();
        options.AllowIdpInitiatedSso.Should().BeTrue();
        options.IdpInitiatedSsoMaxAssertionAge.Should().Be(TimeSpan.FromMinutes(10));
    }

    [Fact]
    public void Saml2Models_Properties_Work()
    {
        var attribute = new Saml2Attribute("dept", ["Engineering"], "Department", "basic");
        attribute.Name.Should().Be("dept");
        attribute.FriendlyName.Should().Be("Department");
        attribute.NameFormat.Should().Be("basic");
        attribute.Values.Should().Contain("Engineering");

        var nameId = new Saml2NameId("alice", Saml2NameIdFormat.EmailAddress, "nq", "spnq");
        nameId.Value.Should().Be("alice");
        nameId.Format.Should().Be(Saml2NameIdFormat.EmailAddress);
        nameId.NameQualifier.Should().Be("nq");
        nameId.SpNameQualifier.Should().Be("spnq");

        var confirmation = new Saml2SubjectConfirmation("bearer", "https://sp.com/acs", "_req1", DateTimeOffset.UtcNow.AddHours(1));
        confirmation.Method.Should().Be("bearer");
        confirmation.Recipient.Should().Be("https://sp.com/acs");
        confirmation.InResponseTo.Should().Be("_req1");
        confirmation.NotOnOrAfter.Should().NotBeNull();

        var subject = new Saml2Subject(nameId, confirmation);
        subject.NameId.Should().BeSameAs(nameId);
        subject.Confirmation.Should().BeSameAs(confirmation);

        var conditions = new Saml2Conditions(
            notBefore: DateTimeOffset.UtcNow.AddMinutes(-5),
            notOnOrAfter: DateTimeOffset.UtcNow.AddHours(1),
            audiences: ["https://sp.com"]);

        conditions.Audiences.Should().Contain("https://sp.com");

        var authnStatement = new Saml2AuthnStatement(
            authnInstant: DateTimeOffset.UtcNow,
            sessionIndex: "_sess1",
            sessionNotOnOrAfter: DateTimeOffset.UtcNow.AddHours(8),
            authnContextClassRef: "PasswordProtectedTransport");

        authnStatement.SessionIndex.Should().Be("_sess1");
        authnStatement.AuthnContextClassRef.Should().Be("PasswordProtectedTransport");

        var assertion = new Saml2Assertion(
            id: "_assert1",
            issueInstant: DateTimeOffset.UtcNow,
            issuer: "https://idp.com",
            subject: subject,
            rawXml: "<xml/>",
            conditions: conditions,
            authnStatement: authnStatement,
            attributes: [attribute]);

        assertion.Id.Should().Be("_assert1");
        assertion.Issuer.Should().Be("https://idp.com");
        assertion.Subject.NameId.Value.Should().Be("alice");
        assertion.Subject.Confirmation!.Method.Should().Be("bearer");
        assertion.Conditions!.Audiences.Should().Contain("https://sp.com");
        assertion.AuthnStatement!.SessionIndex.Should().Be("_sess1");

        var principal = new ClaimsPrincipal(new ClaimsIdentity([new Claim(ClaimTypes.Name, "alice")]));
        var authnResult = new Saml2AuthenticationResult(principal, assertion);
        authnResult.Principal.Should().BeSameAs(principal);
        authnResult.Assertion.Should().BeSameAs(assertion);
        authnResult.Issuer.Should().Be("https://idp.com");
        authnResult.NameId.Should().Be("alice");
        authnResult.SessionIndex.Should().Be("_sess1");

        var status = new Saml2Status(Saml2StatusCode.Success, "sub", "OK");
        status.Code.Should().Be(Saml2StatusCode.Success);
        status.SubCode.Should().Be("sub");
        status.Message.Should().Be("OK");
        status.IsSuccess.Should().BeTrue();

        var logoutReq = new Saml2LogoutRequest(
            id: "_lo1",
            issuer: "https://sp.com",
            issueInstant: DateTimeOffset.UtcNow,
            destination: "https://idp.com/slo",
            nameId: nameId,
            rawXml: "<xml/>",
            sessionIndex: "_sess1");

        logoutReq.Id.Should().Be("_lo1");
        logoutReq.Issuer.Should().Be("https://sp.com");
        logoutReq.Destination.Should().Be("https://idp.com/slo");
        logoutReq.SessionIndex.Should().Be("_sess1");
        logoutReq.RawXml.Should().Be("<xml/>");

        var logoutResp = new Saml2LogoutResponse(
            id: "_lo_resp1",
            issuer: "https://idp.com",
            issueInstant: DateTimeOffset.UtcNow,
            inResponseTo: "_lo1",
            statusCode: "urn:oasis:names:tc:SAML:2.0:status:Success",
            rawXml: "<xml/>",
            statusMessage: "Success");

        logoutResp.Id.Should().Be("_lo_resp1");
        logoutResp.Issuer.Should().Be("https://idp.com");
        logoutResp.InResponseTo.Should().Be("_lo1");
        logoutResp.StatusCode.Should().Be("urn:oasis:names:tc:SAML:2.0:status:Success");
        logoutResp.IsSuccess.Should().BeTrue();
        logoutResp.StatusMessage.Should().Be("Success");
        logoutResp.RawXml.Should().Be("<xml/>");

        var samlResp = new Saml2Response(
            id: "_resp1",
            issueInstant: DateTimeOffset.UtcNow,
            issuer: "https://idp.com",
            status: status,
            rawXml: "<xml/>",
            inResponseTo: "_req1",
            destination: "https://sp.com/acs",
            assertions: [assertion]);

        samlResp.Id.Should().Be("_resp1");
        samlResp.Issuer.Should().Be("https://idp.com");
        samlResp.InResponseTo.Should().Be("_req1");
        samlResp.Destination.Should().Be("https://sp.com/acs");
        samlResp.Status.Should().BeSameAs(status);
        samlResp.Assertions.Should().Contain(assertion);
        samlResp.RawXml.Should().Be("<xml/>");
    }

    [Fact]
    public void AddSaml2Security_RegistersAllServices_InDependencyInjection()
    {
        var services = new ServiceCollection();
        var returned = services.AddSaml2Security(options =>
        {
            options.SpEntityId = "https://sp.test";
            options.IdpEntityId = "https://idp.test";
        });

        returned.Should().BeSameAs(services);

        var provider = services.BuildServiceProvider();
        using var scope = provider.CreateScope();

        var saml2Service = scope.ServiceProvider.GetService<ISaml2Service>();
        var xswValidator = scope.ServiceProvider.GetService<ISaml2XswValidator>();
        var sigValidator = scope.ServiceProvider.GetService<ISaml2SignatureValidator>();
        var decryptor = scope.ServiceProvider.GetService<ISaml2AssertionDecryptor>();
        var claimsMapper = scope.ServiceProvider.GetService<ISaml2ClaimsMapper>();

        saml2Service.Should().NotBeNull();
        xswValidator.Should().NotBeNull();
        sigValidator.Should().NotBeNull();
        decryptor.Should().NotBeNull();
        claimsMapper.Should().NotBeNull();

        var options = scope.ServiceProvider.GetRequiredService<IOptions<Saml2Options>>().Value;
        options.SpEntityId.Should().Be("https://sp.test");
    }

    [Fact]
    public void AddSaml2Security_WithoutOptions_RegistersDefaultOptions()
    {
        var services = new ServiceCollection();
        services.AddSaml2Security();

        var provider = services.BuildServiceProvider();
        var options = provider.GetRequiredService<IOptions<Saml2Options>>().Value;
        options.SpEntityId.Should().Be("https://localhost/saml2/sp");
    }

    [Fact]
    public void AddSaml2Security_NullServices_ThrowsArgumentNullException()
    {
        IServiceCollection services = null!;
        var act = () => services.AddSaml2Security();
        act.Should().Throw<ArgumentNullException>().WithParameterName("services");
    }

    [Fact]
    public void Saml2Models_NullBranchesAndGuards_Work()
    {
        // Saml2Attribute null values branch
        var attrNullValues = new Saml2Attribute("attr", null!);
        attrNullValues.Values.Should().BeEmpty();

        // Saml2Conditions null audiences branch
        var condNullAudiences = new Saml2Conditions(null, null, null);
        condNullAudiences.Audiences.Should().BeEmpty();

        // Saml2Subject null nameId guard
        Assert.Throws<ArgumentNullException>(() => new Saml2Subject(null!));

        // Saml2Response null assertions branch
        var status = new Saml2Status(Saml2StatusCode.Success, "OK");
        var respNullAssertions = new Saml2Response("id", DateTimeOffset.UtcNow, "iss", status, "<xml/>", assertions: null);
        respNullAssertions.Assertions.Should().BeEmpty();

        // Saml2AuthenticationResult null guards and null AuthnStatement SessionIndex
        var nameId = new Saml2NameId("user");
        var subject = new Saml2Subject(nameId);
        var assertWithoutAuthn = new Saml2Assertion("id", DateTimeOffset.UtcNow, "iss", subject, "<xml/>");
        var principal = new ClaimsPrincipal(new ClaimsIdentity([new Claim("sub", "user")]));
        var authResult = new Saml2AuthenticationResult(principal, assertWithoutAuthn);
        authResult.SessionIndex.Should().BeNull();

        Assert.Throws<ArgumentNullException>(() => new Saml2AuthenticationResult(null!, assertWithoutAuthn));
        Assert.Throws<ArgumentNullException>(() => new Saml2AuthenticationResult(principal, null!));
    }

    [Fact]
    public void Saml2Models_ArgumentValidation_Throws()
    {
        var subject = new Saml2Subject(new Saml2NameId("u"));
        var now = DateTimeOffset.UtcNow;
        var status = new Saml2Status(Saml2StatusCode.Success, "OK");

        // Saml2Assertion guards
        Assert.ThrowsAny<ArgumentException>(() => new Saml2Assertion(null!, now, "iss", subject, "<xml/>"));
        Assert.ThrowsAny<ArgumentException>(() => new Saml2Assertion("", now, "iss", subject, "<xml/>"));
        Assert.ThrowsAny<ArgumentException>(() => new Saml2Assertion("id", now, null!, subject, "<xml/>"));
        Assert.ThrowsAny<ArgumentException>(() => new Saml2Assertion("id", now, " ", subject, "<xml/>"));
        Assert.Throws<ArgumentNullException>(() => new Saml2Assertion("id", now, "iss", null!, "<xml/>"));
        Assert.ThrowsAny<ArgumentException>(() => new Saml2Assertion("id", now, "iss", subject, null!));
        Assert.ThrowsAny<ArgumentException>(() => new Saml2Assertion("id", now, "iss", subject, "   "));

        // Saml2Attribute guard
        Assert.ThrowsAny<ArgumentException>(() => new Saml2Attribute(null!, ["v"]));
        Assert.ThrowsAny<ArgumentException>(() => new Saml2Attribute("  ", ["v"]));

        // Saml2AuthnRequest guards
        Assert.ThrowsAny<ArgumentException>(() => new Saml2AuthnRequest(null!, "iss", now, "dest", "acs", "<xml/>"));
        Assert.ThrowsAny<ArgumentException>(() => new Saml2AuthnRequest("id", null!, now, "dest", "acs", "<xml/>"));
        Assert.ThrowsAny<ArgumentException>(() => new Saml2AuthnRequest("id", "iss", now, null!, "acs", "<xml/>"));
        Assert.ThrowsAny<ArgumentException>(() => new Saml2AuthnRequest("id", "iss", now, "dest", null!, "<xml/>"));
        Assert.ThrowsAny<ArgumentException>(() => new Saml2AuthnRequest("id", "iss", now, "dest", "acs", null!));

        // Saml2LogoutRequest guards
        var nameId = new Saml2NameId("u");
        Assert.ThrowsAny<ArgumentException>(() => new Saml2LogoutRequest(null!, "iss", now, "dest", nameId, "<xml/>"));
        Assert.ThrowsAny<ArgumentException>(() => new Saml2LogoutRequest("id", null!, now, "dest", nameId, "<xml/>"));
        Assert.ThrowsAny<ArgumentException>(() => new Saml2LogoutRequest("id", "iss", now, null!, nameId, "<xml/>"));
        Assert.Throws<ArgumentNullException>(() => new Saml2LogoutRequest("id", "iss", now, "dest", null!, "<xml/>"));
        Assert.ThrowsAny<ArgumentException>(() => new Saml2LogoutRequest("id", "iss", now, "dest", nameId, null!));

        // Saml2LogoutResponse guards
        Assert.ThrowsAny<ArgumentException>(() => new Saml2LogoutResponse(null!, "iss", now, "inResp", "code", "<xml/>"));
        Assert.ThrowsAny<ArgumentException>(() => new Saml2LogoutResponse("id", null!, now, "inResp", "code", "<xml/>"));
        Assert.ThrowsAny<ArgumentException>(() => new Saml2LogoutResponse("id", "iss", now, null!, "code", "<xml/>"));
        Assert.ThrowsAny<ArgumentException>(() => new Saml2LogoutResponse("id", "iss", now, "inResp", null!, "<xml/>"));
        Assert.ThrowsAny<ArgumentException>(() => new Saml2LogoutResponse("id", "iss", now, "inResp", "code", null!));

        // Saml2NameId guard
        Assert.ThrowsAny<ArgumentException>(() => new Saml2NameId(null!));
        Assert.ThrowsAny<ArgumentException>(() => new Saml2NameId("   "));

        // Saml2Response guards
        Assert.ThrowsAny<ArgumentException>(() => new Saml2Response(null!, now, "iss", status, "<xml/>"));
        Assert.ThrowsAny<ArgumentException>(() => new Saml2Response("id", now, null!, status, "<xml/>"));
        Assert.Throws<ArgumentNullException>(() => new Saml2Response("id", now, "iss", null!, "<xml/>"));
        Assert.ThrowsAny<ArgumentException>(() => new Saml2Response("id", now, "iss", status, null!));

        // Saml2SubjectConfirmation guard
        Assert.ThrowsAny<ArgumentException>(() => new Saml2SubjectConfirmation(null!));
        Assert.ThrowsAny<ArgumentException>(() => new Saml2SubjectConfirmation("   "));

        // Extension null guards
        var ex1 = Assert.Throws<ArgumentNullException>("services", () => Saml2ServiceCollectionExtensions.AddSaml2Security(null!, _ => { }));
        ex1.StackTrace.Should().NotContain("Configure");
        var ex2 = Assert.Throws<ArgumentNullException>("services", () => Saml2ServiceCollectionExtensions.AddSaml2Security(null!));
        ex2.StackTrace.Should().NotContain("Configure");
    }
}
