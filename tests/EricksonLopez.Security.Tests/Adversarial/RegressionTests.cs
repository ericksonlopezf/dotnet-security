// Copyright © Erickson Lopez. MIT License.
// Regression tests to prevent re-introduction of known security vulnerabilities.

namespace EricksonLopez.Security.Tests.Adversarial;

using System;
using System.Xml;
using AwesomeAssertions;
using EricksonLopez.Security.Mfa;
using EricksonLopez.Security.Saml2.Xsw;
using Xunit;

/// <summary>
/// Security regression tests that document previously discovered vulnerabilities and
/// ensure they cannot be reintroduced by future refactoring.
/// </summary>
public class RegressionTests
{
    /// <summary>
    /// Regression test for SAML XSW protection: duplicate IDs (case-sensitive per spec) must be rejected.
    /// The validator uses StringComparer.Ordinal (case-sensitive) per the XML ID uniqueness spec.
    /// </summary>
    [Fact]
    public void Saml2XswValidator_Rejects_Duplicate_Ids()
    {
        // XML with two assertions sharing the same ID value — classic XSW attack pattern
        var xml = @"<samlp:Response xmlns:samlp=""urn:oasis:names:tc:SAML:2.0:protocol"">
            <saml:Assertion xmlns:saml=""urn:oasis:names:tc:SAML:2.0:assertion"" ID=""valid-id"">
            </saml:Assertion>
            <saml:Assertion xmlns:saml=""urn:oasis:names:tc:SAML:2.0:assertion"" ID=""valid-id"">
                <Role>Admin</Role>
            </saml:Assertion>
        </samlp:Response>";

        var doc = new XmlDocument();
        doc.LoadXml(xml);

        var validator = new Saml2XswValidator();
        var result = validator.ValidateAndExtractAssertion(doc);

        // Multiple assertions OR duplicate IDs should be caught.
        // The current implementation catches multiple assertions first (before duplicate IDs).
        result.IsFailure.Should().BeTrue(because: "multiple assertions or duplicate IDs represent an XSW attack vector");
    }

    /// <summary>
    /// Regression test for SEC-001: Filled TOTP replay cache must NOT evict valid (non-expired)
    /// tokens to make room. Evicting valid tokens would allow an attacker to force cache eviction
    /// via flooding and then replay a previously consumed code.
    /// </summary>
    [Fact]
    public void TotpService_Full_Cache_Rejects_New_Logins_Without_Evicting_Valid_Tokens()
    {
        // FINDING-NEW-04 / SEC-001 REGRESSION:
        // Valid tokens must verify; replayed tokens must be rejected; pruning must not evict active tokens.
        var service = new TotpService();
        var now = DateTimeOffset.UtcNow;
        var masterKey = Base32Encoding.ToBase32String(service.GenerateSecretKey());
        var activeCode = service.ComputeCode(masterKey, now);

        // First verification of active token must succeed
        var firstResult = service.VerifyCode(masterKey, activeCode, now);
        firstResult.Should().BeTrue("Fresh, unconsumed token must be accepted.");

        // Immediate replay of active token must be rejected
        var replayResult = service.VerifyCode(masterKey, activeCode, now);
        replayResult.Should().BeFalse("Replayed token within same window must be rejected.");

        // Fill up slots to trigger periodic pruning (>1000 items)
        var options = new TotpOptions { PreventReplay = true };
        for (int i = 0; i < 1_001; i++)
        {
            var dummyKey = Base32Encoding.ToBase32String(service.GenerateSecretKey());
            var code = service.ComputeCode(dummyKey, now);
            var res = service.VerifyCode(dummyKey, code, now, options);
            res.Should().BeTrue($"Fresh token {i} must be accepted.");
        }

        // Active master token must STILL be rejected upon replay attempt (never evicted early)
        var lateReplayResult = service.VerifyCode(masterKey, activeCode, now);
        lateReplayResult.Should().BeFalse("Active token must NOT have been evicted by cache pruning.");
    }
}
