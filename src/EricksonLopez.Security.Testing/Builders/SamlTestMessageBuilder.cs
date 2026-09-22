// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Testing.Builders;

using System;
using System.Collections.Generic;
using System.Text;

/// <summary>
/// Provides a fluent builder for constructing valid or tampered SAML 2.0 XML responses and assertions for deterministic testing.
/// </summary>
public sealed class SamlTestMessageBuilder
{
    private string _responseId = "_resp_" + Guid.NewGuid().ToString("N");
    private string? _inResponseTo;
    private string? _destination;
    private string _issuer = "https://idp.example.com";
    private string _statusCode = "urn:oasis:names:tc:SAML:2.0:status:Success";
    private string? _secondStatusCode;
    private string? _statusMessage;
    private string _assertionId = "_assert_" + Guid.NewGuid().ToString("N");
    private string? _assertionIssuer;
    private string _subjectNameId = "user@example.com";
    private string _audience = "https://sp.example.com";
    private DateTimeOffset _issueInstant = new(2026, 8, 31, 0, 0, 0, TimeSpan.Zero);
    private DateTimeOffset _notBefore = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
    private DateTimeOffset _notOnOrAfter = new(2030, 1, 1, 0, 0, 0, TimeSpan.Zero);
    private string? _confirmationRecipient;
    private DateTimeOffset? _confirmationNotOnOrAfter;
    private DateTimeOffset? _authnInstant;
    private string? _sessionIndex;
    private readonly List<(string Name, string? FriendlyName, List<string> Values)> _attributes = new();
    private bool _omitAssertion;
    private bool _omitStatus;
    private bool _omitSubject;
    private bool _omitConditions;

    /// <summary>Sets the response element ID.</summary>
    /// <param name="responseId">The response element identifier.</param>
    /// <returns>The current builder instance for fluent chaining.</returns>
    public SamlTestMessageBuilder WithResponseId(string responseId)
    {
        _responseId = responseId;
        return this;
    }

    /// <summary>Sets the InResponseTo attribute.</summary>
    /// <param name="inResponseTo">The identifier of the request message being responded to.</param>
    /// <returns>The current builder instance for fluent chaining.</returns>
    public SamlTestMessageBuilder WithInResponseTo(string inResponseTo)
    {
        _inResponseTo = inResponseTo;
        return this;
    }

    /// <summary>Sets the Destination attribute on the Response element.</summary>
    /// <param name="destination">The destination URI endpoint attribute.</param>
    /// <returns>The current builder instance for fluent chaining.</returns>
    public SamlTestMessageBuilder WithDestination(string destination)
    {
        _destination = destination;
        return this;
    }

    /// <summary>Sets the IDP issuer.</summary>
    /// <param name="issuer">The identity provider issuer entity ID.</param>
    /// <returns>The current builder instance for fluent chaining.</returns>
    public SamlTestMessageBuilder WithIssuer(string issuer)
    {
        _issuer = issuer;
        return this;
    }

    /// <summary>Sets a divergent assertion issuer to test issuer mismatch scenarios.</summary>
    /// <param name="assertionIssuer">The divergent assertion issuer entity ID.</param>
    /// <returns>The current builder instance for fluent chaining.</returns>
    public SamlTestMessageBuilder WithAssertionIssuer(string assertionIssuer)
    {
        _assertionIssuer = assertionIssuer;
        return this;
    }

    /// <summary>Sets the top-level status code.</summary>
    /// <param name="statusCode">The top-level SAML status code URI.</param>
    /// <returns>The current builder instance for fluent chaining.</returns>
    public SamlTestMessageBuilder WithStatusCode(string statusCode)
    {
        _statusCode = statusCode;
        return this;
    }

    /// <summary>Sets a nested secondary status code (e.g. AuthnFailed).</summary>
    /// <param name="secondStatusCode">The nested secondary status code URI.</param>
    /// <returns>The current builder instance for fluent chaining.</returns>
    public SamlTestMessageBuilder WithSecondaryStatusCode(string secondStatusCode)
    {
        _secondStatusCode = secondStatusCode;
        return this;
    }

    /// <summary>Sets the status message.</summary>
    /// <param name="statusMessage">The human-readable status message text.</param>
    /// <returns>The current builder instance for fluent chaining.</returns>
    public SamlTestMessageBuilder WithStatusMessage(string statusMessage)
    {
        _statusMessage = statusMessage;
        return this;
    }

    /// <summary>Sets the assertion ID.</summary>
    /// <param name="assertionId">The assertion element identifier.</param>
    /// <returns>The current builder instance for fluent chaining.</returns>
    public SamlTestMessageBuilder WithAssertionId(string assertionId)
    {
        _assertionId = assertionId;
        return this;
    }

    /// <summary>Sets the subject NameID.</summary>
    /// <param name="subjectNameId">The subject NameID string value.</param>
    /// <returns>The current builder instance for fluent chaining.</returns>
    public SamlTestMessageBuilder WithSubject(string subjectNameId)
    {
        _subjectNameId = subjectNameId;
        return this;
    }

    /// <summary>Sets SubjectConfirmation data for bearer validation.</summary>
    /// <param name="recipient">Expected bearer recipient URI.</param>
    /// <param name="notOnOrAfter">Expiration UTC timestamp for the bearer confirmation.</param>
    /// <returns>Current builder instance for fluent chaining.</returns>
    public SamlTestMessageBuilder WithSubjectConfirmation(string recipient, DateTimeOffset notOnOrAfter)
    {
        _confirmationRecipient = recipient;
        _confirmationNotOnOrAfter = notOnOrAfter;
        return this;
    }

    /// <summary>Sets the AuthnStatement instant and session index.</summary>
    /// <param name="authnInstant">UTC timestamp when authentication occurred.</param>
    /// <param name="sessionIndex">Optional session index identifier.</param>
    /// <returns>Current builder instance for fluent chaining.</returns>
    public SamlTestMessageBuilder WithAuthnStatement(DateTimeOffset authnInstant, string? sessionIndex = null)
    {
        _authnInstant = authnInstant;
        _sessionIndex = sessionIndex;
        return this;
    }

    /// <summary>Sets the audience URI for audience restriction checks.</summary>
    /// <param name="audience">Audience restriction URI.</param>
    /// <returns>Current builder instance for fluent chaining.</returns>
    public SamlTestMessageBuilder WithAudience(string audience)
    {
        _audience = audience;
        return this;
    }

    /// <summary>Sets the issue instant timestamp.</summary>
    /// <param name="issueInstant">Message issue instant UTC timestamp.</param>
    /// <returns>Current builder instance for fluent chaining.</returns>
    public SamlTestMessageBuilder WithIssueInstant(DateTimeOffset issueInstant)
    {
        _issueInstant = issueInstant;
        return this;
    }

    /// <summary>Sets the condition validity timestamps.</summary>
    /// <param name="notBefore">Not-before validity UTC timestamp.</param>
    /// <param name="notOnOrAfter">Not-on-or-after validity UTC timestamp.</param>
    /// <returns>Current builder instance for fluent chaining.</returns>
    public SamlTestMessageBuilder WithConditions(DateTimeOffset notBefore, DateTimeOffset notOnOrAfter)
    {
        _notBefore = notBefore;
        _notOnOrAfter = notOnOrAfter;
        return this;
    }

    /// <summary>Adds a SAML attribute statement with a single value.</summary>
    /// <param name="name">The attribute name URI or identifier.</param>
    /// <param name="value">The single attribute value string.</param>
    /// <param name="friendlyName">The optional friendly name for the attribute.</param>
    /// <returns>The current builder instance for fluent chaining.</returns>
    public SamlTestMessageBuilder WithAttribute(string name, string value, string? friendlyName = null)
    {
        var existing = _attributes.Find(a => a.Name == name);
        if (existing.Name is not null)
        {
            existing.Values.Add(value);
        }
        else
        {
            _attributes.Add((name, friendlyName, new List<string> { value }));
        }
        return this;
    }

    /// <summary>Adds a SAML attribute statement with multiple values.</summary>
    /// <param name="name">The attribute name URI or identifier.</param>
    /// <param name="values">The collection of attribute value strings.</param>
    /// <param name="friendlyName">The optional friendly name for the attribute.</param>
    /// <returns>The current builder instance for fluent chaining.</returns>
    public SamlTestMessageBuilder WithAttribute(string name, string[] values, string? friendlyName = null)
    {
        _attributes.Add((name, friendlyName, new List<string>(values)));
        return this;
    }

    /// <summary>Omits the assertion element to simulate empty or invalid responses.</summary>
    /// <returns>The current builder instance for fluent chaining.</returns>
    public SamlTestMessageBuilder WithoutAssertion()
    {
        _omitAssertion = true;
        return this;
    }

    /// <summary>Omits the Status element to test malformed responses.</summary>
    /// <returns>The current builder instance for fluent chaining.</returns>
    public SamlTestMessageBuilder WithoutStatus()
    {
        _omitStatus = true;
        return this;
    }

    /// <summary>Omits the Subject element to test missing subject scenarios.</summary>
    /// <returns>The current builder instance for fluent chaining.</returns>
    public SamlTestMessageBuilder WithoutSubject()
    {
        _omitSubject = true;
        return this;
    }

    /// <summary>Omits the Conditions element to test missing conditions scenarios.</summary>
    /// <returns>The current builder instance for fluent chaining.</returns>
    public SamlTestMessageBuilder WithoutConditions()
    {
        _omitConditions = true;
        return this;
    }

    /// <summary>Builds the complete SAML 2.0 XML string representation.</summary>
    /// <returns>The complete SAML 2.0 XML string representation.</returns>
    public string BuildXml()
    {
        var culture = System.Globalization.CultureInfo.InvariantCulture;
        var inRespAttr = string.IsNullOrEmpty(_inResponseTo) ? string.Empty : $" InResponseTo=\"{_inResponseTo}\"";
        var destAttr = string.IsNullOrEmpty(_destination) ? string.Empty : $" Destination=\"{_destination}\"";
        var instantStr = _issueInstant.ToString("yyyy-MM-ddTHH:mm:ssZ", culture);

        var sb = new StringBuilder();
        sb.Append(culture, $"<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"{_responseId}\"{inRespAttr}{destAttr} Version=\"2.0\" IssueInstant=\"{instantStr}\">");
        sb.Append(culture, $"<saml:Issuer>{_issuer}</saml:Issuer>");

        if (!_omitStatus)
        {
            sb.Append("<samlp:Status>");
            sb.Append(culture, $"<samlp:StatusCode Value=\"{_statusCode}\">");

            if (!string.IsNullOrEmpty(_secondStatusCode))
            {
                sb.Append(culture, $"<samlp:StatusCode Value=\"{_secondStatusCode}\"/>");
            }

            sb.Append("</samlp:StatusCode>");

            if (!string.IsNullOrEmpty(_statusMessage))
            {
                sb.Append(culture, $"<samlp:StatusMessage>{_statusMessage}</samlp:StatusMessage>");
            }

            sb.Append("</samlp:Status>");
        }

        if (!_omitAssertion)
        {
            var assertIssuer = _assertionIssuer ?? _issuer;
            var notBeforeStr = _notBefore.ToString("yyyy-MM-ddTHH:mm:ssZ", culture);
            var notOnOrAfterStr = _notOnOrAfter.ToString("yyyy-MM-ddTHH:mm:ssZ", culture);

            sb.Append(culture, $"<saml:Assertion ID=\"{_assertionId}\" Version=\"2.0\" IssueInstant=\"{instantStr}\">");
            sb.Append(culture, $"<saml:Issuer>{assertIssuer}</saml:Issuer>");

            if (!_omitSubject)
            {
                sb.Append("<saml:Subject>");
                sb.Append(culture, $"<saml:NameID>{_subjectNameId}</saml:NameID>");

                if (!string.IsNullOrEmpty(_confirmationRecipient) && _confirmationNotOnOrAfter.HasValue)
                {
                    var confDateStr = _confirmationNotOnOrAfter.Value.ToString("yyyy-MM-ddTHH:mm:ssZ", culture);
                    sb.Append(culture, $"<saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\"><saml:SubjectConfirmationData Recipient=\"{_confirmationRecipient}\" NotOnOrAfter=\"{confDateStr}\"/></saml:SubjectConfirmation>");
                }

                sb.Append("</saml:Subject>");
            }

            if (!_omitConditions)
            {
                sb.Append(culture, $"<saml:Conditions NotBefore=\"{notBeforeStr}\" NotOnOrAfter=\"{notOnOrAfterStr}\">");
                sb.Append("<saml:AudienceRestriction>");
                sb.Append(culture, $"<saml:Audience>{_audience}</saml:Audience>");
                sb.Append("</saml:AudienceRestriction>");
                sb.Append("</saml:Conditions>");
            }

            if (_authnInstant.HasValue)
            {
                var authnStr = _authnInstant.Value.ToString("yyyy-MM-ddTHH:mm:ssZ", culture);
                var sessAttr = string.IsNullOrEmpty(_sessionIndex) ? string.Empty : $" SessionIndex=\"{_sessionIndex}\"";
                sb.Append(culture, $"<saml:AuthnStatement AuthnInstant=\"{authnStr}\"{sessAttr}/>");
            }

            if (_attributes.Count > 0)
            {
                sb.Append("<saml:AttributeStatement>");
                foreach (var (name, friendlyName, values) in _attributes)
                {
                    var friendlyAttr = string.IsNullOrEmpty(friendlyName) ? string.Empty : $" FriendlyName=\"{friendlyName}\"";
                    sb.Append(culture, $"<saml:Attribute Name=\"{name}\"{friendlyAttr}>");
                    foreach (var val in values)
                    {
                        sb.Append(culture, $"<saml:AttributeValue>{val}</saml:AttributeValue>");
                    }
                    sb.Append("</saml:Attribute>");
                }
                sb.Append("</saml:AttributeStatement>");
            }

            sb.Append("</saml:Assertion>");
        }

        sb.Append("</samlp:Response>");
        return sb.ToString();
    }
}
