// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Saml2.Services;

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Security.Claims;
using System.Text;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using System.Xml;
using EricksonLopez.Result;
using EricksonLopez.Security.Abstractions.Errors;
using EricksonLopez.Security.Saml2.Abstractions;
using EricksonLopez.Security.Saml2.Enums;
using EricksonLopez.Security.Saml2.Models;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

/// <summary>
/// Provides SAML 2.0 Web Browser Single Sign-On operations, message generation, and cryptographic verification.
/// </summary>
public sealed class Saml2Service : ISaml2Service
{
    private const string Saml2AssertionNamespace = "urn:oasis:names:tc:SAML:2.0:assertion";
    private const string Saml2ProtocolNamespace = "urn:oasis:names:tc:SAML:2.0:protocol";

    private readonly Saml2Options _options;
    private readonly ISaml2XswValidator _xswValidator;
    private readonly ISaml2SignatureValidator _signatureValidator;
    private readonly ISaml2AssertionDecryptor _assertionDecryptor;
    private readonly ISaml2ClaimsMapper _claimsMapper;
    private readonly ILogger<Saml2Service> _logger;
    private readonly TimeProvider _timeProvider;

    // Replay protection cache for IdP-initiated SSO: assertionId → expiry
    // In distributed deployments, replace with a distributed cache backed implementation.
    private readonly ConcurrentDictionary<string, DateTimeOffset> _seenAssertionIds = new();

    /// <summary>
    /// Initializes a new instance of the <see cref="Saml2Service"/> class with required security validators and configuration.
    /// </summary>
    /// <param name="options">The configured SAML 2.0 options.</param>
    /// <param name="xswValidator">The XML Signature Wrapping (XSW) validator.</param>
    /// <param name="signatureValidator">The SAML signature validator.</param>
    /// <param name="assertionDecryptor">The encrypted assertion decryptor.</param>
    /// <param name="claimsMapper">The SAML attribute to claims mapper.</param>
    /// <param name="logger">The optional logger instance.</param>
    /// <param name="timeProvider">The optional time provider instance.</param>
    /// <exception cref="ArgumentNullException"><paramref name="options"/>, <paramref name="xswValidator"/>, <paramref name="signatureValidator"/>, <paramref name="assertionDecryptor"/>, or <paramref name="claimsMapper"/> is <see langword="null"/></exception>
    public Saml2Service(
        IOptions<Saml2Options> options,
        ISaml2XswValidator xswValidator,
        ISaml2SignatureValidator signatureValidator,
        ISaml2AssertionDecryptor assertionDecryptor,
        ISaml2ClaimsMapper claimsMapper,
        ILogger<Saml2Service>? logger = null,
        TimeProvider? timeProvider = null)
    {
        _options = options?.Value ?? throw new ArgumentNullException(nameof(options));
        _xswValidator = xswValidator ?? throw new ArgumentNullException(nameof(xswValidator));
        _signatureValidator = signatureValidator ?? throw new ArgumentNullException(nameof(signatureValidator));
        _assertionDecryptor = assertionDecryptor ?? throw new ArgumentNullException(nameof(assertionDecryptor));
        _claimsMapper = claimsMapper ?? throw new ArgumentNullException(nameof(claimsMapper));
        _logger = logger ?? NullLogger<Saml2Service>.Instance;
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    /// <inheritdoc />
    public Saml2AuthnRequest CreateAuthnRequest(string? relayState = null)
    {
        var id = "_" + Guid.NewGuid().ToString("N");
        var issueInstant = _timeProvider.GetUtcNow();
        var destination = _options.IdpSingleSignOnUrl;
        var acsUrl = _options.AssertionConsumerServiceUrl;
        var issuer = _options.SpEntityId;

        var nameIdFormatUri = _options.DefaultNameIdFormat switch
        {
            Saml2NameIdFormat.EmailAddress => "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
            Saml2NameIdFormat.Persistent => "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
            Saml2NameIdFormat.Transient => "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
            Saml2NameIdFormat.X509SubjectName => "urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName",
            _ => "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
        };

        var doc = new XmlDocument();
        var authnRequestElem = doc.CreateElement("samlp", "AuthnRequest", Saml2ProtocolNamespace);
        authnRequestElem.SetAttribute("ID", id);
        authnRequestElem.SetAttribute("Version", "2.0");
        authnRequestElem.SetAttribute("IssueInstant", issueInstant.ToString("o"));
        authnRequestElem.SetAttribute("Destination", destination);
        authnRequestElem.SetAttribute("AssertionConsumerServiceURL", acsUrl);
        authnRequestElem.SetAttribute("ProtocolBinding", "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST");

        var issuerElem = doc.CreateElement("saml", "Issuer", Saml2AssertionNamespace);
        issuerElem.InnerText = issuer;
        authnRequestElem.AppendChild(issuerElem);

        var nameIdPolicyElem = doc.CreateElement("samlp", "NameIDPolicy", Saml2ProtocolNamespace);
        nameIdPolicyElem.SetAttribute("Format", nameIdFormatUri);
        nameIdPolicyElem.SetAttribute("AllowCreate", "true");
        authnRequestElem.AppendChild(nameIdPolicyElem);

        doc.AppendChild(authnRequestElem);

        if (_options.SignAuthnRequests && _options.SpSigningCertificate is not null)
        {
            _signatureValidator.SignElement(authnRequestElem, _options.SpSigningCertificate);
        }

        return new Saml2AuthnRequest(
            id: id,
            issuer: issuer,
            issueInstant: issueInstant,
            destination: destination,
            assertionConsumerServiceUrl: acsUrl,
            rawXml: doc.OuterXml,
            protocolBinding: _options.AuthnRequestBinding,
            nameIdFormat: _options.DefaultNameIdFormat,
            relayState: relayState);
    }

    /// <inheritdoc />
    public Task<Result<Saml2AuthenticationResult>> ProcessResponseAsync(
        string samlResponseXml,
        string? expectedInResponseTo = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(samlResponseXml);
        cancellationToken.ThrowIfCancellationRequested();

        try
        {
            // 1. Decode Base64 if needed
            var rawXml = samlResponseXml.Trim();
            if (!rawXml.StartsWith('<'))
            {
                var bytes = Convert.FromBase64String(rawXml);
                rawXml = Encoding.UTF8.GetString(bytes);
            }

            // 2. Load XML securely (Disallow DTD / External Entities, preserve whitespace for XMLDSig)
            var doc = CreateSecureXmlDocument(rawXml, preserveWhitespace: true);

            var root = doc.DocumentElement!;

            // 3. Check Top-Level Response Status
            var nsMgr = new XmlNamespaceManager(doc.NameTable);
            nsMgr.AddNamespace("samlp", Saml2ProtocolNamespace);
            nsMgr.AddNamespace("saml", Saml2AssertionNamespace);

            var statusCodeNode = root.SelectSingleNode("//samlp:StatusCode/@Value", nsMgr);
            var statusCodeUri = statusCodeNode?.Value ?? string.Empty;

            if (!statusCodeUri.EndsWith("Success", StringComparison.OrdinalIgnoreCase))
            {
                var statusMessage = root.SelectSingleNode("//samlp:StatusMessage", nsMgr)?.InnerText;
                return Task.FromResult(Result<Saml2AuthenticationResult>.Failure(
                    SecurityError.SecurityPolicyViolation("SAML.Status", $"SAML IdP returned error status: '{statusCodeUri}'. Message: {statusMessage}")));
            }

            // 4. Check InResponseTo if expected
            if (!string.IsNullOrEmpty(expectedInResponseTo))
            {
                var inResponseTo = root.GetAttribute("InResponseTo");
                if (!string.Equals(inResponseTo, expectedInResponseTo, StringComparison.Ordinal))
                {
                    return Task.FromResult(Result<Saml2AuthenticationResult>.Failure(
                        SecurityError.SecurityPolicyViolation("SAML.InResponseTo", $"InResponseTo mismatch: expected '{expectedInResponseTo}', got '{inResponseTo}'.")));
                }
            }

            // 4b. Check Response Issuer
            var responseIssuer = root.SelectSingleNode("./saml:Issuer", nsMgr)?.InnerText?.Trim();
            if (!string.IsNullOrEmpty(_options.IdpEntityId) && !string.IsNullOrEmpty(responseIssuer) &&
                !string.Equals(responseIssuer, _options.IdpEntityId, StringComparison.OrdinalIgnoreCase))
            {
                return Task.FromResult(Result<Saml2AuthenticationResult>.Failure(
                    SecurityError.SecurityPolicyViolation("SAML.Issuer", $"Response issuer mismatch: expected '{_options.IdpEntityId}', got '{responseIssuer}'.")));
            }

            // 5. XSW Mitigation: Validate and Extract canonical assertion
            var assertionExtractResult = _xswValidator.ValidateAndExtractAssertion(doc);
            if (assertionExtractResult.IsFailure)
            {
                return Task.FromResult(Result<Saml2AuthenticationResult>.Failure(assertionExtractResult.Error));
            }

            var assertionElement = assertionExtractResult.Value;

            // 6. If EncryptedAssertion, decrypt it
            if (string.Equals(assertionElement.LocalName, "EncryptedAssertion", StringComparison.Ordinal))
            {
                if (_options.SpDecryptionCertificate is null)
                {
                    return Task.FromResult(Result<Saml2AuthenticationResult>.Failure(
                        SecurityError.InvalidKey("Received EncryptedAssertion but no SpDecryptionCertificate configured.")));
                }

                var decryptResult = _assertionDecryptor.DecryptAssertion(assertionElement, _options.SpDecryptionCertificate);
                if (decryptResult.IsFailure)
                {
                    return Task.FromResult(Result<Saml2AuthenticationResult>.Failure(decryptResult.Error));
                }

                assertionElement = decryptResult.Value;
            }

            // 7. Verify Signature if required
            if (_options.RequireSignedMessages)
            {
                if (_options.IdpSigningCertificate is null)
                {
                    return Task.FromResult(Result<Saml2AuthenticationResult>.Failure(
                        SecurityError.InvalidKey("Signature verification required but IdpSigningCertificate is not configured.")));
                }

                // Check signature on Assertion or Response
                var assertionSigResult = _signatureValidator.VerifySignature(assertionElement, _options.IdpSigningCertificate);
                var responseSigResult = _signatureValidator.VerifySignature(root, _options.IdpSigningCertificate);

                if (assertionSigResult.IsFailure && responseSigResult.IsFailure)
                {
                    return Task.FromResult(Result<Saml2AuthenticationResult>.Failure(
                        SecurityError.DecryptionFailed("Neither Assertion nor Response contains a valid XMLDSig signature from trusted IdP.")));
                }
            }

            // 8. Validate Conditions (NotBefore, NotOnOrAfter, Audience)
            var now = _timeProvider.GetUtcNow();
            var skew = _options.AllowedClockSkew;

            var timeResult = ValidateAssertionTimestamps(assertionElement, nsMgr, now, skew, _options.RequireAssertionExpiration);
            if (timeResult.IsFailure)
            {
                return Task.FromResult(Result<Saml2AuthenticationResult>.Failure(timeResult.Error));
            }

            // Audience restriction check
            var audienceNodes = assertionElement.SelectNodes("./saml:Conditions/saml:AudienceRestriction/saml:Audience", nsMgr);
            if (audienceNodes is { Count: > 0 })
            {
                var matched = false;
                foreach (XmlNode audNode in audienceNodes)
                {
                    if (string.Equals(audNode.InnerText?.Trim(), _options.SpEntityId, StringComparison.OrdinalIgnoreCase))
                    {
                        matched = true;
                    }
                }

                if (!matched)
                {
                    return Task.FromResult(Result<Saml2AuthenticationResult>.Failure(
                        SecurityError.SecurityPolicyViolation("SAML.Audience", $"Assertion audience does not match SP Entity ID '{_options.SpEntityId}'.")));
                }
            }

            // Recipient check
            var recipient = assertionElement.SelectSingleNode("./saml:Subject/saml:SubjectConfirmation/saml:SubjectConfirmationData/@Recipient", nsMgr)?.Value;
            if (!string.IsNullOrEmpty(recipient) &&
                !string.Equals(recipient, _options.AssertionConsumerServiceUrl, StringComparison.OrdinalIgnoreCase))
            {
                return Task.FromResult(Result<Saml2AuthenticationResult>.Failure(
                    SecurityError.SecurityPolicyViolation("SAML.Recipient", $"Recipient mismatch: expected '{_options.AssertionConsumerServiceUrl}', got '{recipient}'.")));
            }

            // Issuer check
            var issuer = assertionElement.SelectSingleNode("./saml:Issuer", nsMgr)?.InnerText?.Trim() ?? string.Empty;
            if (!string.IsNullOrEmpty(_options.IdpEntityId) &&
                !string.Equals(issuer, _options.IdpEntityId, StringComparison.OrdinalIgnoreCase))
            {
                return Task.FromResult(Result<Saml2AuthenticationResult>.Failure(
                    SecurityError.SecurityPolicyViolation("SAML.Issuer", $"Assertion Issuer mismatch: expected '{_options.IdpEntityId}', got '{issuer}'.")));
            }

            // 9. Extract NameID
            var nameIdNode = assertionElement.SelectSingleNode("./saml:Subject/saml:NameID", nsMgr);
            if (nameIdNode is null || string.IsNullOrWhiteSpace(nameIdNode.InnerText))
            {
                return Task.FromResult(Result<Saml2AuthenticationResult>.Failure(
                    SecurityError.InvalidToken("Assertion missing required <saml:NameID> in Subject.")));
            }

            var nameId = new Saml2NameId(nameIdNode.InnerText.Trim());
            var subject = new Saml2Subject(nameId);

            // 10. Extract Attributes
            var attributes = new List<Saml2Attribute>();
            var attrNodes = assertionElement.SelectNodes("./saml:AttributeStatement/saml:Attribute", nsMgr);
            if (attrNodes is not null)
            {
                foreach (XmlNode node in attrNodes)
                {
                    if (node is XmlElement attrElem)
                    {
                        var name = attrElem.GetAttribute("Name");
                        if (string.IsNullOrEmpty(name)) continue;

                        var friendlyName = attrElem.GetAttribute("FriendlyName");
                        var values = new List<string>();
                        var valNodes = attrElem.SelectNodes("./saml:AttributeValue", nsMgr);
                        if (valNodes is not null)
                        {
                            foreach (XmlNode v in valNodes)
                            {
                                if (!string.IsNullOrEmpty(v.InnerText))
                                {
                                    values.Add(v.InnerText);
                                }
                            }
                        }

                        attributes.Add(new Saml2Attribute(name, values, friendlyName));
                    }
                }
            }

            // 11. Extract AuthnStatement
            Saml2AuthnStatement? authnStatement = null;
            var authnNode = assertionElement.SelectSingleNode("./saml:AuthnStatement", nsMgr);
            if (authnNode is XmlElement authnElem)
            {
                var authnInstantStr = authnElem.GetAttribute("AuthnInstant");
                var authnInstant = DateTimeOffset.TryParse(authnInstantStr, out var ai) ? ai : now;
                var sessionIndex = authnElem.GetAttribute("SessionIndex");
                authnStatement = new Saml2AuthnStatement(authnInstant, sessionIndex);
            }

            var assertionId = assertionElement.GetAttribute("ID");

            var assertion = new Saml2Assertion(
                id: string.IsNullOrEmpty(assertionId) ? Guid.NewGuid().ToString("N") : assertionId,
                issueInstant: now,
                issuer: issuer,
                subject: subject,
                rawXml: assertionElement.OuterXml,
                authnStatement: authnStatement,
                attributes: attributes);

            // 12. Map to ClaimsPrincipal
            var principal = _claimsMapper.MapToPrincipal(assertion, _options);
            var result = new Saml2AuthenticationResult(principal, assertion);

            return Task.FromResult(Result<Saml2AuthenticationResult>.Success(result));
        }
        catch (Exception ex)
        {
            return Task.FromResult(Result<Saml2AuthenticationResult>.Failure(
                SecurityError.InvalidToken($"Failed to process SAML response: {ex.Message}")));
        }
    }

    // ── IdP-Initiated SSO ──────────────────────────────────────────────────────

    /// <inheritdoc />
    public Task<Result<Saml2AuthenticationResult>> ProcessIdpInitiatedResponseAsync(
        string samlResponseXml,
        CancellationToken cancellationToken = default)
    {
        if (!_options.AllowIdpInitiatedSso)
        {
            return Task.FromResult(Result<Saml2AuthenticationResult>.Failure(
                SecurityError.SecurityPolicyViolation(
                    "SAML.IdpInitiated",
                    "IdP-initiated SSO is disabled. Set Saml2Options.AllowIdpInitiatedSso = true to enable.")));
        }

        // For IdP-initiated SSO, expectedInResponseTo is null — the base method handles it.
        // We call ProcessResponseAsync but then additionally enforce replay protection.
        ArgumentException.ThrowIfNullOrWhiteSpace(samlResponseXml);
        cancellationToken.ThrowIfCancellationRequested();

        try
        {
            var rawXml = samlResponseXml.Trim();
            if (!rawXml.StartsWith('<'))
            {
                var bytes = Convert.FromBase64String(rawXml);
                rawXml = Encoding.UTF8.GetString(bytes);
            }

            var doc = CreateSecureXmlDocument(rawXml, preserveWhitespace: true);

            var root = doc.DocumentElement!;

            // Security: IdP-initiated responses MUST NOT have InResponseTo
            var inResponseTo = root.GetAttribute("InResponseTo");
            if (!string.IsNullOrEmpty(inResponseTo))
            {
                return Task.FromResult(Result<Saml2AuthenticationResult>.Failure(
                    SecurityError.SecurityPolicyViolation(
                        "SAML.IdpInitiated",
                        "Unexpected InResponseTo attribute in IdP-initiated response. Use ProcessResponseAsync for SP-initiated flows.")));
            }

            // Delegate to the core processing pipeline (without InResponseTo correlation)
            var coreResult = ProcessResponseAsync(samlResponseXml, expectedInResponseTo: null, cancellationToken);

            // Replay protection: check and cache assertion ID
            if (coreResult.Result.IsSuccess)
            {
                var assertionId = coreResult.Result.Value.Assertion.Id;
                var assertionExpiry = _timeProvider.GetUtcNow().Add(_options.IdpInitiatedSsoMaxAssertionAge);

                if (!_seenAssertionIds.TryAdd(assertionId, assertionExpiry))
                {
                    _logger.LogWarning(
                        "SAML assertion replay attack detected. AssertionId={AssertionId} was already processed.",
                        assertionId);
                    return Task.FromResult(Result<Saml2AuthenticationResult>.Failure(
                        SecurityError.SecurityPolicyViolation(
                            "SAML.ReplayAttack",
                            $"Assertion '{assertionId}' has already been processed. Replay attack mitigated.")));
                }

                // Prune expired assertion IDs from the cache (lazy cleanup)
                PruneExpiredAssertionIds();
            }

            return coreResult;
        }
        catch (Exception ex)
        {
            return Task.FromResult(Result<Saml2AuthenticationResult>.Failure(
                SecurityError.InvalidToken($"Failed to process IdP-initiated SAML response: {ex.Message}")));
        }
    }

    internal int MaxReplayCacheCapacity { get; set; } = 50000;

    internal static Result ValidateAssertionTimestamps(
        XmlElement assertionElement,
        XmlNamespaceManager nsMgr,
        DateTimeOffset now,
        TimeSpan skew,
        bool requireExpiration = true)
    {
        var notBeforeStr = assertionElement.SelectSingleNode("./saml:Conditions/@NotBefore", nsMgr)?.Value;
        if (!string.IsNullOrEmpty(notBeforeStr))
        {
            if (DateTimeOffset.TryParse(notBeforeStr, System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.RoundtripKind, out var notBefore))
            {
                if (now + skew < notBefore)
                {
                    return Result.Failure(
                        SecurityError.SecurityPolicyViolation("SAML.Timestamp", $"Assertion is not yet valid (NotBefore: {notBefore}, Now: {now})."));
                }
            }
            else
            {
                return Result.Failure(
                    SecurityError.SecurityPolicyViolation("SAML.Timestamp", "Assertion contains malformed Conditions/@NotBefore attribute."));
            }
        }

        var notOnOrAfterStr = assertionElement.SelectSingleNode("./saml:Conditions/@NotOnOrAfter", nsMgr)?.Value;
        if (string.IsNullOrEmpty(notOnOrAfterStr))
        {
            if (requireExpiration)
            {
                return Result.Failure(
                    SecurityError.SecurityPolicyViolation("SAML.Timestamp", "Assertion missing required Conditions/@NotOnOrAfter expiration attribute."));
            }
        }
        else if (DateTimeOffset.TryParse(notOnOrAfterStr, System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.RoundtripKind, out var notOnOrAfter))
        {
            if (now - skew >= notOnOrAfter)
            {
                return Result.Failure(
                    SecurityError.TokenExpired($"Assertion has expired (NotOnOrAfter: {notOnOrAfter}, Now: {now})."));
            }
        }
        else
        {
            return Result.Failure(
                SecurityError.SecurityPolicyViolation("SAML.Timestamp", "Assertion contains malformed Conditions/@NotOnOrAfter attribute."));
        }

        return Result.Success();
    }

    internal void PruneExpiredAssertionIds()
    {
        var now = _timeProvider.GetUtcNow();
        foreach (var kvp in _seenAssertionIds)
        {
            if (kvp.Value < now)
            {
                _seenAssertionIds.TryRemove(kvp.Key, out _);
            }
        }

        if (_seenAssertionIds.Count > MaxReplayCacheCapacity)
        {
            var excess = _seenAssertionIds.Count - MaxReplayCacheCapacity;
            var keysToRemove = System.Linq.Enumerable.ToList(System.Linq.Enumerable.Take(System.Linq.Enumerable.Select(System.Linq.Enumerable.OrderBy(_seenAssertionIds, k => k.Value), k => k.Key), excess));
            foreach (var key in keysToRemove)
            {
                _seenAssertionIds.TryRemove(key, out _);
            }
        }
    }

    // ── Single Logout (SLO) ────────────────────────────────────────────────────

    /// <inheritdoc />
    public Saml2LogoutRequest CreateLogoutRequest(
        Saml2NameId nameId,
        string? sessionIndex = null,
        string? relayState = null)
    {
        ArgumentNullException.ThrowIfNull(nameId);

        if (string.IsNullOrEmpty(_options.IdpSingleLogoutUrl))
        {
            throw new InvalidOperationException(
                "Saml2Options.IdpSingleLogoutUrl must be configured to create logout requests.");
        }

        var id = "_" + Guid.NewGuid().ToString("N");
        var issueInstant = _timeProvider.GetUtcNow();
        var destination = _options.IdpSingleLogoutUrl;
        var issuer = _options.SpEntityId;

        var doc = new XmlDocument();
        var logoutRequestElem = doc.CreateElement("samlp", "LogoutRequest", Saml2ProtocolNamespace);
        logoutRequestElem.SetAttribute("ID", id);
        logoutRequestElem.SetAttribute("Version", "2.0");
        logoutRequestElem.SetAttribute("IssueInstant", issueInstant.ToString("o"));
        logoutRequestElem.SetAttribute("Destination", destination);

        if (!string.IsNullOrEmpty(relayState))
        {
            logoutRequestElem.SetAttribute("RelayState", relayState);
        }

        var issuerElem = doc.CreateElement("saml", "Issuer", Saml2AssertionNamespace);
        issuerElem.InnerText = issuer;
        logoutRequestElem.AppendChild(issuerElem);

        var nameIdElem = doc.CreateElement("saml", "NameID", Saml2AssertionNamespace);
        nameIdElem.InnerText = nameId.Value;
        logoutRequestElem.AppendChild(nameIdElem);

        if (!string.IsNullOrEmpty(sessionIndex))
        {
            var sessionIndexElem = doc.CreateElement("samlp", "SessionIndex", Saml2ProtocolNamespace);
            sessionIndexElem.InnerText = sessionIndex;
            logoutRequestElem.AppendChild(sessionIndexElem);
        }

        doc.AppendChild(logoutRequestElem);

        if (_options.SignLogoutRequests && _options.SpSigningCertificate is not null)
        {
            _signatureValidator.SignElement(logoutRequestElem, _options.SpSigningCertificate);
        }

        if (_logger.IsEnabled(LogLevel.Information))
        {
            _logger.LogInformation(
                "SAML LogoutRequest created. ID={RequestId}, Destination={Destination}, NameId={NameId}",
                id, destination, nameId.Value);
        }

        return new Saml2LogoutRequest(
            id: id,
            issuer: issuer,
            issueInstant: issueInstant,
            destination: destination,
            nameId: nameId,
            rawXml: doc.OuterXml,
            sessionIndex: sessionIndex);
    }

    /// <inheritdoc />
    public Task<Result<Saml2LogoutResponse>> ProcessLogoutResponseAsync(
        string samlLogoutResponseXml,
        string expectedInResponseTo,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(samlLogoutResponseXml);
        ArgumentException.ThrowIfNullOrWhiteSpace(expectedInResponseTo);
        cancellationToken.ThrowIfCancellationRequested();

        try
        {
            var rawXml = samlLogoutResponseXml.Trim();
            if (!rawXml.StartsWith('<'))
            {
                var bytes = Convert.FromBase64String(rawXml);
                rawXml = Encoding.UTF8.GetString(bytes);
            }

            var doc = CreateSecureXmlDocument(rawXml, preserveWhitespace: true);

            var root = doc.DocumentElement!;

            var nsMgr = new XmlNamespaceManager(doc.NameTable);
            nsMgr.AddNamespace("samlp", Saml2ProtocolNamespace);
            nsMgr.AddNamespace("saml", Saml2AssertionNamespace);

            // Verify InResponseTo correlation
            var inResponseTo = root.GetAttribute("InResponseTo");
            if (!string.Equals(inResponseTo, expectedInResponseTo, StringComparison.Ordinal))
            {
                return Task.FromResult(Result<Saml2LogoutResponse>.Failure(
                    SecurityError.SecurityPolicyViolation(
                        "SAML.SLO.InResponseTo",
                        $"LogoutResponse InResponseTo mismatch: expected '{expectedInResponseTo}', got '{inResponseTo}'.")));
            }

            // Verify signature if required
            if (_options.RequireSignedMessages && _options.IdpSigningCertificate is not null)
            {
                var sigResult = _signatureValidator.VerifySignature(root, _options.IdpSigningCertificate);
                if (sigResult.IsFailure)
                {
                    return Task.FromResult(Result<Saml2LogoutResponse>.Failure(
                        SecurityError.DecryptionFailed("SAML LogoutResponse signature verification failed.")));
                }
            }

            // Extract status
            var statusCodeNode = root.SelectSingleNode("//samlp:StatusCode/@Value", nsMgr);
            var statusCode = statusCodeNode?.Value ?? string.Empty;
            var statusMessage = root.SelectSingleNode("//samlp:StatusMessage", nsMgr)?.InnerText;
            var id = root.GetAttribute("ID");
            var issuer = root.SelectSingleNode("//saml:Issuer", nsMgr)?.InnerText?.Trim() ?? string.Empty;
            var issueInstantStr = root.GetAttribute("IssueInstant");
            var issueInstant = DateTimeOffset.TryParse(issueInstantStr, out var dt) ? dt : _timeProvider.GetUtcNow();

            var response = new Saml2LogoutResponse(
                id: string.IsNullOrEmpty(id) ? Guid.NewGuid().ToString("N") : id,
                issuer: issuer,
                issueInstant: issueInstant,
                inResponseTo: inResponseTo,
                statusCode: statusCode,
                rawXml: root.OuterXml,
                statusMessage: statusMessage);

            if (!response.IsSuccess)
            {
                _logger.LogWarning(
                    "SAML SLO: IdP returned non-success status. StatusCode={StatusCode}, Message={Message}",
                    statusCode, statusMessage);
                return Task.FromResult(Result<Saml2LogoutResponse>.Failure(
                    SecurityError.SecurityPolicyViolation(
                        "SAML.SLO.Status",
                        $"IdP returned SLO error: '{statusCode}'. {statusMessage}")));
            }

            if (_logger.IsEnabled(LogLevel.Information))
            {
                _logger.LogInformation(
                    "SAML SLO completed successfully. InResponseTo={InResponseTo}",
                    inResponseTo);
            }

            return Task.FromResult(Result<Saml2LogoutResponse>.Success(response));
        }
        catch (Exception ex)
        {
            return Task.FromResult(Result<Saml2LogoutResponse>.Failure(
                SecurityError.InvalidToken($"Failed to process SAML LogoutResponse: {ex.Message}")));
        }
    }

    /// <inheritdoc />
    public Saml2LogoutResponse CreateLogoutResponse(
        string inResponseTo,
        string destination,
        bool success = true)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(inResponseTo);
        ArgumentException.ThrowIfNullOrWhiteSpace(destination);

        var id = "_" + Guid.NewGuid().ToString("N");
        var issueInstant = _timeProvider.GetUtcNow();
        var issuer = _options.SpEntityId;
        var statusCode = success
            ? "urn:oasis:names:tc:SAML:2.0:status:Success"
            : "urn:oasis:names:tc:SAML:2.0:status:Responder";

        var doc = new XmlDocument();
        var logoutResponseElem = doc.CreateElement("samlp", "LogoutResponse", Saml2ProtocolNamespace);
        logoutResponseElem.SetAttribute("ID", id);
        logoutResponseElem.SetAttribute("Version", "2.0");
        logoutResponseElem.SetAttribute("IssueInstant", issueInstant.ToString("o"));
        logoutResponseElem.SetAttribute("InResponseTo", inResponseTo);
        logoutResponseElem.SetAttribute("Destination", destination);

        var issuerElem = doc.CreateElement("saml", "Issuer", Saml2AssertionNamespace);
        issuerElem.InnerText = issuer;
        logoutResponseElem.AppendChild(issuerElem);

        var statusElem = doc.CreateElement("samlp", "Status", Saml2ProtocolNamespace);
        var statusCodeElem = doc.CreateElement("samlp", "StatusCode", Saml2ProtocolNamespace);
        statusCodeElem.SetAttribute("Value", statusCode);
        statusElem.AppendChild(statusCodeElem);
        logoutResponseElem.AppendChild(statusElem);

        doc.AppendChild(logoutResponseElem);

        if (_options.SignLogoutRequests && _options.SpSigningCertificate is not null)
        {
            _signatureValidator.SignElement(logoutResponseElem, _options.SpSigningCertificate);
        }

        return new Saml2LogoutResponse(
            id: id,
            issuer: issuer,
            issueInstant: issueInstant,
            inResponseTo: inResponseTo,
            statusCode: statusCode,
            rawXml: doc.OuterXml);
    }

    // ── SP Metadata ─────────────────────────────────────────────────────────────

    /// <inheritdoc />
    public string GenerateSpMetadata()
    {
        const string mdNs = "urn:oasis:names:tc:SAML:2.0:metadata";
        const string dsNs = "http://www.w3.org/2000/09/xmldsig#";

        var doc = new XmlDocument();

        // <md:EntityDescriptor>
        var entityDescriptor = doc.CreateElement("md", "EntityDescriptor", mdNs);
        entityDescriptor.SetAttribute("entityID", _options.SpEntityId);
        doc.AppendChild(entityDescriptor);

        // <md:SPSSODescriptor>
        var spSsoDescriptor = doc.CreateElement("md", "SPSSODescriptor", mdNs);
        spSsoDescriptor.SetAttribute("AuthnRequestsSigned", _options.SignAuthnRequests ? "true" : "false");
        spSsoDescriptor.SetAttribute("WantAssertionsSigned", _options.RequireSignedMessages ? "true" : "false");
        spSsoDescriptor.SetAttribute("protocolSupportEnumeration", "urn:oasis:names:tc:SAML:2.0:protocol");
        entityDescriptor.AppendChild(spSsoDescriptor);

        // Signing certificate KeyDescriptor (if configured)
        if (_options.SpSigningCertificate is not null)
        {
            spSsoDescriptor.AppendChild(
                CreateKeyDescriptor(doc, mdNs, dsNs, _options.SpSigningCertificate, "signing"));
        }

        // Encryption certificate KeyDescriptor (if configured and different from signing)
        if (_options.SpDecryptionCertificate is not null)
        {
            spSsoDescriptor.AppendChild(
                CreateKeyDescriptor(doc, mdNs, dsNs, _options.SpDecryptionCertificate, "encryption"));
        }

        // <md:SingleLogoutService> (if SLO is configured)
        if (!string.IsNullOrEmpty(_options.SpSingleLogoutUrl))
        {
            var sloService = doc.CreateElement("md", "SingleLogoutService", mdNs);
            sloService.SetAttribute("Binding", "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST");
            sloService.SetAttribute("Location", _options.SpSingleLogoutUrl);
            spSsoDescriptor.AppendChild(sloService);

            var sloRedirectService = doc.CreateElement("md", "SingleLogoutService", mdNs);
            sloRedirectService.SetAttribute("Binding", "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect");
            sloRedirectService.SetAttribute("Location", _options.SpSingleLogoutUrl);
            spSsoDescriptor.AppendChild(sloRedirectService);
        }

        // <md:NameIDFormat>
        var nameIdFormat = doc.CreateElement("md", "NameIDFormat", mdNs);
        nameIdFormat.InnerText = ToNameIdFormatUrn(_options.DefaultNameIdFormat);
        spSsoDescriptor.AppendChild(nameIdFormat);

        // <md:AssertionConsumerService> — HTTP-POST binding (index 0, isDefault=true)
        var acsPost = doc.CreateElement("md", "AssertionConsumerService", mdNs);
        acsPost.SetAttribute("Binding", "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST");
        acsPost.SetAttribute("Location", _options.AssertionConsumerServiceUrl);
        acsPost.SetAttribute("index", "1");
        acsPost.SetAttribute("isDefault", "true");
        spSsoDescriptor.AppendChild(acsPost);

        using var sw = new System.IO.StringWriter();
        using var xw = XmlWriter.Create(sw, new XmlWriterSettings
        {
            Indent = true,
            IndentChars = "  ",
            Encoding = Encoding.UTF8,
            OmitXmlDeclaration = false,
        });
        doc.Save(xw);
        return sw.ToString();
    }

    private static XmlElement CreateKeyDescriptor(
        XmlDocument doc,
        string mdNs,
        string dsNs,
        System.Security.Cryptography.X509Certificates.X509Certificate2 certificate,
        string use)
    {
        var keyDescriptor = doc.CreateElement("md", "KeyDescriptor", mdNs);
        keyDescriptor.SetAttribute("use", use);

        var keyInfo = doc.CreateElement("ds", "KeyInfo", dsNs);
        keyDescriptor.AppendChild(keyInfo);

        var x509Data = doc.CreateElement("ds", "X509Data", dsNs);
        keyInfo.AppendChild(x509Data);

        var x509Certificate = doc.CreateElement("ds", "X509Certificate", dsNs);
        x509Certificate.InnerText = Convert.ToBase64String(certificate.RawData);
        x509Data.AppendChild(x509Certificate);

        return keyDescriptor;
    }

    private static string ToNameIdFormatUrn(Saml2NameIdFormat format) => format switch
    {
        Saml2NameIdFormat.EmailAddress => "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
        Saml2NameIdFormat.Transient => "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
        Saml2NameIdFormat.Persistent => "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
        Saml2NameIdFormat.Unspecified => "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
        _ => "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
    };

    private static XmlDocument CreateSecureXmlDocument(string rawXml, bool preserveWhitespace = true)
    {
        var settings = new XmlReaderSettings
        {
            DtdProcessing = DtdProcessing.Prohibit,
            XmlResolver = null,
            MaxCharactersInDocument = 2_000_000
        };

        using var stringReader = new StringReader(rawXml);
        using var xmlReader = XmlReader.Create(stringReader, settings);
        var doc = new XmlDocument
        {
            XmlResolver = null,
            PreserveWhitespace = preserveWhitespace
        };
        doc.Load(xmlReader);
        return doc;
    }
}

