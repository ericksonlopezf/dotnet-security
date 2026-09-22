// Copyright © Erickson Lopez. MIT License.
using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;

namespace EricksonLopez.Security.Cryptography.XmlDSig;

/// <summary>
/// Specifies configuration options for verifying W3C XML Digital Signatures (XMLDSig).
/// </summary>
public sealed class XmlVerificationOptions
{
    /// <summary>
    /// Gets or sets a value indicating whether embedded certificates in KeyInfo must be validated against a trusted chain or root anchor.
    /// </summary>
    public bool RequireTrustedCertificate { get; set; } = true;

    /// <summary>
    /// Gets or sets a collection of custom trusted root certificates for evaluating embedded certificates.
    /// </summary>
    public IList<X509Certificate2> CustomTrustAnchors { get; set; } = new List<X509Certificate2>();

    /// <summary>
    /// Gets or sets a custom certificate trust evaluator predicate.
    /// </summary>
    public Func<X509Certificate2, bool>? CertificateTrustEvaluator { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether to allow untrusted embedded certificates without chain validation.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <strong>⚠️ SECURITY RISK — DO NOT USE IN PRODUCTION.</strong>
    /// </para>
    /// <para>
    /// Setting this to <see langword="true"/> completely bypasses certificate trust validation.
    /// An attacker can generate their own self-signed certificate, embed it in the
    /// <c>&lt;KeyInfo&gt;</c> element of a forged XML document, sign that document with the
    /// corresponding private key, and the verification will succeed because it uses the
    /// attacker's certificate to verify the attacker's signature.
    /// </para>
    /// <para>
    /// This option exists only to facilitate unit testing and debugging against unsigned/self-signed
    /// test documents. <strong>Never set this to <see langword="true"/> in production code.</strong>
    /// </para>
    /// <para>
    /// Safer alternatives:
    /// <list type="bullet">
    ///   <item>Provide the expected certificate directly to <c>VerifyXml(xmlContent, expectedCertificate)</c>.</item>
    ///   <item>Populate <see cref="CustomTrustAnchors"/> with your trusted CA certificates.</item>
    ///   <item>Set <see cref="CertificateTrustEvaluator"/> to a predicate that validates against your PKI.</item>
    /// </list>
    /// </para>
    /// </remarks>
    public bool AllowUntrustedEmbeddedCertificate { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether to allow documents containing multiple &lt;Signature&gt; elements.
    /// </summary>
    /// <remarks>
    /// When <see langword="false"/> (the default, secure setting), XML documents with more than one
    /// <c>&lt;Signature&gt;</c> element are rejected with a validation error. This prevents XML Signature Wrapping (XSW)
    /// and signature selection ambiguity attacks where an untrusted signature wraps or precedes an authentic signature.
    /// Set to <see langword="true"/> only if multi-signature documents are explicitly expected and handled.
    /// </remarks>
    public bool AllowMultipleSignatures { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether duplicate ID attributes are permitted in the XML document.
    /// </summary>
    /// <remarks>
    /// When <see langword="false"/> (the default, secure setting), documents with duplicate ID attributes
    /// are rejected with a validation error to prevent XML Signature Wrapping (XSW) and element confusion attacks.
    /// </remarks>
    public bool AllowDuplicateIds { get; set; }

    /// <summary>
    /// Gets or sets the maximum number of characters allowed in the XML document to prevent memory exhaustion DoS attacks.
    /// Default is 10,000,000 characters.
    /// </summary>
    public long MaxCharactersInDocument { get; set; } = 10_000_000;

    /// <summary>
    /// Gets or sets the set of allowed XMLDSig transform algorithm URIs.
    /// By default, dangerous transforms like XSLT or XPath are rejected to prevent remote code execution and DoS.
    /// </summary>
    public ISet<string> AllowedTransformAlgorithms { get; set; } = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
        "http://www.w3.org/TR/2001/REC-xml-c14n-20010315",
        "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments",
        "http://www.w3.org/2001/10/xml-exc-c14n#",
        "http://www.w3.org/2001/10/xml-exc-c14n#WithComments",
        "http://www.w3.org/2000/09/xmldsig#base64"
    };
}

