// Copyright © Erickson Lopez. MIT License.
using System;
using System.Collections.Generic;
using System.Security.Cryptography.Xml;

namespace EricksonLopez.Security.Cryptography.XmlDSig;

/// <summary>
/// Specifies configuration options for W3C XML Digital Signature (XMLDSig) generation.
/// </summary>
public sealed class XmlSigningOptions
{
    // XML-003/XML-004 fix: Allowlists of approved algorithm URIs. Callers cannot specify arbitrary URIs
    // that might enable weak algorithms (SHA-1, MD5) or dangerous transforms (XPath exfiltration).

    /// <summary>
    /// Gets the set of permitted canonicalization method URIs.
    /// Attempts to set a URI not in this list will throw <see cref="ArgumentException"/>.
    /// </summary>
    public static readonly IReadOnlySet<string> AllowedCanonicalizationMethods = new HashSet<string>(StringComparer.Ordinal)
    {
        SignedXml.XmlDsigC14NTransformUrl,           // http://www.w3.org/TR/2001/REC-xml-c14n-20010315
        SignedXml.XmlDsigC14NWithCommentsTransformUrl, // http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments
        SignedXml.XmlDsigExcC14NTransformUrl,         // http://www.w3.org/2001/10/xml-exc-c14n#
        SignedXml.XmlDsigExcC14NWithCommentsTransformUrl, // http://www.w3.org/2001/10/xml-exc-c14n#WithComments
    };

    /// <summary>
    /// Gets the set of permitted signature method algorithm URIs.
    /// Attempts to set a URI not in this list will throw <see cref="ArgumentException"/>.
    /// SHA-1 based methods are intentionally excluded.
    /// </summary>
    public static readonly IReadOnlySet<string> AllowedSignatureMethods = new HashSet<string>(StringComparer.Ordinal)
    {
        SignedXml.XmlDsigRSASHA256Url,      // http://www.w3.org/2001/04/xmldsig-more#rsa-sha256
        SignedXml.XmlDsigRSASHA384Url,      // http://www.w3.org/2001/04/xmldsig-more#rsa-sha384
        SignedXml.XmlDsigRSASHA512Url,      // http://www.w3.org/2001/04/xmldsig-more#rsa-sha512
    };

    /// <summary>
    /// Gets the set of permitted digest method algorithm URIs.
    /// Attempts to set a URI not in this list will throw <see cref="ArgumentException"/>.
    /// SHA-1 and MD5 digests are intentionally excluded.
    /// </summary>
    public static readonly IReadOnlySet<string> AllowedDigestMethods = new HashSet<string>(StringComparer.Ordinal)
    {
        SignedXml.XmlDsigSHA256Url,   // http://www.w3.org/2001/04/xmlenc#sha256
        SignedXml.XmlDsigSHA384Url,   // http://www.w3.org/2001/04/xmldsig-more#sha384
        SignedXml.XmlDsigSHA512Url,   // http://www.w3.org/2001/04/xmlenc#sha512
    };

    private string _canonicalizationMethod = SignedXml.XmlDsigC14NTransformUrl;
    private string _signatureMethod = SignedXml.XmlDsigRSASHA256Url;
    private string _digestMethod = SignedXml.XmlDsigSHA256Url;

    /// <summary>
    /// Gets or sets the URI of the canonicalization method algorithm.
    /// Default is C14N 1.0 (<c>http://www.w3.org/TR/2001/REC-xml-c14n-20010315</c>).
    /// </summary>
    /// <exception cref="ArgumentException">The specified URI is not in <see cref="AllowedCanonicalizationMethods"/></exception>
    public string CanonicalizationMethod
    {
        get => _canonicalizationMethod;
        set
        {
            // XML-003 fix: validate against allowlist to prevent dangerous transforms like XPath.
            if (!AllowedCanonicalizationMethods.Contains(value))
            {
                throw new ArgumentException(
                    $"Canonicalization method '{value}' is not in the list of approved algorithms. " +
                    $"Use one of: {string.Join(", ", AllowedCanonicalizationMethods)}",
                    nameof(value));
            }
            _canonicalizationMethod = value;
        }
    }

    /// <summary>
    /// Gets or sets the URI of the signature method algorithm.
    /// Default is RSA-SHA256 (<c>http://www.w3.org/2001/04/xmldsig-more#rsa-sha256</c>).
    /// SHA-1 based methods are not permitted.
    /// </summary>
    /// <exception cref="ArgumentException">The specified URI is not in <see cref="AllowedSignatureMethods"/></exception>
    public string SignatureMethod
    {
        get => _signatureMethod;
        set
        {
            // XML-004 fix: validate against allowlist to prevent weak signature methods (e.g., RSA-SHA1).
            if (!AllowedSignatureMethods.Contains(value))
            {
                throw new ArgumentException(
                    $"Signature method '{value}' is not in the list of approved algorithms. " +
                    $"Weak methods (e.g., RSA-SHA1) are not permitted. " +
                    $"Use one of: {string.Join(", ", AllowedSignatureMethods)}",
                    nameof(value));
            }
            _signatureMethod = value;
        }
    }

    /// <summary>
    /// Gets or sets the URI of the reference digest method algorithm.
    /// Default is SHA256 (<c>http://www.w3.org/2001/04/xmlenc#sha256</c>).
    /// SHA-1 and MD5 digests are not permitted.
    /// </summary>
    /// <exception cref="ArgumentException">The specified URI is not in <see cref="AllowedDigestMethods"/></exception>
    public string DigestMethod
    {
        get => _digestMethod;
        set
        {
            if (!AllowedDigestMethods.Contains(value))
            {
                throw new ArgumentException(
                    $"Digest method '{value}' is not in the list of approved algorithms. " +
                    $"Use one of: {string.Join(", ", AllowedDigestMethods)}",
                    nameof(value));
            }
            _digestMethod = value;
        }
    }

    /// <summary>
    /// Gets or sets the reference URI pointing to the signed element.
    /// Default is empty string (""), indicating the entire containing document.
    /// </summary>
    public string ReferenceUri { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets a value indicating whether to embed the public X.509 certificate in the &lt;KeyInfo&gt; element.
    /// Default is <see langword="true"/>.
    /// </summary>
    public bool IncludeKeyInfo { get; set; } = true;

    /// <summary>
    /// Gets or sets the maximum number of characters allowed in the XML document to prevent memory exhaustion DoS attacks.
    /// Default is 10,000,000 characters.
    /// </summary>
    public long MaxCharactersInDocument { get; set; } = 10_000_000;
}
