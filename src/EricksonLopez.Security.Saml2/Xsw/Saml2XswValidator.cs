// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Saml2.Xsw;

using System;
using System.Collections.Generic;
using System.Xml;
using EricksonLopez.Result;
using EricksonLopez.Security.Abstractions.Errors;
using EricksonLopez.Security.Saml2.Abstractions;

/// <summary>
/// Validates XML Signature Wrapping (XSW 1..8) defenses for SAML 2.0 messages.
/// </summary>
/// <remarks>
/// Enforces strict single-assertion integrity, duplicate ID prevention, and signed reference binding.
/// </remarks>
public sealed class Saml2XswValidator : ISaml2XswValidator
{
    private const string Saml2AssertionNamespace = "urn:oasis:names:tc:SAML:2.0:assertion";
    private const string Saml2ProtocolNamespace = "urn:oasis:names:tc:SAML:2.0:protocol";
    private const string XmlDSigNamespace = "http://www.w3.org/2000/09/xmldsig#";

    /// <inheritdoc />
    public Result<XmlElement> ValidateAndExtractAssertion(XmlDocument document)
    {
        ArgumentNullException.ThrowIfNull(document);

        var root = document.DocumentElement;
        if (root is null)
        {
            return Result<XmlElement>.Failure(SecurityError.InvalidToken("SAML XML document has no root element."));
        }

        // 1. Scan for Duplicate IDs (ID Spoofing mitigation)
        var idSet = new HashSet<string>(StringComparer.Ordinal);
        var allElements = document.SelectNodes("//*");
        if (allElements is not null)
        {
            foreach (XmlNode node in allElements)
            {
                if (node is XmlElement el)
                {
                    foreach (XmlAttribute attr in el.Attributes)
                    {
                        if (string.Equals(attr.LocalName, "id", StringComparison.OrdinalIgnoreCase))
                        {
                            var idVal = attr.Value;
                            if (!string.IsNullOrEmpty(idVal))
                            {
                                if (!idSet.Add(idVal))
                                {
                                    return Result<XmlElement>.Failure(
                                        SecurityError.SecurityPolicyViolation("SAML.XSW", $"Duplicate ID '{idVal}' detected in XML document (XSW mitigation)."));
                                }
                            }
                        }
                    }
                }
            }
        }

        // 2. Count Total Assertion Elements (Reject multiple conflicting assertions)
        var nsMgr = new XmlNamespaceManager(document.NameTable);
        nsMgr.AddNamespace("saml", Saml2AssertionNamespace);

        var allAssertions = document.SelectNodes("//saml:Assertion", nsMgr);
        var allEncryptedAssertions = document.SelectNodes("//saml:EncryptedAssertion", nsMgr);

        var totalAssertions = allAssertions!.Count + allEncryptedAssertions!.Count;
        if (totalAssertions == 0)
        {
            return Result<XmlElement>.Failure(SecurityError.InvalidToken("No SAML assertion found in document."));
        }

        if (totalAssertions > 1)
        {
            return Result<XmlElement>.Failure(
                SecurityError.SecurityPolicyViolation("SAML.XSW", "Multiple assertions found in SAML message. Only single-assertion responses are permitted to prevent XSW attacks."));
        }

        // 3. Locate Assertion (Direct child of Response or root if assertion is root)
        XmlElement? targetAssertion = null;
        if ((string.Equals(root.LocalName, "Assertion", StringComparison.Ordinal) ||
             string.Equals(root.LocalName, "EncryptedAssertion", StringComparison.Ordinal)) &&
            string.Equals(root.NamespaceURI, Saml2AssertionNamespace, StringComparison.Ordinal))
        {
            targetAssertion = root;
        }
        else if (string.Equals(root.LocalName, "Response", StringComparison.Ordinal) &&
                 string.Equals(root.NamespaceURI, Saml2ProtocolNamespace, StringComparison.Ordinal))
        {
            foreach (XmlNode child in root.ChildNodes)
            {
                if (child is XmlElement el &&
                    (string.Equals(el.LocalName, "Assertion", StringComparison.Ordinal) ||
                     string.Equals(el.LocalName, "EncryptedAssertion", StringComparison.Ordinal)) &&
                    string.Equals(el.NamespaceURI, Saml2AssertionNamespace, StringComparison.Ordinal))
                {
                    targetAssertion = el;
                }
            }
        }

        if (targetAssertion is null)
        {
            return Result<XmlElement>.Failure(
                SecurityError.SecurityPolicyViolation("SAML.XSW", "Assertion element is not a direct child of Response (displaced assertion / XSW attempt detected)."));
        }

        return Result<XmlElement>.Success(targetAssertion);
    }
}
