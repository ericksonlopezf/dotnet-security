// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Saml2.Cryptography;

using System;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;
using EricksonLopez.Result;
using EricksonLopez.Security.Abstractions.Errors;
using EricksonLopez.Security.Saml2.Abstractions;
using Result = global::EricksonLopez.Result.Result;

/// <summary>
/// Validates and signs SAML 2.0 XML messages using XMLDSig standards.
/// </summary>
public sealed class Saml2SignatureValidator : ISaml2SignatureValidator
{
    private const string XmlDSigNamespace = "http://www.w3.org/2000/09/xmldsig#";

    /// <inheritdoc />
    public Result VerifySignature(XmlElement element, X509Certificate2 certificate)
    {
        ArgumentNullException.ThrowIfNull(element);
        ArgumentNullException.ThrowIfNull(certificate);

        try
        {
            var ownerDoc = element.OwnerDocument!;
            var nsMgr = new XmlNamespaceManager(ownerDoc.NameTable);
            nsMgr.AddNamespace("ds", XmlDSigNamespace);

            // Find <ds:Signature> inside this element
            var signatureNode = element.SelectSingleNode("./ds:Signature", nsMgr);
            if (signatureNode is not XmlElement signatureElement)
            {
                return Result.Failure(SecurityError.InvalidToken("No XMLDSig <ds:Signature> element found in the target element."));
            }

            var signedXml = new SignedXml(ownerDoc);
            signedXml.LoadXml(signatureElement);

            // Check reference target matches element ID
            var targetId = element.GetAttribute("ID");
            if (string.IsNullOrEmpty(targetId))
            {
                targetId = element.GetAttribute("id");
            }

            if (signedXml.SignedInfo is null || signedXml.SignedInfo.References.Count == 0)
            {
                return Result.Failure(SecurityError.InvalidToken("XMLDSig contains no signed references."));
            }

            var reference = (Reference)signedXml.SignedInfo.References[0]!;
            var refUri = reference.Uri?.TrimStart('#');

            if (!string.IsNullOrEmpty(targetId) && !string.Equals(refUri, targetId, StringComparison.Ordinal))
            {
                return Result.Failure(
                    SecurityError.SecurityPolicyViolation("SAML.Signature", $"Signature reference URI '#{refUri}' does not match element ID '{targetId}'."));
            }

            var isValid = signedXml.CheckSignature(certificate, verifySignatureOnly: true);
            return isValid
                ? Result.Success()
                : Result.Failure(SecurityError.DecryptionFailed("XMLDSig signature verification failed with provided certificate."));
        }
        catch (Exception ex)
        {
            return Result.Failure(SecurityError.DecryptionFailed($"XMLDSig signature evaluation error: {ex.Message}"));
        }
    }

    /// <inheritdoc />
    public Result SignElement(XmlElement element, X509Certificate2 certificate)
    {
        ArgumentNullException.ThrowIfNull(element);
        ArgumentNullException.ThrowIfNull(certificate);

        if (!certificate.HasPrivateKey)
        {
            return Result.Failure(SecurityError.InvalidKey("Certificate does not contain a private key for signing."));
        }

        try
        {
            var targetId = element.GetAttribute("ID");
            if (string.IsNullOrEmpty(targetId))
            {
                targetId = "_" + Guid.NewGuid().ToString("N");
                element.SetAttribute("ID", targetId);
            }

            var rsaKey = certificate.GetRSAPrivateKey();
            if (rsaKey is null)
            {
                return Result.Failure(SecurityError.InvalidKey("Could not extract RSA private key from certificate."));
            }

            var ownerDoc = element.OwnerDocument!;
            var signedXml = new SignedXml(ownerDoc)
            {
                SigningKey = rsaKey
            };

            signedXml.SignedInfo!.CanonicalizationMethod = SignedXml.XmlDsigExcC14NTransformUrl;
            signedXml.SignedInfo!.SignatureMethod = SignedXml.XmlDsigRSASHA256Url;

            var reference = new Reference
            {
                Uri = "#" + targetId
            };
            reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
            reference.AddTransform(new XmlDsigExcC14NTransform());
            reference.DigestMethod = SignedXml.XmlDsigSHA256Url;

            signedXml.AddReference(reference);

            var keyInfo = new KeyInfo();
            keyInfo.AddClause(new KeyInfoX509Data(certificate));
            signedXml.KeyInfo = keyInfo;

            signedXml.ComputeSignature();
            var xmlDigitalSignature = signedXml.GetXml();

            // Append signature after <saml:Issuer> if present, or as first child
            var issuerNode = element.SelectSingleNode("./*[local-name()='Issuer']");
            if (issuerNode is not null && issuerNode.NextSibling is not null)
            {
                element.InsertAfter(ownerDoc.ImportNode(xmlDigitalSignature, true), issuerNode);
            }
            else
            {
                element.AppendChild(ownerDoc.ImportNode(xmlDigitalSignature, true));
            }

            return Result.Success();
        }
        catch (Exception ex)
        {
            return Result.Failure(SecurityError.EncryptionFailed($"Failed to sign XML element: {ex.Message}"));
        }
    }
}
