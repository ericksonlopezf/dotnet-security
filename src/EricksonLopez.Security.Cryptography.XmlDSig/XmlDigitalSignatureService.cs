// Copyright © Erickson Lopez. MIT License.
using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;
using EricksonLopez.Result;

namespace EricksonLopez.Security.Cryptography.XmlDSig;

/// <summary>
/// Provides W3C XML Digital Signature (XMLDSig) generation and verification operations.
/// </summary>
public sealed class XmlDigitalSignatureService : IXmlDigitalSigner, IXmlDigitalSignatureVerifier
{
    /// <summary>
    /// Gets the default shared singleton instance of <see cref="XmlDigitalSignatureService"/>.
    /// </summary>
    public static readonly XmlDigitalSignatureService Instance = new();

    /// <inheritdoc />
    public Result<string> SignXml(string xmlContent, X509Certificate2 certificate, XmlSigningOptions? options = null)
    {
        if (string.IsNullOrWhiteSpace(xmlContent))
        {
            return Error.Validation("XmlDigitalSignatureService.EmptyXml", "XML content cannot be null or empty.");
        }

        ArgumentNullException.ThrowIfNull(certificate);

        try
        {
            var doc = new XmlDocument { PreserveWhitespace = true };
            using var stringReader = new StringReader(xmlContent);
            using var xmlReader = XmlReader.Create(stringReader, new XmlReaderSettings
            {
                DtdProcessing = DtdProcessing.Prohibit,
                XmlResolver = null,
                MaxCharactersInDocument = options?.MaxCharactersInDocument ?? 10_000_000
            });
            doc.Load(xmlReader);

            var signResult = SignXml(doc, certificate, options);
            if (signResult.IsFailure)
            {
                return signResult.Error;
            }

            return Result<string>.Success(doc.OuterXml);
        }
        catch (Exception ex)
        {
            return Error.Failure("XmlDigitalSignatureService.SignXmlFailed", $"XML signing failed: {ex.Message}");
        }
    }

    /// <inheritdoc />
    public Result<XmlDocument> SignXml(XmlDocument document, X509Certificate2 certificate, XmlSigningOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(document);
        ArgumentNullException.ThrowIfNull(certificate);

        if (document.DocumentElement is null)
        {
            return Error.Validation("XmlDigitalSignatureService.EmptyDocument", "XML document has no root element.");
        }

        var rsaKey = certificate.GetRSAPrivateKey();
        if (rsaKey is null)
        {
            return Error.Forbidden("XmlDigitalSignatureService.NoPrivateKey", "The certificate does not contain an accessible RSA private key.");
        }

        options ??= new XmlSigningOptions();

        try
        {
            var signedXml = new SignedXml(document)
            {
                SigningKey = rsaKey
            };

            var reference = new Reference(options.ReferenceUri);
            reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
            reference.AddTransform(new XmlDsigC14NTransform());
            reference.DigestMethod = options.DigestMethod;
            signedXml.AddReference(reference);

            if (signedXml.SignedInfo is not null)
            {
                signedXml.SignedInfo.CanonicalizationMethod = options.CanonicalizationMethod;
                signedXml.SignedInfo.SignatureMethod = options.SignatureMethod;
            }

            if (options.IncludeKeyInfo)
            {
                var keyInfo = new KeyInfo();
                keyInfo.AddClause(new KeyInfoX509Data(certificate));
                signedXml.KeyInfo = keyInfo;
            }

            signedXml.ComputeSignature();
            var xmlDigitalSignature = signedXml.GetXml();

            document.DocumentElement.AppendChild(document.ImportNode(xmlDigitalSignature, true));

            return Result<XmlDocument>.Success(document);
        }
        catch (Exception ex)
        {
            return Error.Failure("XmlDigitalSignatureService.ComputationFailed", $"Failed to compute XML signature: {ex.Message}");
        }
    }

    /// <inheritdoc />
    public Result<bool> VerifyXml(string xmlContent, X509Certificate2? expectedCertificate = null) =>
        VerifyXml(xmlContent, expectedCertificate, options: null);

    /// <inheritdoc />
    public Result<bool> VerifyXml(string xmlContent, X509Certificate2? expectedCertificate, XmlVerificationOptions? options)
    {
        if (string.IsNullOrWhiteSpace(xmlContent))
        {
            return Error.Validation("XmlDigitalSignatureService.EmptyXml", "XML content cannot be null or empty.");
        }

        try
        {
            var doc = new XmlDocument { PreserveWhitespace = true };
            using var stringReader = new StringReader(xmlContent);
            using var xmlReader = XmlReader.Create(stringReader, new XmlReaderSettings
            {
                DtdProcessing = DtdProcessing.Prohibit,
                XmlResolver = null,
                MaxCharactersInDocument = options?.MaxCharactersInDocument ?? 10_000_000
            });
            doc.Load(xmlReader);

            return VerifyXml(doc, expectedCertificate, options);
        }
        catch (Exception ex)
        {
            return Error.Failure("XmlDigitalSignatureService.VerifyXmlFailed", $"XML verification failed: {ex.Message}");
        }
    }

    /// <inheritdoc />
    public Result<bool> VerifyXml(XmlDocument document, X509Certificate2? expectedCertificate = null) =>
        VerifyXml(document, expectedCertificate, options: null);

    /// <inheritdoc />
    public Result<bool> VerifyXml(XmlDocument document, X509Certificate2? expectedCertificate, XmlVerificationOptions? options)
    {
        var extractResult = VerifyAndExtractSignedElement(document, expectedCertificate, options);
        if (extractResult.IsFailure)
        {
            return extractResult.Error;
        }

        return Result<bool>.Success(extractResult.Value.IsValid);
    }

    /// <inheritdoc />
    public Result<XmlVerificationResult> VerifyAndExtractSignedElement(
        XmlDocument document,
        X509Certificate2? expectedCertificate = null,
        XmlVerificationOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(document);

        var signatureNodes = document.GetElementsByTagName("Signature", SignedXml.XmlDsigNamespaceUrl);
        if (signatureNodes.Count == 0)
        {
            return Error.NotFound("XmlDigitalSignatureService.SignatureNotFound", "No <Signature> element found in the document.");
        }

        var opt = options ?? new XmlVerificationOptions();
        if (signatureNodes.Count > 1 && !opt.AllowMultipleSignatures)
        {
            return Error.Validation(
                "XmlDigitalSignatureService.MultipleSignaturesNotAllowed",
                $"Found {signatureNodes.Count} <Signature> elements in XML document. Multiple signatures are rejected by default to prevent signature ambiguity attacks.");
        }

        if (!opt.AllowDuplicateIds)
        {
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
                                        return Error.Validation(
                                            "XmlDigitalSignatureService.DuplicateIdDetected",
                                            $"Duplicate ID '{idVal}' detected in XML document (XSW mitigation).");
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        var sigElem = (XmlElement)signatureNodes[0]!;
        if (opt.AllowedTransformAlgorithms is not null)
        {
            var transformNodes = sigElem.GetElementsByTagName("Transform", SignedXml.XmlDsigNamespaceUrl);
            foreach (XmlNode tNode in transformNodes)
            {
                if (tNode is XmlElement tElem)
                {
                    var alg = tElem.GetAttribute("Algorithm");
                    if (string.IsNullOrEmpty(alg) || !opt.AllowedTransformAlgorithms.Contains(alg))
                    {
                        return Error.Validation(
                            "XmlDigitalSignatureService.DisallowedTransform",
                            $"XML transform algorithm '{alg}' is not permitted by verification policy.");
                    }
                }
            }
        }

        try
        {
            var signedXml = new SignedXml(document);
            signedXml.LoadXml(sigElem);

            if (signedXml.SignedInfo?.References is not null && opt.AllowedTransformAlgorithms is not null)
            {
                foreach (Reference refItem in signedXml.SignedInfo.References)
                {
                    if (refItem.TransformChain is not null)
                    {
                        foreach (Transform transform in refItem.TransformChain)
                        {
                            if (transform.Algorithm is null || !opt.AllowedTransformAlgorithms.Contains(transform.Algorithm))
                            {
                                return Error.Validation(
                                    "XmlDigitalSignatureService.DisallowedTransform",
                                    $"XML transform algorithm '{transform.Algorithm}' is not permitted by verification policy.");
                            }
                        }
                    }
                }
            }

            bool isValid;
            X509Certificate2? verifiedCert = expectedCertificate;

            if (expectedCertificate is not null)
            {
                using var rsaPublic = expectedCertificate.GetRSAPublicKey();
                if (rsaPublic is null)
                {
                    return Error.Forbidden("XmlDigitalSignatureService.NoPublicKey", "Expected certificate has no RSA public key.");
                }

                isValid = signedXml.CheckSignature(rsaPublic);
            }
            else
            {
                // Attempt to extract certificate from KeyInfo
                var certExtractionResult = XmlSignatureCertificateExtractor.ExtractCertificate(document);
                if (certExtractionResult.IsSuccess)
                {
                    var embeddedCert = certExtractionResult.Value;
                    verifiedCert = embeddedCert;

                    // SEC-CRIT-01: Validate trust of the embedded certificate
                    if (!opt.AllowUntrustedEmbeddedCertificate)
                    {
                        if (opt.CertificateTrustEvaluator is not null)
                        {
                            if (!opt.CertificateTrustEvaluator(embeddedCert))
                            {
                                return Error.Forbidden(
                                    "XmlDigitalSignatureService.UntrustedCertificate",
                                    "The embedded certificate in KeyInfo failed custom trust policy validation.");
                            }
                        }
                        else if (opt.CustomTrustAnchors is not null && opt.CustomTrustAnchors.Count > 0)
                        {
                            using var chain = new X509Chain();
                            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                            chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
                            foreach (var anchor in opt.CustomTrustAnchors)
                            {
                                chain.ChainPolicy.CustomTrustStore.Add(anchor);
                            }

                            if (!chain.Build(embeddedCert))
                            {
                                return Error.Forbidden(
                                    "XmlDigitalSignatureService.UntrustedCertificate",
                                    "The embedded certificate in KeyInfo does not chain to any configured custom trust anchor.");
                            }
                        }
                        else if (opt.RequireTrustedCertificate)
                        {
                            using var chain = new X509Chain();
                            if (!chain.Build(embeddedCert))
                            {
                                return Error.Forbidden(
                                    "XmlDigitalSignatureService.UntrustedCertificate",
                                    "The embedded certificate in KeyInfo is not trusted and does not chain to a trusted CA root. " +
                                    "To verify safely, provide the expected certificate, configure custom trust anchors, or specify a CertificateTrustEvaluator.");
                            }
                        }
                    }

                    using var rsaPublic = embeddedCert.GetRSAPublicKey();
                    isValid = rsaPublic is not null && signedXml.CheckSignature(rsaPublic);
                }
                else
                {
                    if (opt.AllowUntrustedEmbeddedCertificate)
                    {
                        isValid = signedXml.CheckSignature();
                    }
                    else
                    {
                        return Error.Forbidden(
                            "XmlDigitalSignatureService.CertificateNotFound",
                            "No expected certificate was provided and no valid certificate was found in KeyInfo.");
                    }
                }
            }

            if (!isValid)
            {
                return Error.Forbidden("XmlDigitalSignatureService.InvalidSignature", "The XML digital signature failed cryptographic verification.");
            }

            // Extract the authenticated signed element to protect against XML Signature Wrapping (XSW)
            XmlElement? signedElement = null;
            string? refUri = null;
            if (signedXml.SignedInfo?.References.Count > 0)
            {
                var reference = (Reference)signedXml.SignedInfo.References[0]!;
                refUri = reference.Uri;
                if (string.IsNullOrEmpty(refUri))
                {
                    signedElement = document.DocumentElement;
                }
                else if (refUri.StartsWith('#'))
                {
                    string id = refUri.Substring(1);
                    if (!IsValidXmlId(id))
                    {
                        return Error.Validation("XmlDigitalSignatureService.InvalidReferenceId", "Malformed signature reference ID format.");
                    }

                    signedElement = FindElementByIdSafe(document, id);
                }
            }

            return Result<XmlVerificationResult>.Success(new XmlVerificationResult(
                isValid: true,
                signedElement: signedElement,
                referenceUri: refUri,
                signingCertificate: verifiedCert));
        }
        catch (Exception ex)
        {
            return Error.Failure("XmlDigitalSignatureService.VerificationError", $"Error during XML signature validation: {ex.Message}");
        }
    }

    private static bool IsValidXmlId(string id)
    {
        if (string.IsNullOrEmpty(id) || id.Length > 256)
        {
            return false;
        }

        if (!char.IsLetter(id[0]) && id[0] != '_')
        {
            return false;
        }

        for (int i = 1; i < id.Length; i++)
        {
            char c = id[i];
            if (!char.IsLetterOrDigit(c) && c != '.' && c != '-' && c != '_')
            {
                return false;
            }
        }

        return true;
    }

    private const int MaxXmlNestingDepth = 64;

    private static XmlElement? FindElementByIdSafe(XmlNode parent, string targetId)
    {
        var stack = new Stack<(XmlNode Node, int Depth)>();
        stack.Push((parent, 0));

        while (stack.Count > 0)
        {
            var (current, depth) = stack.Pop();
            if (depth > MaxXmlNestingDepth)
            {
                throw new CryptographicException($"XML structure exceeds maximum permitted nesting depth of {MaxXmlNestingDepth}.");
            }

            if (current is XmlElement elem)
            {
                if (string.Equals(elem.GetAttribute("Id"), targetId, StringComparison.Ordinal) ||
                    string.Equals(elem.GetAttribute("id"), targetId, StringComparison.Ordinal) ||
                    string.Equals(elem.GetAttribute("ID"), targetId, StringComparison.Ordinal))
                {
                    return elem;
                }
            }

            for (int i = current.ChildNodes.Count - 1; i >= 0; i--)
            {
                var child = current.ChildNodes[i];
                if (child is not null)
                {
                    stack.Push((child, depth + 1));
                }
            }
        }

        return null;
    }
}
