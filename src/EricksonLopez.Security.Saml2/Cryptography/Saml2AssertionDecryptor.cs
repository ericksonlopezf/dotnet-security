// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Saml2.Cryptography;

using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;
using EricksonLopez.Result;
using EricksonLopez.Security.Abstractions.Errors;
using EricksonLopez.Security.Saml2.Abstractions;

/// <summary>
/// Decrypts SAML 2.0 <c>&lt;saml:EncryptedAssertion&gt;</c> structures.
/// </summary>
public sealed class Saml2AssertionDecryptor : ISaml2AssertionDecryptor
{
    /// <inheritdoc />
    public Result<XmlElement> DecryptAssertion(XmlElement encryptedAssertionElement, X509Certificate2 decryptionCertificate)
    {
        ArgumentNullException.ThrowIfNull(encryptedAssertionElement);
        ArgumentNullException.ThrowIfNull(decryptionCertificate);

        if (!decryptionCertificate.HasPrivateKey)
        {
            return Result<XmlElement>.Failure(SecurityError.InvalidKey("Decryption certificate has no private key."));
        }

        try
        {
            var encryptedDataNode = encryptedAssertionElement.SelectSingleNode("./*[local-name()='EncryptedData']");
            if (encryptedDataNode is not XmlElement encryptedDataElement)
            {
                return Result<XmlElement>.Failure(SecurityError.InvalidToken("No <xenc:EncryptedData> found in EncryptedAssertion."));
            }

            var ownerDoc = encryptedAssertionElement.OwnerDocument!;
            var encryptedXml = new EncryptedXml(ownerDoc);
            var rsaKey = decryptionCertificate.GetRSAPrivateKey();

            var encryptedData = new EncryptedData();
            encryptedData.LoadXml(encryptedDataElement);

            SymmetricAlgorithm? symAlg = null;
            if (encryptedData.KeyInfo is not null && rsaKey is not null)
            {
                foreach (KeyInfoClause clause in encryptedData.KeyInfo)
                {
                    if (clause is KeyInfoEncryptedKey keyInfoEncryptedKey &&
                        keyInfoEncryptedKey.EncryptedKey?.CipherData?.CipherValue is { } cipherVal)
                    {
                        var isOaep = string.Equals(
                            keyInfoEncryptedKey.EncryptedKey.EncryptionMethod?.KeyAlgorithm,
                            EncryptedXml.XmlEncRSAOAEPUrl,
                            StringComparison.Ordinal);

                        var keyBytes = EncryptedXml.DecryptKey(
                            cipherVal,
                            rsaKey,
                            isOaep);

                        var alg = Aes.Create();
                        alg.Key = keyBytes;
                        symAlg = alg;
                        break;
                    }
                }
            }

            symAlg ??= encryptedXml.GetDecryptionKey(encryptedData, null);
            if (symAlg is null)
            {
                return Result<XmlElement>.Failure(SecurityError.DecryptionFailed("Could not resolve symmetric decryption key for EncryptedAssertion."));
            }

            byte[] decryptedBytes;
            using (symAlg)
            {
                decryptedBytes = encryptedXml.DecryptData(encryptedData, symAlg);
            }

            var settings = new XmlReaderSettings
            {
                DtdProcessing = DtdProcessing.Prohibit,
                XmlResolver = null,
                MaxCharactersInDocument = 2_000_000
            };

            using var stringReader = new StringReader(System.Text.Encoding.UTF8.GetString(decryptedBytes));
            using var xmlReader = XmlReader.Create(stringReader, settings);
            var decryptedDoc = new XmlDocument
            {
                XmlResolver = null,
                PreserveWhitespace = true
            };
            decryptedDoc.Load(xmlReader);

            return Result<XmlElement>.Success(decryptedDoc.DocumentElement!);
        }
        catch (Exception ex)
        {
            return Result<XmlElement>.Failure(SecurityError.DecryptionFailed($"Failed to decrypt SAML assertion: {ex.Message}"));
        }
    }
}
