// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Saml2.Tests;

using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;
using AwesomeAssertions;
using EricksonLopez.Security.Saml2.Cryptography;
using Xunit;

public sealed class Saml2AssertionDecryptorTests
{
    private readonly Saml2AssertionDecryptor _decryptor = new();

    [Fact]
    public void DecryptAssertion_ValidEncryptedAssertion_DecryptsSuccessfully()
    {
        using var rsa = RSA.Create(2048);
        var certReq = new CertificateRequest("CN=SamlDecryptionTest", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var certWithKey = certReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddYears(1));

        var assertionXml = @"<saml:Assertion xmlns:saml=""urn:oasis:names:tc:SAML:2.0:assertion"" ID=""_decrypted_assert"" Version=""2.0"">
  <saml:Issuer>https://idp.example.com</saml:Issuer>
  <saml:Subject>
    <saml:NameID>john.doe@example.com</saml:NameID>
  </saml:Subject>
</saml:Assertion>";

        var plainDoc = new XmlDocument { XmlResolver = null };
        plainDoc.LoadXml(assertionXml);

        // Encrypt with AES-256 and wrap key with RSA
        using var aes = Aes.Create();
        aes.KeySize = 256;
        aes.GenerateKey();

        var encryptedXml = new EncryptedXml();
        var encryptedBytes = encryptedXml.EncryptData(plainDoc.DocumentElement!, aes, false);

        var encryptedData = new EncryptedData
        {
            Type = EncryptedXml.XmlEncElementUrl,
            EncryptionMethod = new EncryptionMethod(EncryptedXml.XmlEncAES256Url)
        };

        var encryptedKey = new EncryptedKey
        {
            EncryptionMethod = new EncryptionMethod(EncryptedXml.XmlEncRSA15Url),
            CipherData = new CipherData(EncryptedXml.EncryptKey(aes.Key, rsa, false))
        };
        encryptedData.KeyInfo.AddClause(new KeyInfoEncryptedKey(encryptedKey));
        encryptedData.CipherData.CipherValue = encryptedBytes;

        var envelopeDoc = new XmlDocument { XmlResolver = null };
        var encAssertionElem = envelopeDoc.CreateElement("saml", "EncryptedAssertion", "urn:oasis:names:tc:SAML:2.0:assertion");
        encAssertionElem.AppendChild(envelopeDoc.ImportNode(encryptedData.GetXml(), true));
        envelopeDoc.AppendChild(encAssertionElem);

        var result = _decryptor.DecryptAssertion(encAssertionElem, certWithKey);

        result.IsSuccess.Should().BeTrue();
        result.Value.GetAttribute("ID").Should().Be("_decrypted_assert");

        var nsMgr = new XmlNamespaceManager(result.Value.OwnerDocument!.NameTable);
        nsMgr.AddNamespace("saml", "urn:oasis:names:tc:SAML:2.0:assertion");
        result.Value.SelectSingleNode("//saml:NameID", nsMgr)!.InnerText.Should().Be("john.doe@example.com");
    }

    [Fact]
    public void DecryptAssertion_OversizedPayload_ExceedsMaxCharactersLimit_FailsWithDecryptionError()
    {
        using var rsa = RSA.Create(2048);
        var certReq = new CertificateRequest("CN=SamlDecryptionOversizedTest", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var certWithKey = certReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddYears(1));

        var padding = new string('x', 2_000_100);
        var assertionXml = $@"<saml:Assertion xmlns:saml=""urn:oasis:names:tc:SAML:2.0:assertion"" ID=""_oversized"">
  <saml:Issuer>{padding}</saml:Issuer>
</saml:Assertion>";

        var plainDoc = new XmlDocument { XmlResolver = null };
        plainDoc.LoadXml(assertionXml);

        using var aes = Aes.Create();
        aes.KeySize = 256;
        aes.GenerateKey();

        var encryptedXml = new EncryptedXml();
        var encryptedBytes = encryptedXml.EncryptData(plainDoc.DocumentElement!, aes, false);

        var encryptedData = new EncryptedData
        {
            Type = EncryptedXml.XmlEncElementUrl,
            EncryptionMethod = new EncryptionMethod(EncryptedXml.XmlEncAES256Url)
        };

        var encryptedKey = new EncryptedKey
        {
            EncryptionMethod = new EncryptionMethod(EncryptedXml.XmlEncRSA15Url),
            CipherData = new CipherData(EncryptedXml.EncryptKey(aes.Key, rsa, false))
        };
        encryptedData.KeyInfo.AddClause(new KeyInfoEncryptedKey(encryptedKey));
        encryptedData.CipherData.CipherValue = encryptedBytes;

        var envelopeDoc = new XmlDocument { XmlResolver = null };
        var encAssertionElem = envelopeDoc.CreateElement("saml", "EncryptedAssertion", "urn:oasis:names:tc:SAML:2.0:assertion");
        encAssertionElem.AppendChild(envelopeDoc.ImportNode(encryptedData.GetXml(), true));
        envelopeDoc.AppendChild(encAssertionElem);

        var result = _decryptor.DecryptAssertion(encAssertionElem, certWithKey);

        result.IsFailure.Should().BeTrue();
        result.Error.Code.Should().Be("Security.DecryptionFailed");
    }

    [Fact]
    public void DecryptAssertion_MissingEncryptedData_ReturnsInvalidToken()
    {
        using var rsa = RSA.Create(2048);
        var certReq = new CertificateRequest("CN=SamlDecryptionTest", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = certReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddYears(1));

        var doc = new XmlDocument();
        var elem = doc.CreateElement("saml", "EncryptedAssertion", "urn:oasis:names:tc:SAML:2.0:assertion");
        doc.AppendChild(elem);

        var result = _decryptor.DecryptAssertion(elem, cert);

        result.IsFailure.Should().BeTrue();
        result.Error.Description.Should().Contain("No <xenc:EncryptedData> found");
    }

    [Fact]
    public void DecryptAssertion_CertificateWithoutPrivateKey_ReturnsInvalidKey()
    {
        using var rsa = RSA.Create(2048);
        var certReq = new CertificateRequest("CN=SamlDecryptionTest", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var certWithKey = certReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddYears(1));
#if NET9_0_OR_GREATER
        var certPub = X509CertificateLoader.LoadCertificate(certWithKey.Export(X509ContentType.Cert));
#else
        var certPub = new X509Certificate2(certWithKey.Export(X509ContentType.Cert));
#endif

        var doc = new XmlDocument();
        var elem = doc.CreateElement("saml", "EncryptedAssertion", "urn:oasis:names:tc:SAML:2.0:assertion");
        doc.AppendChild(elem);

        var result = _decryptor.DecryptAssertion(elem, certPub);

        result.IsFailure.Should().BeTrue();
        result.Error.Description.Should().Contain("Decryption certificate has no private key");
    }

    [Fact]
    public void DecryptAssertion_WithRsaOaep_DecryptsSuccessfully()
    {
        using var rsa = RSA.Create(2048);
        var certReq = new CertificateRequest("CN=SamlDecryptionOaepTest", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var certWithKey = certReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddYears(1));

        var assertionXml = @"<saml:Assertion xmlns:saml=""urn:oasis:names:tc:SAML:2.0:assertion"" ID=""_oaep_assert"" Version=""2.0"">
  <saml:Issuer>https://idp.example.com</saml:Issuer>
  <saml:Subject>
    <saml:NameID>oaep.user@example.com</saml:NameID>
  </saml:Subject>
</saml:Assertion>";

        var plainDoc = new XmlDocument { XmlResolver = null };
        plainDoc.LoadXml(assertionXml);

        using var aes = Aes.Create();
        aes.KeySize = 256;
        aes.GenerateKey();

        var encryptedXml = new EncryptedXml();
        var encryptedBytes = encryptedXml.EncryptData(plainDoc.DocumentElement!, aes, false);

        var encryptedData = new EncryptedData
        {
            Type = EncryptedXml.XmlEncElementUrl,
            EncryptionMethod = new EncryptionMethod(EncryptedXml.XmlEncAES256Url)
        };

        var encryptedKey = new EncryptedKey
        {
            EncryptionMethod = new EncryptionMethod(EncryptedXml.XmlEncRSAOAEPUrl),
            CipherData = new CipherData(EncryptedXml.EncryptKey(aes.Key, rsa, true))
        };
        encryptedData.KeyInfo.AddClause(new KeyInfoEncryptedKey(encryptedKey));
        encryptedData.CipherData.CipherValue = encryptedBytes;

        var envelopeDoc = new XmlDocument { XmlResolver = null };
        var encAssertionElem = envelopeDoc.CreateElement("saml", "EncryptedAssertion", "urn:oasis:names:tc:SAML:2.0:assertion");
        encAssertionElem.AppendChild(envelopeDoc.ImportNode(encryptedData.GetXml(), true));
        envelopeDoc.AppendChild(encAssertionElem);

        var result = _decryptor.DecryptAssertion(encAssertionElem, certWithKey);

        result.IsSuccess.Should().BeTrue();
        result.Value.GetAttribute("ID").Should().Be("_oaep_assert");
    }

    [Fact]
    public void DecryptAssertion_UnresolvableKey_ReturnsDecryptionFailed()
    {
        using var rsa = RSA.Create(2048);
        var certReq = new CertificateRequest("CN=SamlDecryptionTest", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var certWithKey = certReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddYears(1));

        var encryptedData = new EncryptedData
        {
            Type = EncryptedXml.XmlEncElementUrl,
            EncryptionMethod = new EncryptionMethod(EncryptedXml.XmlEncAES256Url),
            CipherData = new CipherData(new byte[] { 1, 2, 3, 4 })
        };

        var envelopeDoc = new XmlDocument { XmlResolver = null };
        var encAssertionElem = envelopeDoc.CreateElement("saml", "EncryptedAssertion", "urn:oasis:names:tc:SAML:2.0:assertion");
        encAssertionElem.AppendChild(envelopeDoc.ImportNode(encryptedData.GetXml(), true));
        envelopeDoc.AppendChild(encAssertionElem);

        var result = _decryptor.DecryptAssertion(encAssertionElem, certWithKey);

        result.IsFailure.Should().BeTrue();
        result.Error.Description.Should().Contain("Could not resolve symmetric decryption key");
    }

    [Fact]
    public void DecryptAssertion_CorruptedCipherValue_ReturnsDecryptionFailed()
    {
        using var rsa = RSA.Create(2048);
        var certReq = new CertificateRequest("CN=SamlDecryptionTest", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var certWithKey = certReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddYears(1));

        using var aes = Aes.Create();
        aes.KeySize = 256;
        aes.GenerateKey();

        var encryptedData = new EncryptedData
        {
            Type = EncryptedXml.XmlEncElementUrl,
            EncryptionMethod = new EncryptionMethod(EncryptedXml.XmlEncAES256Url)
        };

        var encryptedKey = new EncryptedKey
        {
            EncryptionMethod = new EncryptionMethod(EncryptedXml.XmlEncRSA15Url),
            CipherData = new CipherData(EncryptedXml.EncryptKey(aes.Key, rsa, false))
        };
        encryptedData.KeyInfo.AddClause(new KeyInfoEncryptedKey(encryptedKey));
        // Random corrupted ciphertext that fails PKCS7 padding on decrypt
        encryptedData.CipherData.CipherValue = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };

        var envelopeDoc = new XmlDocument { XmlResolver = null };
        var encAssertionElem = envelopeDoc.CreateElement("saml", "EncryptedAssertion", "urn:oasis:names:tc:SAML:2.0:assertion");
        encAssertionElem.AppendChild(envelopeDoc.ImportNode(encryptedData.GetXml(), true));
        envelopeDoc.AppendChild(encAssertionElem);

        var result = _decryptor.DecryptAssertion(encAssertionElem, certWithKey);

        result.IsFailure.Should().BeTrue();
        result.Error.Description.Should().Contain("Failed to decrypt SAML assertion");
    }

    [Fact]
    public void DecryptAssertion_KeyInfoWithNonEncryptedKeyClause_Handled()
    {
        using var rsa = RSA.Create(2048);
        var certReq = new CertificateRequest("CN=SamlDecryptionTest", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var certWithKey = certReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddYears(1));

        var encryptedData = new EncryptedData
        {
            Type = EncryptedXml.XmlEncElementUrl,
            EncryptionMethod = new EncryptionMethod(EncryptedXml.XmlEncAES256Url),
            CipherData = new CipherData(new byte[] { 1, 2, 3, 4 })
        };
        encryptedData.KeyInfo.AddClause(new KeyInfoName("custom-key-name"));

        var envelopeDoc = new XmlDocument { XmlResolver = null };
        var encAssertionElem = envelopeDoc.CreateElement("saml", "EncryptedAssertion", "urn:oasis:names:tc:SAML:2.0:assertion");
        encAssertionElem.AppendChild(envelopeDoc.ImportNode(encryptedData.GetXml(), true));
        envelopeDoc.AppendChild(encAssertionElem);

        var result = _decryptor.DecryptAssertion(encAssertionElem, certWithKey);
        result.IsFailure.Should().BeTrue();
    }

    [Fact]
    public void DecryptAssertion_EncryptedKeyWithoutEncryptionMethod_DefaultsToNonOaep()
    {
        using var rsa = RSA.Create(2048);
        var certReq = new CertificateRequest("CN=SamlDecryptionTest", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var certWithKey = certReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddYears(1));

        using var aes = Aes.Create();
        aes.KeySize = 256;
        aes.GenerateKey();

        var encryptedData = new EncryptedData
        {
            Type = EncryptedXml.XmlEncElementUrl,
            EncryptionMethod = new EncryptionMethod(EncryptedXml.XmlEncAES256Url)
        };

        var encryptedKey = new EncryptedKey
        {
            CipherData = new CipherData(EncryptedXml.EncryptKey(aes.Key, rsa, false))
        };
        // EncryptionMethod is null
        encryptedData.KeyInfo.AddClause(new KeyInfoEncryptedKey(encryptedKey));

        var plainDoc = new XmlDocument { XmlResolver = null };
        plainDoc.LoadXml("<saml:Assertion xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"_test\"/>");
        var encXml = new EncryptedXml();
        encryptedData.CipherData.CipherValue = encXml.EncryptData(plainDoc.DocumentElement!, aes, false);

        var envelopeDoc = new XmlDocument { XmlResolver = null };
        var encAssertionElem = envelopeDoc.CreateElement("saml", "EncryptedAssertion", "urn:oasis:names:tc:SAML:2.0:assertion");
        encAssertionElem.AppendChild(envelopeDoc.ImportNode(encryptedData.GetXml(), true));
        envelopeDoc.AppendChild(encAssertionElem);

        var result = _decryptor.DecryptAssertion(encAssertionElem, certWithKey);
        result.IsSuccess.Should().BeTrue();
    }

    [Fact]
    public void DecryptAssertion_EncryptedKeyWithoutCipherData_Handled()
    {
        using var rsa = RSA.Create(2048);
        var certReq = new CertificateRequest("CN=SamlDecryptionTest", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var certWithKey = certReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddYears(1));

        var encryptedData = new EncryptedData
        {
            Type = EncryptedXml.XmlEncElementUrl,
            EncryptionMethod = new EncryptionMethod(EncryptedXml.XmlEncAES256Url),
            CipherData = new CipherData(new byte[] { 1, 2, 3, 4 })
        };

        var encryptedKey = new EncryptedKey
        {
            CipherData = new CipherData(new CipherReference("#ref"))
        };
        encryptedData.KeyInfo.AddClause(new KeyInfoEncryptedKey(encryptedKey));

        var envelopeDoc = new XmlDocument { XmlResolver = null };
        var encAssertionElem = envelopeDoc.CreateElement("saml", "EncryptedAssertion", "urn:oasis:names:tc:SAML:2.0:assertion");
        encAssertionElem.AppendChild(envelopeDoc.ImportNode(encryptedData.GetXml(), true));
        envelopeDoc.AppendChild(encAssertionElem);

        var result = _decryptor.DecryptAssertion(encAssertionElem, certWithKey);
        result.IsFailure.Should().BeTrue();
    }

    [Fact]
    public void DecryptAssertion_EcdsaCertificate_ReturnsInvalidKey()
    {
        using var ecdsa = ECDsa.Create();
        var certReq = new CertificateRequest("CN=SamlEcdsaDecTest", ecdsa, HashAlgorithmName.SHA256);
        using var cert = certReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddYears(1));

        var encryptedData = new EncryptedData
        {
            Type = EncryptedXml.XmlEncElementUrl,
            EncryptionMethod = new EncryptionMethod(EncryptedXml.XmlEncAES256Url),
            CipherData = new CipherData(new byte[] { 1, 2, 3, 4 })
        };
        var encryptedKey = new EncryptedKey
        {
            CipherData = new CipherData(new byte[] { 5, 6, 7, 8 })
        };
        encryptedData.KeyInfo.AddClause(new KeyInfoEncryptedKey(encryptedKey));

        var envelopeDoc = new XmlDocument { XmlResolver = null };
        var encAssertionElem = envelopeDoc.CreateElement("saml", "EncryptedAssertion", "urn:oasis:names:tc:SAML:2.0:assertion");
        encAssertionElem.AppendChild(envelopeDoc.ImportNode(encryptedData.GetXml(), true));
        envelopeDoc.AppendChild(encAssertionElem);

        var result = _decryptor.DecryptAssertion(encAssertionElem, cert);
        result.IsFailure.Should().BeTrue();
        result.Error.Description.Should().Contain("Unable to retrieve the decryption key");
    }

    [Fact]
    public void DecryptAssertion_MultipleKeyClausesFirstValid_BreaksEarlyAndPreservesWhitespace()
    {
        using var rsa = RSA.Create(2048);
        var certReq = new CertificateRequest("CN=SamlDecryptionMultiKeyTest", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var certWithKey = certReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddYears(1));

        using var aes = Aes.Create();
        aes.KeySize = 256;
        aes.GenerateKey();

        var encryptedData = new EncryptedData
        {
            Type = EncryptedXml.XmlEncElementUrl,
            EncryptionMethod = new EncryptionMethod(EncryptedXml.XmlEncAES256Url)
        };

        var validKey = new EncryptedKey
        {
            CipherData = new CipherData(EncryptedXml.EncryptKey(aes.Key, rsa, true)),
            EncryptionMethod = new EncryptionMethod(EncryptedXml.XmlEncRSAOAEPUrl)
        };
        var invalidKey = new EncryptedKey
        {
            CipherData = new CipherData(new byte[] { 99, 98, 97 }),
            EncryptionMethod = new EncryptionMethod(EncryptedXml.XmlEncRSAOAEPUrl)
        };
        encryptedData.KeyInfo.AddClause(new KeyInfoEncryptedKey(validKey));
        encryptedData.KeyInfo.AddClause(new KeyInfoEncryptedKey(invalidKey));

        var plainDoc = new XmlDocument { XmlResolver = null };
        plainDoc.LoadXml("<saml:Assertion xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"_test_multi_key\"/>");
        var encXml = new EncryptedXml();
        encryptedData.CipherData.CipherValue = encXml.EncryptData(plainDoc.DocumentElement!, aes, false);

        var envelopeDoc = new XmlDocument { XmlResolver = null };
        var encAssertionElem = envelopeDoc.CreateElement("saml", "EncryptedAssertion", "urn:oasis:names:tc:SAML:2.0:assertion");
        encAssertionElem.AppendChild(envelopeDoc.ImportNode(encryptedData.GetXml(), true));
        envelopeDoc.AppendChild(encAssertionElem);

        var result = _decryptor.DecryptAssertion(encAssertionElem, certWithKey);
        result.IsSuccess.Should().BeTrue();
        result.Value.OwnerDocument!.PreserveWhitespace.Should().BeTrue();
    }

    [Fact]
    public void DecryptAssertion_NullArguments_ThrowsArgumentNullException()
    {
        using var rsa = RSA.Create(2048);
        var certReq = new CertificateRequest("CN=SamlDecryptionTest", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = certReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddYears(1));

        var doc = new XmlDocument();
        var elem = doc.CreateElement("root");

        Assert.Throws<ArgumentNullException>(() => _decryptor.DecryptAssertion(null!, cert));
        Assert.Throws<ArgumentNullException>(() => _decryptor.DecryptAssertion(elem, null!));
    }
}
