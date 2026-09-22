// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.WebAuthn.Fido2.Tests;

using System;
using System.Formats.Cbor;
using AwesomeAssertions;
using EricksonLopez.Security.WebAuthn.Fido2.Enums;
using EricksonLopez.Security.WebAuthn.Fido2.Parsers;
using Xunit;

public sealed class CoseKeyParserTests
{
    private readonly CoseKeyParser _parser = new();

    [Theory]
    [InlineData(CoseEllipticCurve.P256, CoseAlgorithmIdentifier.ES256)]
    [InlineData(CoseEllipticCurve.P384, CoseAlgorithmIdentifier.ES384)]
    [InlineData(CoseEllipticCurve.P521, CoseAlgorithmIdentifier.ES512)]
    public void Parse_ValidEc2Curves_ReturnsSuccess(CoseEllipticCurve curve, CoseAlgorithmIdentifier alg)
    {
        // Arrange
        var writer = new CborWriter(CborConformanceMode.Lax);
        writer.WriteStartMap(5);
        writer.WriteInt32(1); // kty
        writer.WriteInt32((int)CoseKeyType.Ec2);
        writer.WriteInt32(3); // alg
        writer.WriteInt32((int)alg);
        writer.WriteInt32(-1); // crv
        writer.WriteInt32((int)curve);
        writer.WriteInt32(-2); // x
        writer.WriteByteString(new byte[32]);
        writer.WriteInt32(-3); // y
        writer.WriteByteString(new byte[32]);
        writer.WriteEndMap();

        var cbor = writer.Encode();

        // Act
        var result = _parser.Parse(cbor);

        // Assert
        result.IsSuccess.Should().BeTrue();
        result.Value.KeyType.Should().Be(CoseKeyType.Ec2);
        result.Value.Algorithm.Should().Be(alg);
        result.Value.Curve.Should().Be(curve);
        result.Value.X.Should().NotBeNull();
        result.Value.Y.Should().NotBeNull();
    }

    [Theory]
    [InlineData(CoseAlgorithmIdentifier.RS256)]
    [InlineData(CoseAlgorithmIdentifier.PS256)]
    public void Parse_ValidRsaKeys_ReturnsSuccess(CoseAlgorithmIdentifier alg)
    {
        // Arrange
        var writer = new CborWriter(CborConformanceMode.Lax);
        writer.WriteStartMap(5);
        writer.WriteInt32(1); // kty
        writer.WriteInt32((int)CoseKeyType.Rsa);
        writer.WriteInt32(3); // alg
        writer.WriteInt32((int)alg);
        writer.WriteInt32(-1); // n (modulus as byte string)
        writer.WriteByteString(new byte[256]);
        writer.WriteInt32(-2); // e (exponent as byte string)
        writer.WriteByteString(new byte[] { 0x01, 0x00, 0x01 });
        writer.WriteInt32(999); // Unknown label to test skip value
        writer.WriteTextString("custom_field");
        writer.WriteEndMap();

        var cbor = writer.Encode();

        // Act
        var result = _parser.Parse(cbor);

        // Assert
        result.IsSuccess.Should().BeTrue();
        result.Value.KeyType.Should().Be(CoseKeyType.Rsa);
        result.Value.Algorithm.Should().Be(alg);
        result.Value.Modulus.Should().NotBeNull();
        result.Value.Exponent.Should().NotBeNull();
    }

    [Fact]
    public void Parse_ValidOkpKey_ReturnsSuccess()
    {
        var writer = new CborWriter(CborConformanceMode.Lax);
        writer.WriteStartMap(4);
        writer.WriteInt32(1); // kty
        writer.WriteInt32((int)CoseKeyType.Okp);
        writer.WriteInt32(3); // alg
        writer.WriteInt32((int)CoseAlgorithmIdentifier.EdDSA);
        writer.WriteInt32(-1); // crv
        writer.WriteInt32((int)CoseEllipticCurve.Ed25519);
        writer.WriteInt32(-2); // x
        writer.WriteByteString(new byte[32]);
        writer.WriteEndMap();

        var cbor = writer.Encode();
        var result = _parser.Parse(cbor);

        result.IsSuccess.Should().BeTrue();
        result.Value.KeyType.Should().Be(CoseKeyType.Okp);
        result.Value.Algorithm.Should().Be(CoseAlgorithmIdentifier.EdDSA);
        result.Value.Curve.Should().Be(CoseEllipticCurve.Ed25519);
        result.Value.X.Should().NotBeNull();
        result.Value.Y.Should().BeNull();
    }

    [Fact]
    public void Parse_MissingKty_ReturnsFailure()
    {
        var writer = new CborWriter(CborConformanceMode.Lax);
        writer.WriteStartMap(1);
        writer.WriteInt32(3); // alg only
        writer.WriteInt32((int)CoseAlgorithmIdentifier.ES256);
        writer.WriteEndMap();

        var result = _parser.Parse(writer.Encode());

        result.IsFailure.Should().BeTrue();
        result.Error.Description.Should().Contain("missing required 'kty'");
    }

    [Fact]
    public void Parse_MissingAlg_ReturnsFailure()
    {
        var writer = new CborWriter(CborConformanceMode.Lax);
        writer.WriteStartMap(1);
        writer.WriteInt32(1); // kty only
        writer.WriteInt32((int)CoseKeyType.Ec2);
        writer.WriteEndMap();

        var result = _parser.Parse(writer.Encode());

        result.IsFailure.Should().BeTrue();
        result.Error.Description.Should().Contain("missing required 'alg'");
    }

    [Fact]
    public void Parse_EmptyBytes_ReturnsFailure()
    {
        var result = _parser.Parse(ReadOnlySpan<byte>.Empty);
        result.IsFailure.Should().BeTrue();
        result.Error.Description.Should().Contain("empty");
    }

    [Fact]
    public void Parse_MalformedCbor_ReturnsFailure()
    {
        var result = _parser.Parse(new byte[] { 0xFF, 0xFF, 0xFF });
        result.IsFailure.Should().BeTrue();
    }

    [Fact]
    public void Parse_InvalidCborEncoding_ReturnsFailure()
    {
        var result = _parser.Parse(new byte[] { 0xA1, 0x01 });
        result.IsFailure.Should().BeTrue();
        result.Error.Description.Should().Contain("Invalid CBOR encoding in COSE key");
    }

    [Fact]
    public void Parse_MapWithDeclaredLengthMismatch_ReturnsFailure()
    {
        // Map of 3 pairs (0xA3), but only 2 pairs supplied: kty=2, alg=-7
        var bytes = new byte[] { 0xA3, 0x01, 0x02, 0x03, 0x26 };
        var result = _parser.Parse(bytes);
        result.IsFailure.Should().BeTrue();
        result.Error.Description.Should().Contain("Invalid CBOR encoding in COSE key");
    }

    [Fact]
    public void Parse_IndefiniteLengthMap_ConsumesBreakByte()
    {
        // 0xBF = start indefinite map, 0x01, 0x02 = kty:2, 0x03, 0x26 = alg:-7, 0xFF = break
        var bytes = new byte[] { 0xBF, 0x01, 0x02, 0x03, 0x26, 0xFF };
        var result = _parser.Parse(bytes);
        result.IsSuccess.Should().BeTrue();
        result.Value.RawBytes.Should().Equal(bytes);
    }
}
