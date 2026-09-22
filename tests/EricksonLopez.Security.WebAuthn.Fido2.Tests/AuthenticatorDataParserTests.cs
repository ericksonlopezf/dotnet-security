// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.WebAuthn.Fido2.Tests;

using System;
using System.Buffers.Binary;
using System.Formats.Cbor;
using AwesomeAssertions;
using EricksonLopez.Security.WebAuthn.Fido2.Enums;
using EricksonLopez.Security.WebAuthn.Fido2.Parsers;
using Xunit;

public sealed class AuthenticatorDataParserTests
{
    private readonly AuthenticatorDataParser _parser = new(new CoseKeyParser());

    [Fact]
    public void Constructor_NullParser_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => new AuthenticatorDataParser(null!));
    }

    [Fact]
    public void Parse_LessThan37Bytes_ReturnsFailure()
    {
        var shortBuffer = new byte[36];
        var result = _parser.Parse(shortBuffer);

        result.IsFailure.Should().BeTrue();
        result.Error.Description.Should().Contain("expected at least 37 bytes");
    }

    [Fact]
    public void Parse_MinimalAuthData_ReturnsSuccess()
    {
        // Arrange: 32 bytes rpIdHash + 1 byte flags (UP | UV) + 4 bytes signCount
        var buffer = new byte[37];
        var rpIdHash = new byte[32];
        Array.Fill(rpIdHash, (byte)0xAA);
        Buffer.BlockCopy(rpIdHash, 0, buffer, 0, 32);

        buffer[32] = (byte)(AuthenticatorDataFlags.UserPresent | AuthenticatorDataFlags.UserVerified);
        BinaryPrimitives.WriteUInt32BigEndian(buffer.AsSpan(33, 4), 42);

        // Act
        var result = _parser.Parse(buffer);

        // Assert
        result.IsSuccess.Should().BeTrue();
        var authData = result.Value;
        authData.RpIdHash.Should().Equal(rpIdHash);
        authData.UserPresent.Should().BeTrue();
        authData.UserVerified.Should().BeTrue();
        authData.BackupEligibility.Should().BeFalse();
        authData.BackupState.Should().BeFalse();
        authData.SignCount.Should().Be(42u);
        authData.AttestedCredentialData.Should().BeNull();
        authData.ExtensionData.Should().BeNull();
    }

    [Fact]
    public void Parse_WithAttestedCredentialData_ReturnsSuccess()
    {
        // 1. Build COSE Key
        var writer = new CborWriter(CborConformanceMode.Lax);
        writer.WriteStartMap(5);
        writer.WriteInt32(1);
        writer.WriteInt32((int)CoseKeyType.Ec2);
        writer.WriteInt32(3);
        writer.WriteInt32((int)CoseAlgorithmIdentifier.ES256);
        writer.WriteInt32(-1);
        writer.WriteInt32((int)CoseEllipticCurve.P256);
        writer.WriteInt32(-2);
        writer.WriteByteString(new byte[32]);
        writer.WriteInt32(-3);
        writer.WriteByteString(new byte[32]);
        writer.WriteEndMap();
        var coseBytes = writer.Encode();

        // 2. Build full AuthData
        var credId = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05 };
        var totalLength = 37 + 16 + 2 + credId.Length + coseBytes.Length;
        var buffer = new byte[totalLength];

        // RpIdHash
        Array.Fill(buffer, (byte)0xBB, 0, 32);
        // Flags: UP + AT + BE + BS
        buffer[32] = (byte)(AuthenticatorDataFlags.UserPresent | AuthenticatorDataFlags.AttestedCredentialData | AuthenticatorDataFlags.BackupEligibility | AuthenticatorDataFlags.BackupState);
        // SignCount
        BinaryPrimitives.WriteUInt32BigEndian(buffer.AsSpan(33, 4), 100);

        // AAGUID (16 bytes)
        var aaguid = Guid.NewGuid();
        Buffer.BlockCopy(aaguid.ToByteArray(bigEndian: true), 0, buffer, 37, 16);

        // CredIdLen
        BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(53, 2), (ushort)credId.Length);
        // CredId
        Buffer.BlockCopy(credId, 0, buffer, 55, credId.Length);
        // CoseKey
        Buffer.BlockCopy(coseBytes, 0, buffer, 55 + credId.Length, coseBytes.Length);

        // Act
        var result = _parser.Parse(buffer);

        // Assert
        result.IsSuccess.Should().BeTrue();
        var authData = result.Value;
        authData.UserPresent.Should().BeTrue();
        authData.BackupEligibility.Should().BeTrue();
        authData.BackupState.Should().BeTrue();
        authData.AttestedCredentialData.Should().NotBeNull();
        authData.AttestedCredentialData!.Aaguid.Should().Be(aaguid);
        authData.AttestedCredentialData.CredentialId.Should().Equal(credId);
        authData.AttestedCredentialData.PublicKey.KeyType.Should().Be(CoseKeyType.Ec2);
    }

    [Fact]
    public void Parse_AttestedFlagWithoutEnoughBytesForAaguid_ReturnsFailure()
    {
        var buffer = new byte[40]; // 37 header + 3 bytes (less than 18 needed)
        buffer[32] = (byte)AuthenticatorDataFlags.AttestedCredentialData;

        var result = _parser.Parse(buffer);

        result.IsFailure.Should().BeTrue();
        result.Error.Description.Should().Contain("truncated before AAGUID");
    }

    [Fact]
    public void Parse_AttestedFlagWithTruncatedCredId_ReturnsFailure()
    {
        var buffer = new byte[37 + 16 + 2 + 5]; // specifies credId length 10 but only has 5 bytes
        buffer[32] = (byte)AuthenticatorDataFlags.AttestedCredentialData;
        BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(53, 2), 10);

        var result = _parser.Parse(buffer);

        result.IsFailure.Should().BeTrue();
        result.Error.Description.Should().Contain("expected 10 bytes for CredentialId");
    }

    [Fact]
    public void Parse_AttestedFlagWithCorruptCoseKey_ReturnsFailure()
    {
        var credId = new byte[] { 1, 2, 3 };
        var corruptCose = new byte[] { 0xFF, 0xFF };
        var buffer = new byte[37 + 16 + 2 + credId.Length + corruptCose.Length];
        buffer[32] = (byte)AuthenticatorDataFlags.AttestedCredentialData;
        BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(53, 2), (ushort)credId.Length);
        Buffer.BlockCopy(credId, 0, buffer, 55, credId.Length);
        Buffer.BlockCopy(corruptCose, 0, buffer, 55 + credId.Length, corruptCose.Length);

        var result = _parser.Parse(buffer);

        result.IsFailure.Should().BeTrue();
    }

    [Fact]
    public void Parse_WithExtensionDataFlag_ParsesExtensionBytes()
    {
        var buffer = new byte[37 + 10];
        buffer[32] = (byte)(AuthenticatorDataFlags.UserPresent | AuthenticatorDataFlags.ExtensionData);
        Array.Fill(buffer, (byte)0xEE, 37, 10);

        var result = _parser.Parse(buffer);

        result.IsSuccess.Should().BeTrue();
        result.Value.ExtensionData.Should().NotBeNull();
        result.Value.ExtensionData!.Length.Should().Be(10);
    }

    [Fact]
    public void Parse_WithExtensionDataFlag_NoRemainingBytes_ExtensionDataIsNull()
    {
        var buffer = new byte[37];
        buffer[32] = (byte)(AuthenticatorDataFlags.UserPresent | AuthenticatorDataFlags.ExtensionData);

        var result = _parser.Parse(buffer);

        result.IsSuccess.Should().BeTrue();
        result.Value.ExtensionData.Should().BeNull();
    }

    [Fact]
    public void Parse_LengthBoundaryAndBothAtAndEdFlags_ParsesCorrectly()
    {
        // 1. Length exactly 55 (offset 37 + 18) with credIdLength = 10
        var b55 = new byte[55];
        b55[32] = (byte)(AuthenticatorDataFlags.UserPresent | AuthenticatorDataFlags.AttestedCredentialData);
        BinaryPrimitives.WriteUInt16BigEndian(b55.AsSpan(53, 2), 10);
        var res55 = _parser.Parse(b55);
        res55.IsFailure.Should().BeTrue();
        res55.Error.Description.Should().Contain("expected 10 bytes for CredentialId");

        // 2. Length exactly 55 + 10 = 65 with credIdLength = 10, but 0 bytes for COSE key
        var b65 = new byte[65];
        b65[32] = (byte)(AuthenticatorDataFlags.UserPresent | AuthenticatorDataFlags.AttestedCredentialData);
        BinaryPrimitives.WriteUInt16BigEndian(b65.AsSpan(53, 2), 10);
        var res65 = _parser.Parse(b65);
        res65.IsFailure.Should().BeTrue();
        res65.Error.Description.Should().NotContain("expected 10 bytes for CredentialId");

        // 3. Both AT and ED flags with valid COSE key and 5 extension bytes
        var writer = new CborWriter(CborConformanceMode.Lax);
        writer.WriteStartMap(2);
        writer.WriteInt32(1);
        writer.WriteInt32((int)CoseKeyType.Ec2);
        writer.WriteInt32(3);
        writer.WriteInt32((int)CoseAlgorithmIdentifier.ES256);
        writer.WriteEndMap();
        var coseBytes = writer.Encode();

        var credId = new byte[] { 0x01, 0x02 };
        var extBytes = new byte[] { 0xAA, 0xBB, 0xCC, 0xDD, 0xEE };
        var totalLen = 37 + 16 + 2 + credId.Length + coseBytes.Length + extBytes.Length;
        var fullBuf = new byte[totalLen];
        fullBuf[32] = (byte)(AuthenticatorDataFlags.UserPresent | AuthenticatorDataFlags.AttestedCredentialData | AuthenticatorDataFlags.ExtensionData);
        BinaryPrimitives.WriteUInt16BigEndian(fullBuf.AsSpan(53, 2), (ushort)credId.Length);
        Buffer.BlockCopy(credId, 0, fullBuf, 55, credId.Length);
        Buffer.BlockCopy(coseBytes, 0, fullBuf, 55 + credId.Length, coseBytes.Length);
        Buffer.BlockCopy(extBytes, 0, fullBuf, 55 + credId.Length + coseBytes.Length, extBytes.Length);

        var fullRes = _parser.Parse(fullBuf);
        fullRes.IsSuccess.Should().BeTrue();
        fullRes.Value.AttestedCredentialData!.RawBytes.Length.Should().Be(18 + credId.Length + coseBytes.Length);
        fullRes.Value.ExtensionData.Should().Equal(extBytes);
    }
}
