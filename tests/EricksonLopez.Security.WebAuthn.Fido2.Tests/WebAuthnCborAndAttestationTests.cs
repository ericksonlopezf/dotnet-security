// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.WebAuthn.Fido2.Tests;

using System;
using System.Formats.Cbor;
using System.Text;
using System.Threading.Tasks;
using AwesomeAssertions;
using EricksonLopez.Security.WebAuthn.Fido2.Models;
using EricksonLopez.Security.WebAuthn.Fido2.Services;
using Xunit;

[Trait("Category", "Unit")]
public sealed class WebAuthnCborAndAttestationTests
{
    private readonly WebAuthnCeremonyService _service;
    private readonly WebAuthnOptions _options;

    public WebAuthnCborAndAttestationTests()
    {
        (_service, _options) = WebAuthnTestContext.CreateService();
    }

    [Fact]
    public async Task ParseAttestationObject_WithComplexAndMalformedCborPayloads_HandlesGracefully()
    {
        var challenge = new byte[32];
        var challengeB64 = Convert.ToBase64String(challenge).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var clientDataJson = Encoding.UTF8.GetBytes(
            $"{{\"type\":\"webauthn.create\",\"challenge\":\"{challengeB64}\",\"origin\":\"https://localhost:5001\"}}");

        // 1. Missing fmt
        var w1 = new CborWriter(CborConformanceMode.Lax);
        w1.WriteStartMap(1);
        w1.WriteTextString("authData");
        w1.WriteByteString(new byte[37]);
        w1.WriteEndMap();
        var res1 = await _service.VerifyRegistrationAsync(new AuthenticatorAttestationRawResponse("1", [1], clientDataJson, w1.Encode()), challenge, [1]);
        res1.IsFailure.Should().BeTrue();
        res1.Error.Description.Should().Contain("Missing 'fmt'");

        // 2. Missing authData
        var w2 = new CborWriter(CborConformanceMode.Lax);
        w2.WriteStartMap(1);
        w2.WriteTextString("fmt");
        w2.WriteTextString("none");
        w2.WriteEndMap();
        var res2 = await _service.VerifyRegistrationAsync(new AuthenticatorAttestationRawResponse("1", [1], clientDataJson, w2.Encode()), challenge, [1]);
        res2.IsFailure.Should().BeTrue();
        res2.Error.Description.Should().Contain("'authData'");

        // 3. attStmt with sig, alg, x5c, response as text, certInfo, unknown fields
        var authDataBuffer = WebAuthnTestContext.CreateAuthDataBuffer("localhost");

        var w3 = new CborWriter(CborConformanceMode.Lax);
        w3.WriteStartMap(4);
        w3.WriteTextString("fmt");
        w3.WriteTextString("none");
        w3.WriteTextString("unknown_top");
        w3.WriteInt32(12345);
        w3.WriteTextString("authData");
        w3.WriteByteString(authDataBuffer);
        w3.WriteTextString("attStmt");
        w3.WriteStartMap(6);
        w3.WriteTextString("sig");
        w3.WriteByteString([1, 2]);
        w3.WriteTextString("alg");
        w3.WriteInt64(-7);
        w3.WriteTextString("x5c");
        w3.WriteStartArray(1);
        w3.WriteByteString([0x30, 0x82]);
        w3.WriteEndArray();
        w3.WriteTextString("response");
        w3.WriteTextString("sample_jwt_response");
        w3.WriteTextString("certInfo");
        w3.WriteByteString([0xFF, 0x54, 0x43, 0x47]);
        w3.WriteTextString("unknown_stmt_key");
        w3.WriteTextString("custom_val");
        w3.WriteEndMap();
        w3.WriteEndMap();

        var res3 = await _service.VerifyRegistrationAsync(new AuthenticatorAttestationRawResponse("1", [1], clientDataJson, w3.Encode()), challenge, [1]);
        res3.IsFailure.Should().BeTrue();

        // 4. attStmt with response as byte string
        var w4 = new CborWriter(CborConformanceMode.Lax);
        w4.WriteStartMap(3);
        w4.WriteTextString("fmt");
        w4.WriteTextString("none");
        w4.WriteTextString("authData");
        w4.WriteByteString(authDataBuffer);
        w4.WriteTextString("attStmt");
        w4.WriteStartMap(1);
        w4.WriteTextString("response");
        w4.WriteByteString([1, 2, 3]);
        w4.WriteEndMap();
        w4.WriteEndMap();

        var res4 = await _service.VerifyRegistrationAsync(new AuthenticatorAttestationRawResponse("1", [1], clientDataJson, w4.Encode()), challenge, [1]);
        res4.IsSuccess.Should().BeTrue();
    }

    [Fact]
    public async Task ParseAttestationObject_InvalidAuthDataLength_ReturnsFailure()
    {
        var challenge = new byte[32];
        var challengeB64 = Convert.ToBase64String(challenge).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var clientDataJson = Encoding.UTF8.GetBytes(
            $"{{\"type\":\"webauthn.create\",\"challenge\":\"{challengeB64}\",\"origin\":\"https://localhost:5001\"}}");

        var w = new CborWriter(CborConformanceMode.Lax);
        w.WriteStartMap(3);
        w.WriteTextString("fmt");
        w.WriteTextString("none");
        w.WriteTextString("attStmt");
        w.WriteStartMap(0);
        w.WriteEndMap();
        w.WriteTextString("authData");
        w.WriteByteString(new byte[10]);
        w.WriteEndMap();

        var res = await _service.VerifyRegistrationAsync(new AuthenticatorAttestationRawResponse("1", [1], clientDataJson, w.Encode()), challenge, [1]);
        res.IsFailure.Should().BeTrue();
    }

    [Fact]
    public void ParseAttestationObject_UnknownKeysAndPayloads_ParsedCorrectly()
    {
        var authDataBuffer = WebAuthnTestContext.CreateAuthDataBuffer("localhost");

        // 1. Unknown top key and unknown stmt key with none fmt
        var w = new CborWriter(CborConformanceMode.Lax);
        w.WriteStartMap(4);
        w.WriteTextString("fmt");
        w.WriteTextString("none");
        w.WriteTextString("custom_top");
        w.WriteInt32(999);
        w.WriteTextString("authData");
        w.WriteByteString(authDataBuffer);
        w.WriteTextString("attStmt");
        w.WriteStartMap(2);
        w.WriteTextString("custom_stmt_key");
        w.WriteTextString("val");
        w.WriteTextString("certInfo");
        w.WriteByteString([0xAA, 0xBB]);
        w.WriteEndMap();
        w.WriteEndMap();

        var res = _service.ParseAttestationObject(w.Encode());
        res.IsSuccess.Should().BeTrue();
        res.Value.Statement.RawBytes.Should().Equal([0xAA, 0xBB]);

        // 2. Response as text
        var w2 = new CborWriter(CborConformanceMode.Lax);
        w2.WriteStartMap(3);
        w2.WriteTextString("fmt");
        w2.WriteTextString("none");
        w2.WriteTextString("authData");
        w2.WriteByteString(authDataBuffer);
        w2.WriteTextString("attStmt");
        w2.WriteStartMap(1);
        w2.WriteTextString("response");
        w2.WriteTextString("jwt_payload");
        w2.WriteEndMap();
        w2.WriteEndMap();

        var res2 = _service.ParseAttestationObject(w2.Encode());
        res2.IsSuccess.Should().BeTrue();
        res2.Value.Statement.RawBytes.Should().Equal(Encoding.UTF8.GetBytes("jwt_payload"));

        // 3. attStmt with x5c array of 2 certs followed by alg
        var w3 = new CborWriter(CborConformanceMode.Lax);
        w3.WriteStartMap(3);
        w3.WriteTextString("fmt");
        w3.WriteTextString("none");
        w3.WriteTextString("authData");
        w3.WriteByteString(authDataBuffer);
        w3.WriteTextString("attStmt");
        w3.WriteStartMap(2);
        w3.WriteTextString("x5c");
        w3.WriteStartArray(2);
        w3.WriteByteString([1, 2]);
        w3.WriteByteString([3, 4]);
        w3.WriteEndArray();
        w3.WriteTextString("alg");
        w3.WriteInt64(-7);
        w3.WriteEndMap();
        w3.WriteEndMap();

        var res3 = _service.ParseAttestationObject(w3.Encode());
        res3.IsSuccess.Should().BeTrue();
        res3.Value.Statement.X5c.Should().HaveCount(2);
        res3.Value.Statement.Algorithm.Should().Be(-7);
    }

    [Fact]
    public void ParseAttestationObject_WithUnknownKeysOrTruncatedAuthData_FailsGracefully()
    {
        var authDataBuffer = WebAuthnTestContext.CreateAuthDataBuffer();

        // Unknown key before alg inside attStmt
        var w = new CborWriter(CborConformanceMode.Lax);
        w.WriteStartMap(3);
        w.WriteTextString("fmt");
        w.WriteTextString("none");
        w.WriteTextString("authData");
        w.WriteByteString(authDataBuffer);
        w.WriteTextString("attStmt");
        w.WriteStartMap(2);
        w.WriteTextString("unknown_key");
        w.WriteInt32(12345);
        w.WriteTextString("alg");
        w.WriteInt64(-7);
        w.WriteEndMap();
        w.WriteEndMap();

        var res = _service.ParseAttestationObject(w.Encode());
        res.IsSuccess.Should().BeTrue();
        res.Value.Statement.Algorithm.Should().Be(-7);

        // Truncated authData in attestationObject (less than 37 bytes)
        var wTrunc = new CborWriter(CborConformanceMode.Lax);
        wTrunc.WriteStartMap(3);
        wTrunc.WriteTextString("fmt");
        wTrunc.WriteTextString("none");
        wTrunc.WriteTextString("authData");
        wTrunc.WriteByteString(new byte[] { 1, 2, 3 });
        wTrunc.WriteTextString("attStmt");
        wTrunc.WriteStartMap(0);
        wTrunc.WriteEndMap();
        wTrunc.WriteEndMap();

        var resTrunc = _service.ParseAttestationObject(wTrunc.Encode());
        resTrunc.IsFailure.Should().BeTrue();
        resTrunc.Error.Description.Should().Be("AuthenticatorData too short: expected at least 37 bytes, got 3.");
        resTrunc.Error.Description.Should().NotContain("Failed to parse attestationObject CBOR");

        // Indefinite length map with break byte
        var wIndef = new CborWriter(CborConformanceMode.Lax);
        wIndef.WriteStartMap(null);
        wIndef.WriteTextString("fmt");
        wIndef.WriteTextString("none");
        wIndef.WriteTextString("authData");
        wIndef.WriteByteString(authDataBuffer);
        wIndef.WriteTextString("attStmt");
        wIndef.WriteStartMap(0);
        wIndef.WriteEndMap();
        wIndef.WriteEndMap();
        var resIndef = _service.ParseAttestationObject(wIndef.Encode());
        resIndef.IsSuccess.Should().BeTrue();

        // Trailing data after attestationObject
        var wNormal = w.Encode();
        var bytesTrailing = new byte[wNormal.Length + 2];
        Buffer.BlockCopy(wNormal, 0, bytesTrailing, 0, wNormal.Length);
        bytesTrailing[^2] = 0x01;
        bytesTrailing[^1] = 0x02;
        var resTrailing = _service.ParseAttestationObject(bytesTrailing);
        resTrailing.IsFailure.Should().BeTrue();
        resTrailing.Error.Description.Should().Contain("Unexpected trailing data");
    }
}
