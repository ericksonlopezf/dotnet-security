// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Abstractions.Tests;

using System;
using EricksonLopez.Security.Abstractions.Cryptography;
using EricksonLopez.Security.Abstractions.Passwords;
using EricksonLopez.Security.Abstractions.Primitives;
using Xunit;

public sealed class CryptographyAndPasswordModelTests
{
    // ==========================================
    // AeadAlgorithm Enum Tests
    // ==========================================

    [Fact]
    public void AeadAlgorithm_EnumValues_MatchExpectedIntegers()
    {
        Assert.Equal(1, (int)AeadAlgorithm.Aes256Gcm);
        Assert.Equal(2, (int)AeadAlgorithm.ChaCha20Poly1305);
        Assert.Equal(99, (int)(AeadAlgorithm)99);
    }

    // ==========================================
    // EncryptedData Struct Tests
    // ==========================================

    [Fact]
    public void EncryptedData_Properties_ReturnExactLengths()
    {
        ReadOnlyMemory<byte> ciphertext = new byte[] { 1, 2, 3, 4, 5 };
        ReadOnlyMemory<byte> tag = new byte[] { 10, 20, 30 };
        ReadOnlyMemory<byte> nonce = new byte[] { 100, 200 };

        var encrypted = new EncryptedData(ciphertext, tag, nonce);

        Assert.Equal(5, encrypted.CiphertextLength);
        Assert.Equal(3, encrypted.TagLength);
        Assert.Equal(2, encrypted.NonceLength);
        Assert.True(encrypted.Ciphertext.Span.SequenceEqual(ciphertext.Span));
        Assert.True(encrypted.Tag.Span.SequenceEqual(tag.Span));
        Assert.True(encrypted.Nonce.Span.SequenceEqual(nonce.Span));
    }

    // ==========================================
    // SecurityEnvelope Record Tests
    // ==========================================

    [Fact]
    public void SecurityEnvelope_PropertiesAndHasAssociatedData_WorkCorrectly()
    {
        var keyId = KeyIdentifier.New();
        var keyVersion = KeyVersion.Initial;
        ReadOnlyMemory<byte> nonce = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 };
        ReadOnlyMemory<byte> tag = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
        ReadOnlyMemory<byte> ciphertext = new byte[] { 10, 20, 30, 40, 50 };
        ReadOnlyMemory<byte> aad = new byte[] { 99, 88, 77 };

        var envelopeWithAad = new SecurityEnvelope(
            FormatVersion: SecurityEnvelope.CurrentFormatVersion,
            Algorithm: AeadAlgorithm.Aes256Gcm,
            KeyId: keyId,
            KeyVersion: keyVersion,
            Nonce: nonce,
            Tag: tag,
            Ciphertext: ciphertext,
            AssociatedData: aad);

        Assert.Equal(SecurityEnvelope.CurrentFormatVersion, envelopeWithAad.FormatVersion);
        Assert.Equal(AeadAlgorithm.Aes256Gcm, envelopeWithAad.Algorithm);
        Assert.Equal(keyId, envelopeWithAad.KeyId);
        Assert.Equal(keyVersion, envelopeWithAad.KeyVersion);
        Assert.Equal(5, envelopeWithAad.CiphertextLength);
        Assert.True(envelopeWithAad.HasAssociatedData);

        var envelopeWithoutAad = new SecurityEnvelope(
            FormatVersion: 1,
            Algorithm: AeadAlgorithm.ChaCha20Poly1305,
            KeyId: keyId,
            KeyVersion: keyVersion,
            Nonce: nonce,
            Tag: tag,
            Ciphertext: ciphertext);

        Assert.Equal(5, envelopeWithoutAad.CiphertextLength);
        Assert.False(envelopeWithoutAad.HasAssociatedData);
        Assert.True(envelopeWithoutAad.AssociatedData.IsEmpty);

        var cloned = envelopeWithAad with { Algorithm = (AeadAlgorithm)99 };
        Assert.Equal((AeadAlgorithm)99, cloned.Algorithm);
        Assert.NotEqual(envelopeWithAad, cloned);
        Assert.True(envelopeWithAad != cloned);
        Assert.False(envelopeWithAad == cloned);
        Assert.Equal($"SecurityEnvelope {{ KeyId = {keyId}, KeyVersion = {keyVersion}, Algorithm = Aes256Gcm, PayloadLength = 5 bytes, HasAad = True }}", envelopeWithAad.ToString());
    }

    // ==========================================
    // AuthenticatedContext Struct Tests
    // ==========================================

    [Fact]
    public void AuthenticatedContext_Empty_PropertiesAndDefaults()
    {
        var empty = AuthenticatedContext.Empty;
        Assert.True(empty.IsEmpty);
        Assert.True(empty.Span.IsEmpty);
        Assert.Equal(0, empty.GetHashCode());
        Assert.True(empty.Equals(AuthenticatedContext.Empty));
        Assert.True(empty.Equals((object)AuthenticatedContext.Empty));
        Assert.True(empty == AuthenticatedContext.Empty);
        Assert.False(empty != AuthenticatedContext.Empty);
    }

    [Fact]
    public void AuthenticatedContext_ForTenant_ValidTenant_ReturnsPrefixedBytes()
    {
        var ctx = AuthenticatedContext.ForTenant("acme-corp");
        Assert.False(ctx.IsEmpty);
        Assert.Equal("tenant:acme-corp", System.Text.Encoding.UTF8.GetString(ctx.Span));
        Assert.NotEqual(0, ctx.GetHashCode());

        var exNull = Assert.Throws<ArgumentException>("tenantId", () => AuthenticatedContext.ForTenant(null!));
        Assert.Contains("Tenant ID cannot be null or whitespace.", exNull.Message, StringComparison.Ordinal);
        var exEmpty = Assert.Throws<ArgumentException>("tenantId", () => AuthenticatedContext.ForTenant(""));
        Assert.Contains("Tenant ID cannot be null or whitespace.", exEmpty.Message, StringComparison.Ordinal);
        var exWs = Assert.Throws<ArgumentException>("tenantId", () => AuthenticatedContext.ForTenant("   "));
        Assert.Contains("Tenant ID cannot be null or whitespace.", exWs.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void AuthenticatedContext_FromBytes_SpanVariants()
    {
        var empty = AuthenticatedContext.FromBytes(ReadOnlySpan<byte>.Empty);
        Assert.True(empty.IsEmpty);

        byte[] raw = [10, 20, 30, 40];
        var ctx = AuthenticatedContext.FromBytes(raw);
        Assert.False(ctx.IsEmpty);
        Assert.True(ctx.Span.SequenceEqual(raw));
    }

    [Fact]
    public void AuthenticatedContext_Equality_AllBranchesCovered()
    {
        var empty1 = AuthenticatedContext.Empty;
        var empty2 = default(AuthenticatedContext);
        var ctx1 = AuthenticatedContext.FromBytes(new byte[] { 1, 2, 3 });
        var ctx2 = AuthenticatedContext.FromBytes(new byte[] { 1, 2, 3 });
        var ctxDiff = AuthenticatedContext.FromBytes(new byte[] { 1, 2, 4 });

        // Both empty
        Assert.True(empty1.Equals(empty2));
        Assert.True(empty1 == empty2);

        // One empty, other not
        Assert.False(empty1.Equals(ctx1));
        Assert.False(ctx1.Equals(empty1));
        Assert.False(empty1 == ctx1);
        Assert.True(empty1 != ctx1);
        Assert.False(empty1.Equals((object)ctx1));
        Assert.False(empty1.Equals("not-a-context"));
        Assert.False(empty1.Equals(null));

        // Both non-empty equal
        Assert.True(ctx1.Equals(ctx2));
        Assert.True(ctx1 == ctx2);
        Assert.False(ctx1 != ctx2);
        Assert.Equal(ctx1.GetHashCode(), ctx2.GetHashCode());

        // Both non-empty different
        Assert.False(ctx1.Equals(ctxDiff));
        Assert.False(ctx1 == ctxDiff);
        Assert.NotEqual(ctx1.GetHashCode(), ctxDiff.GetHashCode());
        Assert.NotEqual(ctx1.GetHashCode(), empty1.GetHashCode());
        Assert.True(ctx1 != ctxDiff);
    }

    // ==========================================
    // PasswordHash Struct Tests
    // ==========================================

    [Fact]
    public void PasswordHash_ConstructorsAndConversions_WorkCorrectly()
    {
        var rawHash = "$argon2id$v=19$m=65536,t=3,p=4$someSalt$someHash";
        var hash1 = new PasswordHash(rawHash);
        PasswordHash hash2 = "  " + rawHash + "  ";
        PasswordHash def = default;

        Assert.Equal(rawHash, hash1.Value);
        Assert.Equal(rawHash, hash2.Value);
        Assert.Equal(rawHash, (string)hash1);
        Assert.Equal("[REDACTED PASSWORD HASH]", hash1.ToString());
        Assert.Equal(string.Empty, def.Value);

        var exEmpty = Assert.Throws<ArgumentException>(() => new PasswordHash(""));
        Assert.Contains("Password hash string cannot be null, empty, or whitespace.", exEmpty.Message);
        Assert.Equal("value", exEmpty.ParamName);

        Assert.Throws<ArgumentException>(() => new PasswordHash("   "));
        Assert.Throws<ArgumentException>(() => new PasswordHash(null!));
    }

    // ==========================================
    // Password Hash Algorithms & Verification Enums
    // ==========================================

    [Fact]
    public void PasswordHashAlgorithm_EnumValues_MatchExpectedIntegers()
    {
        Assert.Equal(1, (int)PasswordHashAlgorithm.Pbkdf2HmacSha512);
        Assert.Equal(2, (int)PasswordHashAlgorithm.Argon2id);
    }

    [Fact]
    public void PasswordVerificationResult_EnumValues_MatchExpectedIntegers()
    {
        Assert.Equal(1, (int)PasswordVerificationResult.Success);
        Assert.Equal(2, (int)PasswordVerificationResult.SuccessRehashNeeded);
        Assert.Equal(3, (int)PasswordVerificationResult.Failed);
    }
}
