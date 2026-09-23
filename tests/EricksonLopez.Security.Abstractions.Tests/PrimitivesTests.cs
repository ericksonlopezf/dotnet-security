// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Abstractions.Tests;

using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using EricksonLopez.Security.Abstractions.Primitives;
using Xunit;

public sealed class PrimitivesTests
{
    // ==========================================
    // Redacted<T> Tests
    // ==========================================

    [Fact]
    public void Redacted_ToString_AlwaysReturnsMask()
    {
        var secretText = "super-secret-password-12345";
        var redacted = new Redacted<string>(secretText);

        Assert.Equal("[REDACTED]", redacted.ToString());
        Assert.True(redacted.HasValue);
        Assert.Equal(secretText, redacted.UnsafeValue);
    }

    [Fact]
    public void Redacted_NullValue_HandlesCorrectly()
    {
        var redacted = new Redacted<string>(null);

        Assert.Equal("[REDACTED]", redacted.ToString());
        Assert.False(redacted.HasValue);
        Assert.Null(redacted.UnsafeValue);
        Assert.Equal(0, redacted.GetHashCode());
    }

    [Fact]
    public void Redacted_Default_HandlesCorrectly()
    {
        Redacted<string> redacted = default;

        Assert.Equal("[REDACTED]", redacted.ToString());
        Assert.False(redacted.HasValue);
        Assert.Null(redacted.UnsafeValue);
        Assert.Equal(0, redacted.GetHashCode());
    }

    [Fact]
    public void GetHashCode_ValueTypeWithZeroOrNull_ReturnsConsistentHash()
    {
        Redacted<int> rInt0 = new(0);
        Assert.True(rInt0.HasValue);
        Assert.Equal(EqualityComparer<int>.Default.GetHashCode(0), rInt0.GetHashCode());

        Redacted<int?> rNullableNull = new((int?)null);
        Assert.False(rNullableNull.HasValue);
        Assert.Equal(0, rNullableNull.GetHashCode());

        Redacted<int?> rNullableVal = new((int?)42);
        Assert.True(rNullableVal.HasValue);
        Assert.Equal(EqualityComparer<int?>.Default.GetHashCode(42), rNullableVal.GetHashCode());

        Redacted<DateTime> defaultDateTimeRedacted = default;
        Assert.False(defaultDateTimeRedacted.HasValue);
        Assert.Equal(0, defaultDateTimeRedacted.GetHashCode());

        Redacted<Guid> defaultGuidRedacted = default;
        Assert.False(defaultGuidRedacted.HasValue);
        Assert.Equal(0, defaultGuidRedacted.GetHashCode());

        Redacted<StructWithNonZeroDefaultHash> defaultNonZero = default;
        Assert.False(defaultNonZero.HasValue);
        Assert.Equal(0, defaultNonZero.GetHashCode());
    }

    private readonly struct StructWithNonZeroDefaultHash
    {
        public override int GetHashCode() => 1234567;
    }

    [Fact]
    public void Redacted_ImplicitConversion_WrapsValue()
    {
        Redacted<string> redacted = "secret-token";

        Assert.True(redacted.HasValue);
        Assert.Equal("secret-token", redacted.UnsafeValue);

        Redacted<string> nullRedacted = (string?)null;
        Assert.False(nullRedacted.HasValue);
    }

    [Fact]
    public void Redacted_Equality_AllBranchesCovered()
    {
        var r1 = new Redacted<string>("password123");
        var r2 = new Redacted<string>("password123");
        var r3 = new Redacted<string>("otherPassword");
        var rNull1 = new Redacted<string>(null);
        var rNull2 = new Redacted<string>(null);

        // Both have value, equal
        Assert.True(r1.Equals(r2));
        Assert.True(r1 == r2);
        Assert.False(r1 != r2);
        Assert.True(r1.Equals((object)r2));
        Assert.Equal(r1.GetHashCode(), r2.GetHashCode());

        // Both have value, unequal
        Assert.False(r1.Equals(r3));
        Assert.False(r1 == r3);
        Assert.True(r1 != r3);
        Assert.False(r1.Equals((object)r3));
        Assert.NotEqual(r1.GetHashCode(), r3.GetHashCode());

        // Both null (no value)
        Assert.True(rNull1.Equals(rNull2));
        Assert.True(rNull1 == rNull2);
        Assert.False(rNull1 != rNull2);
        Assert.True(rNull1.Equals((object)rNull2));
        Assert.Equal(0, rNull1.GetHashCode());

        // One has value, one null
        Assert.False(r1.Equals(rNull1));
        Assert.False(r1 == rNull1);
        Assert.True(r1 != rNull1);
        Assert.False(rNull1.Equals(r1));
        Assert.False(rNull1 == r1);
        Assert.True(rNull1 != r1);

        // Object equality with invalid types and null
        Assert.False(r1.Equals((object?)null));
        Assert.False(r1.Equals("not-a-redacted"));
        Assert.False(r1.Equals(42));

        // Byte array equality (FixedTimeEquals path vs reference/default equality)
        byte[] bytes1 = [1, 2, 3];
        byte[] bytes2 = [1, 2, 3];
        byte[] bytes3 = [1, 2, 4];
        var rBytes1 = new Redacted<byte[]>(bytes1);
        var rBytes2 = new Redacted<byte[]>(bytes2);
        var rBytes3 = new Redacted<byte[]>(bytes3);

        Assert.True(rBytes1.Equals(rBytes2));
        Assert.True(rBytes1 == rBytes2);
        Assert.False(rBytes1 != rBytes2);
        Assert.False(rBytes1.Equals(rBytes3));
        Assert.False(rBytes1 == rBytes3);
        Assert.True(rBytes1 != rBytes3);
    }

    // ==========================================
    // CryptographicKey Tests
    // ==========================================

    [Fact]
    public void CryptographicKey_ConstructAndProperties_WorkAsExpected()
    {
        var metadata = new KeyMetadata(
            KeyId: KeyIdentifier.New(),
            Version: KeyVersion.Initial,
            Purpose: KeyPurpose.Encryption,
            Status: KeyStatus.Active,
            AlgorithmId: "AES-256-GCM",
            CreatedAtUtc: DateTimeOffset.UtcNow);

        byte[] keyBytes = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        using var buffer = new FakeSecretBuffer(keyBytes);
        using var key = new CryptographicKey(metadata, buffer);

        Assert.Same(metadata, key.Metadata);
        Assert.Equal(16, key.KeyLengthInBytes);
        Assert.False(key.IsDisposed);
        Assert.True(key.GetKeyBytes().SequenceEqual(keyBytes));
        Assert.Contains(metadata.KeyId.Value, key.ToString());
        Assert.Contains(metadata.Purpose.ToString(), key.ToString());
    }

    [Fact]
    public void CryptographicKey_NullArguments_ThrowArgumentNullException()
    {
        var metadata = new KeyMetadata(
            KeyId: KeyIdentifier.New(),
            Version: KeyVersion.Initial,
            Purpose: KeyPurpose.Encryption,
            Status: KeyStatus.Active,
            AlgorithmId: "AES-256-GCM",
            CreatedAtUtc: DateTimeOffset.UtcNow);

        using var buffer = new FakeSecretBuffer([1, 2, 3, 4]);

        Assert.Throws<ArgumentNullException>("metadata", () => new CryptographicKey(null!, buffer));
        Assert.Throws<ArgumentNullException>("keyMaterial", () => new CryptographicKey(metadata, null!));
    }

    [Fact]
    public void CryptographicKey_TryCopyKeyBytes_HandlesSuccessAndInsufficientLength()
    {
        var metadata = new KeyMetadata(
            KeyId: KeyIdentifier.New(),
            Version: KeyVersion.Initial,
            Purpose: KeyPurpose.Encryption,
            Status: KeyStatus.Active,
            AlgorithmId: "AES-256-GCM",
            CreatedAtUtc: DateTimeOffset.UtcNow);

        byte[] keyBytes = [10, 20, 30, 40];
        using var buffer = new FakeSecretBuffer(keyBytes);
        using var key = new CryptographicKey(metadata, buffer);

        // Insufficient destination span
        Span<byte> tooSmall = stackalloc byte[3];
        Assert.False(key.TryCopyKeyBytes(tooSmall));

        // Exact destination span
        Span<byte> exact = stackalloc byte[4];
        Assert.True(key.TryCopyKeyBytes(exact));
        Assert.True(exact.SequenceEqual(keyBytes));

        // Larger destination span
        Span<byte> larger = stackalloc byte[8];
        Assert.True(key.TryCopyKeyBytes(larger));
        Assert.True(larger[..4].SequenceEqual(keyBytes));
    }

    [Fact]
    public void CryptographicKey_Dispose_ScrubsAndThrowsOnSubsequentAccess()
    {
        var metadata = new KeyMetadata(
            KeyId: KeyIdentifier.New(),
            Version: KeyVersion.Initial,
            Purpose: KeyPurpose.Encryption,
            Status: KeyStatus.Active,
            AlgorithmId: "AES-256-GCM",
            CreatedAtUtc: DateTimeOffset.UtcNow);

        var buffer = new FakeSecretBuffer([1, 2, 3, 4]) { ThrowOnAccessAfterDispose = false };
        var key = new CryptographicKey(metadata, buffer);

        Assert.False(key.IsDisposed);
        key.Dispose();
        Assert.True(key.IsDisposed);
        Assert.True(buffer.IsDisposed);
        Assert.Equal(1, buffer.DisposeCount);

        // Idempotent dispose — must not call buffer.Dispose() again
        key.Dispose();
        Assert.True(key.IsDisposed);
        Assert.Equal(1, buffer.DisposeCount);

        // CryptographicKey itself must throw ObjectDisposedException even if buffer does not
        var ex1 = Assert.Throws<ObjectDisposedException>(() => key.GetKeyBytes());
        Assert.Equal(typeof(CryptographicKey).FullName, ex1.ObjectName);

        byte[] destination = new byte[4];
        var ex2 = Assert.Throws<ObjectDisposedException>(() => key.TryCopyKeyBytes(destination));
        Assert.Equal(typeof(CryptographicKey).FullName, ex2.ObjectName);
    }

    // ==========================================
    // KeyIdentifier Tests
    // ==========================================

    [Fact]
    public void KeyIdentifier_New_GeneratesUniqueIdentifiers()
    {
        var id1 = KeyIdentifier.New();
        var id2 = KeyIdentifier.New();

        Assert.False(string.IsNullOrWhiteSpace(id1.Value));
        Assert.False(string.IsNullOrWhiteSpace(id2.Value));
        Assert.NotEqual(id1, id2);
        Assert.Equal(32, id1.Value.Length);
        Assert.Matches("^[0-9a-f]{32}$", id1.Value);
    }

    [Fact]
    public void KeyIdentifier_Prefixed_IncludesPrefixAndTrimsHyphens()
    {
        var id1 = KeyIdentifier.Prefixed("enc");
        var id2 = KeyIdentifier.Prefixed("enc-");
        var id3 = KeyIdentifier.Prefixed("  key-store-  ");

        Assert.StartsWith("enc-", id1.Value, StringComparison.Ordinal);
        Assert.StartsWith("enc-", id2.Value, StringComparison.Ordinal);
        Assert.StartsWith("key-store-", id3.Value, StringComparison.Ordinal);

        var exEmpty = Assert.Throws<ArgumentException>(() => KeyIdentifier.Prefixed(""));
        Assert.Equal("prefix", exEmpty.ParamName);
        Assert.Throws<ArgumentException>(() => KeyIdentifier.Prefixed("   "));
        Assert.Throws<ArgumentNullException>(() => KeyIdentifier.Prefixed(null!));
    }

    [Fact]
    public void KeyIdentifier_EmptyValue_ThrowsArgumentException()
    {
        var ex = Assert.Throws<ArgumentException>(() => new KeyIdentifier(""));
        Assert.Contains("Key identifier cannot be null, empty, or whitespace.", ex.Message);
        Assert.Equal("value", ex.ParamName);

        Assert.Throws<ArgumentException>(() => new KeyIdentifier("   "));
        Assert.Throws<ArgumentException>(() => new KeyIdentifier(null!));
    }

    [Fact]
    public void KeyIdentifier_TryCreate_ValidatesCorrectly()
    {
        Assert.True(KeyIdentifier.TryCreate("valid-id-123", out var id1));
        Assert.Equal("valid-id-123", id1.Value);

        Assert.False(KeyIdentifier.TryCreate("", out var idEmpty));
        Assert.Equal(default, idEmpty);

        Assert.False(KeyIdentifier.TryCreate("   ", out var idWs));
        Assert.Equal(default, idWs);

        Assert.False(KeyIdentifier.TryCreate(null, out var idNull));
        Assert.Equal(default, idNull);
    }

    [Fact]
    public void KeyIdentifier_ComparisonsAndOperators_WorkCorrectly()
    {
        KeyIdentifier a = "alpha";
        KeyIdentifier b = "beta";
        KeyIdentifier aSame = new("alpha");
        KeyIdentifier aSameCase = new("ALPHA");
        KeyIdentifier def = default;

        Assert.Equal("alpha", (string)a);
        Assert.Equal("alpha", a.ToString());
        Assert.Equal(string.Empty, def.ToString());

        Assert.True(a.CompareTo(b) < 0);
        Assert.True(b.CompareTo(a) > 0);
        Assert.Equal(0, a.CompareTo(aSameCase));

        // Inequality comparisons
        Assert.True(a < b);
        Assert.True(a <= b);
        Assert.True(a <= aSame);
        Assert.False(a > b);
        Assert.False(a >= b);
        Assert.True(b > a);
        Assert.True(b >= a);
        Assert.True(aSameCase >= a);

        // Equal comparison: < and > must be false for equal items
        Assert.False(a < aSame);
        Assert.False(a > aSame);
        Assert.True(a <= aSame);
        Assert.True(a >= aSame);
    }

    // ==========================================
    // KeyVersion Tests
    // ==========================================

    [Fact]
    public void KeyVersion_Initial_IsOne()
    {
        Assert.Equal(1, KeyVersion.Initial.Value);
        Assert.Equal("v1", KeyVersion.Initial.ToString());
    }

    [Fact]
    public void KeyVersion_Next_IncrementsValue()
    {
        var v1 = KeyVersion.Initial;
        var v2 = v1.Next();
        var v3 = v2.Next();

        Assert.Equal(2, v2.Value);
        Assert.Equal(3, v3.Value);
        Assert.Equal("v2", v2.ToString());
        Assert.Equal("v3", v3.ToString());
    }

    [Fact]
    public void KeyVersion_InvalidValue_ThrowsArgumentOutOfRangeException()
    {
        var ex = Assert.Throws<ArgumentOutOfRangeException>(() => new KeyVersion(0));
        Assert.Contains("Key version must be a positive integer greater than or equal to 1.", ex.Message);
        Assert.Equal("value", ex.ParamName);

        Assert.Throws<ArgumentOutOfRangeException>(() => new KeyVersion(-1));
        Assert.Throws<ArgumentOutOfRangeException>(() => new KeyVersion(int.MinValue));
    }

    [Fact]
    public void KeyVersion_ImplicitConversionsAndOperators_WorkCorrectly()
    {
        KeyVersion v1 = 1;
        KeyVersion v2 = 2;
        KeyVersion v1Copy = new(1);
        int intVal = v2;

        Assert.Equal(2, intVal);
        Assert.Equal(1, v1.Value);
        Assert.Equal(0, v1.CompareTo(new KeyVersion(1)));
        Assert.True(v1.CompareTo(v2) < 0);
        Assert.True(v2.CompareTo(v1) > 0);

        Assert.True(v1 < v2);
        Assert.True(v1 <= v2);
        Assert.True(v1 <= v1Copy);
        Assert.False(v1 > v2);
        Assert.False(v1 >= v2);
        Assert.True(v2 > v1);
        Assert.True(v2 >= v1);
        Assert.True(v2 >= new KeyVersion(2));

        // When equal: < and > must be false
        Assert.False(v1 < v1Copy);
        Assert.False(v1 > v1Copy);
        Assert.True(v1 <= v1Copy);
        Assert.True(v1 >= v1Copy);
    }

    // ==========================================
    // Fingerprint Tests
    // ==========================================

    [Fact]
    public void Fingerprint_Constructors_And_Factories_WorkCorrectly()
    {
        var rawString = "test-input-string";
        var expectedHashHex = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(rawString)));

        var fp1 = new Fingerprint("   " + expectedHashHex.ToLowerInvariant() + "   ");
        Assert.Equal(expectedHashHex, fp1.HexValue);
        Assert.Equal(expectedHashHex, fp1.ToString());

        var fp2 = Fingerprint.FromUtf8String(rawString);
        Assert.Equal(expectedHashHex, fp2.HexValue);

        var fp3 = Fingerprint.FromBytes(Encoding.UTF8.GetBytes(rawString));
        Assert.Equal(expectedHashHex, fp3.HexValue);

        var exEmpty = Assert.Throws<ArgumentException>(() => new Fingerprint(""));
        Assert.Contains("Fingerprint hex value cannot be null, empty, or whitespace.", exEmpty.Message);
        Assert.Equal("hexValue", exEmpty.ParamName);

        Assert.Throws<ArgumentException>(() => new Fingerprint("   "));
        Assert.Throws<ArgumentException>(() => new Fingerprint(null!));
        var exNull = Assert.Throws<ArgumentNullException>(() => Fingerprint.FromUtf8String(null!));
        Assert.Equal("input", exNull.ParamName);

        Fingerprint def = default;
        Assert.Equal(string.Empty, def.ToString());
    }

    [Fact]
    public void Fingerprint_ComparisonsAndOperators_WorkCorrectly()
    {
        var fpA = Fingerprint.FromUtf8String("AAA");
        var fpB = Fingerprint.FromUtf8String("BBB");
        var fpSame = Fingerprint.FromUtf8String("AAA");

        Assert.True(fpA.CompareTo(fpSame) == 0);

        if (fpA.CompareTo(fpB) < 0)
        {
            Assert.True(fpA < fpB);
            Assert.True(fpA <= fpB);
            Assert.False(fpA > fpB);
            Assert.False(fpA >= fpB);
        }
        else
        {
            Assert.True(fpA > fpB);
            Assert.True(fpA >= fpB);
            Assert.False(fpA < fpB);
            Assert.False(fpA <= fpB);
        }

        // When equal: < and > must be false
        Assert.False(fpA < fpSame);
        Assert.False(fpA > fpSame);
        Assert.True(fpA <= fpSame);
        Assert.True(fpA >= fpSame);
    }

    // ==========================================
    // Nonce Tests
    // ==========================================

    [Fact]
    public void Nonce_Constructors_And_Properties_WorkCorrectly()
    {
        byte[] raw = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        var nonce1 = new Nonce(raw);
        var nonce2 = new Nonce(raw.AsSpan());

        Assert.Equal(12, nonce1.Length);
        Assert.Equal(12, nonce2.Length);
        Assert.True(nonce1.Span.SequenceEqual(raw));
        Assert.True(nonce2.Memory.Span.SequenceEqual(raw));
        Assert.Contains(Convert.ToHexString(raw), nonce1.ToString());

        Span<byte> destination = stackalloc byte[12];
        nonce1.CopyTo(destination);
        Assert.True(destination.SequenceEqual(raw));

        // Array isolation
        raw[0] = 99;
        Assert.Equal(1, nonce1.Span[0]);

        // Exceptions
        var exNull = Assert.Throws<ArgumentNullException>(() => new Nonce((byte[])null!));
        Assert.Equal("bytes", exNull.ParamName);

        var exEmpty = Assert.Throws<ArgumentException>(() => new Nonce((byte[])Array.Empty<byte>()));
        Assert.Contains("Nonce bytes cannot be empty.", exEmpty.Message);
        Assert.Equal("bytes", exEmpty.ParamName);

        var exSpan = Assert.Throws<ArgumentException>(() => new Nonce(ReadOnlySpan<byte>.Empty));
        Assert.Contains("Nonce span cannot be empty.", exSpan.Message);
        Assert.Equal("span", exSpan.ParamName);
    }

    [Fact]
    public void Nonce_DefaultStruct_HandlesSafely()
    {
        Nonce def = default;
        Assert.Equal(0, def.Length);
        Assert.True(def.Span.IsEmpty);
        Assert.Equal(0, def.Span.Length);
        Assert.True(def.Memory.IsEmpty);
        Assert.Equal(0, def.Memory.Length);
        Assert.Equal(0, def.GetHashCode());
        Assert.Equal("Nonce(0 bytes: )", def.ToString());
    }

    [Fact]
    public void EqualsAndGetHashCode_VariousNonceInstances_DistinguishesEqualAndUnequalInstances()
    {
        byte[] b1 = [1, 2, 3, 4];
        byte[] b2 = [1, 2, 3, 4];
        byte[] b3 = [1, 2, 3, 5];

        var n1 = new Nonce(b1);
        var n2 = new Nonce(b2);
        var n3 = new Nonce(b3);
        Nonce def1 = default;
        Nonce def2 = default;

        Assert.True(n1.Equals(n2));
        Assert.True(n1 == n2);
        Assert.False(n1 != n2);
        Assert.True(n1.Equals((object)n2));
        Assert.Equal(n1.GetHashCode(), n2.GetHashCode());

        Assert.False(n1.Equals(n3));
        Assert.False(n1 == n3);
        Assert.True(n1 != n3);
        Assert.False(n1.Equals((object)n3));
        Assert.NotEqual(n1.GetHashCode(), n3.GetHashCode());

        Assert.False(n1.Equals((object?)null));
        Assert.False(n1.Equals("not-a-nonce"));

        Assert.True(def1.Equals(def2));
        Assert.True(def1 == def2);
        Assert.False(def1.Equals(n1));
    }

    // ==========================================
    // Salt Tests
    // ==========================================

    [Fact]
    public void Salt_Constructors_And_Properties_WorkCorrectly()
    {
        byte[] raw = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100, 110, 120, 130, 140, 150, 160];
        var salt1 = new Salt(raw);
        var salt2 = new Salt(raw.AsSpan());

        Assert.Equal(16, salt1.Length);
        Assert.Equal(16, salt2.Length);
        Assert.True(salt1.Span.SequenceEqual(raw));
        Assert.True(salt2.Memory.Span.SequenceEqual(raw));
        Assert.Equal("Salt(16 bytes)", salt1.ToString());

        Span<byte> destination = stackalloc byte[16];
        salt1.CopyTo(destination);
        Assert.True(destination.SequenceEqual(raw));

        // Array isolation
        raw[0] = 99;
        Assert.Equal(10, salt1.Span[0]);

        // Exceptions
        var exNull = Assert.Throws<ArgumentNullException>(() => new Salt((byte[])null!));
        Assert.Equal("bytes", exNull.ParamName);

        var exEmpty = Assert.Throws<ArgumentException>(() => new Salt((byte[])Array.Empty<byte>()));
        Assert.Contains("Salt bytes cannot be empty.", exEmpty.Message);
        Assert.Equal("bytes", exEmpty.ParamName);

        var exSpan = Assert.Throws<ArgumentException>(() => new Salt(ReadOnlySpan<byte>.Empty));
        Assert.Contains("Salt span cannot be empty.", exSpan.Message);
        Assert.Equal("span", exSpan.ParamName);
    }

    [Fact]
    public void Salt_DefaultStruct_HandlesSafely()
    {
        Salt def = default;
        Assert.Equal(0, def.Length);
        Assert.True(def.Span.IsEmpty);
        Assert.Equal(0, def.Span.Length);
        Assert.True(def.Memory.IsEmpty);
        Assert.Equal(0, def.Memory.Length);
        Assert.Equal(0, def.GetHashCode());
        Assert.Equal("Salt(0 bytes)", def.ToString());
    }

    [Fact]
    public void EqualsAndGetHashCode_VariousSaltInstances_DistinguishesEqualAndUnequalInstances()
    {
        byte[] b1 = [1, 2, 3, 4];
        byte[] b2 = [1, 2, 3, 4];
        byte[] b3 = [1, 2, 3, 9];

        var s1 = new Salt(b1);
        var s2 = new Salt(b2);
        var s3 = new Salt(b3);
        Salt def1 = default;
        Salt def2 = default;

        Assert.True(s1.Equals(s2));
        Assert.True(s1 == s2);
        Assert.False(s1 != s2);
        Assert.True(s1.Equals((object)s2));
        Assert.Equal(s1.GetHashCode(), s2.GetHashCode());

        Assert.False(s1.Equals(s3));
        Assert.False(s1 == s3);
        Assert.True(s1 != s3);
        Assert.False(s1.Equals((object)s3));
        Assert.NotEqual(s1.GetHashCode(), s3.GetHashCode());

        Assert.False(s1.Equals((object?)null));
        Assert.False(s1.Equals(123));

        Assert.True(def1.Equals(def2));
        Assert.True(def1 == def2);
        Assert.False(def1.Equals(s1));
    }

    // ==========================================
    // SecurityStamp Tests
    // ==========================================

    [Fact]
    public void SecurityStamp_Constructors_And_TryCreate_WorkCorrectly()
    {
        var stamp1 = SecurityStamp.New();
        Assert.False(string.IsNullOrWhiteSpace(stamp1.Value));
        Assert.Equal(stamp1.Value, (string)stamp1);
        Assert.Equal(stamp1.Value, stamp1.ToString());
        Assert.Matches("^[0-9a-f]{32}$", stamp1.Value);

        SecurityStamp stamp2 = "custom-stamp-123";
        Assert.Equal("custom-stamp-123", stamp2.Value);

        Assert.True(SecurityStamp.TryCreate("valid-stamp", out var stamp3));
        Assert.Equal("valid-stamp", stamp3.Value);

        Assert.False(SecurityStamp.TryCreate("", out var sEmpty));
        Assert.Equal(default, sEmpty);
        Assert.False(SecurityStamp.TryCreate("   ", out var sWs));
        Assert.Equal(default, sWs);
        Assert.False(SecurityStamp.TryCreate(null, out var sNull));
        Assert.Equal(default, sNull);

        var ex = Assert.Throws<ArgumentException>(() => new SecurityStamp(""));
        Assert.Contains("Security stamp cannot be null, empty, or whitespace.", ex.Message);
        Assert.Equal("value", ex.ParamName);

        Assert.Throws<ArgumentException>(() => new SecurityStamp("   "));
        Assert.Throws<ArgumentException>(() => new SecurityStamp(null!));

        SecurityStamp def = default;
        Assert.Equal(string.Empty, def.ToString());
    }

    // ==========================================
    // ApiKeyId Tests
    // ==========================================

    [Fact]
    public void ApiKeyId_New_And_Comparisons_WorkCorrectly()
    {
        var id1 = ApiKeyId.New();
        var id2 = ApiKeyId.New();
        ApiKeyId a = "api_key_alpha";
        ApiKeyId b = "api_key_beta";
        ApiKeyId aCopy = new("api_key_alpha");
        ApiKeyId bCopy = new("api_key_beta");
        ApiKeyId def = default;

        Assert.False(string.IsNullOrWhiteSpace(id1.Value));
        Assert.Matches("^[0-9a-f]{32}$", id1.Value);
        Assert.Equal(a.Value, (string)a);
        Assert.Equal(a.Value, a.ToString());
        Assert.Equal(string.Empty, def.ToString());

        Assert.True(a.CompareTo(b) < 0);
        Assert.True(b.CompareTo(a) > 0);

        Assert.True(a < b);
        Assert.True(a <= b);
        Assert.True(a <= aCopy);
        Assert.False(a > b);
        Assert.False(a >= b);
        Assert.True(b > a);
        Assert.True(b >= a);
        Assert.True(b >= bCopy);

        // Equal comparison: < and > must be false
        Assert.False(a < aCopy);
        Assert.False(a > aCopy);
        Assert.True(a <= aCopy);
        Assert.True(a >= aCopy);

        var ex = Assert.Throws<ArgumentException>(() => new ApiKeyId(""));
        Assert.Contains("API key ID cannot be null, empty, or whitespace.", ex.Message);
        Assert.Equal("value", ex.ParamName);

        Assert.Throws<ArgumentException>(() => new ApiKeyId("   "));
        Assert.Throws<ArgumentException>(() => new ApiKeyId(null!));
    }

    // ==========================================
    // ApiKey Entity Tests
    // ==========================================

    [Fact]
    public void ApiKey_IsActive_And_Scopes_CoverAllBranches()
    {
        var keyId = ApiKeyId.New();
        var now = DateTimeOffset.UtcNow;

        var activeKeyWithNoExpiration = new ApiKey(
            Id: keyId,
            OwnerId: "user-123",
            Name: "No Expiration Key",
            DisplayPrefix: "ek_live_***",
            HashedSecret: "hashed-secret",
            CreatedAtUtc: now.AddDays(-10),
            ExpiresAtUtc: null);

        var activeKeyWithFutureExpiration = activeKeyWithNoExpiration with
        {
            ExpiresAtUtc = now.AddDays(10)
        };

        var expiredKey = activeKeyWithNoExpiration with
        {
            ExpiresAtUtc = now.AddDays(-1)
        };

        // Exact boundary: ExpiresAtUtc == now -> must be expired (false)
        var exactExpiredKey = activeKeyWithNoExpiration with
        {
            ExpiresAtUtc = now
        };

        var revokedKey = activeKeyWithNoExpiration with
        {
            RevokedAtUtc = now.AddDays(-1)
        };

        var revokedAndExpiredKey = activeKeyWithNoExpiration with
        {
            RevokedAtUtc = now.AddDays(-1),
            ExpiresAtUtc = now.AddDays(-5)
        };

        Assert.False(activeKeyWithNoExpiration.IsRevoked);
        Assert.True(activeKeyWithNoExpiration.IsActive(now));
        Assert.True(activeKeyWithNoExpiration.IsActive(null)); // nowUtc = null default branch

        Assert.False(activeKeyWithFutureExpiration.IsRevoked);
        Assert.True(activeKeyWithFutureExpiration.IsActive(now));
        Assert.True(activeKeyWithFutureExpiration.IsActive(now.AddDays(5)));
        Assert.False(activeKeyWithFutureExpiration.IsActive(now.AddDays(50))); // Far future overrides current time

        Assert.False(expiredKey.IsRevoked);
        Assert.False(expiredKey.IsActive(now));

        // Exact expiration boundary test
        Assert.False(exactExpiredKey.IsActive(now));

        Assert.True(revokedKey.IsRevoked);
        Assert.False(revokedKey.IsActive(now));

        Assert.True(revokedAndExpiredKey.IsRevoked);
        Assert.False(revokedAndExpiredKey.IsActive(now));

        // Test active key with null nowUtc and past/future expiration
        var pastKeyRealClock = activeKeyWithNoExpiration with { ExpiresAtUtc = DateTimeOffset.UtcNow.AddMinutes(-5) };
        Assert.False(pastKeyRealClock.IsActive(null));

        var futureKeyRealClock = activeKeyWithNoExpiration with { ExpiresAtUtc = DateTimeOffset.UtcNow.AddHours(1) };
        Assert.True(futureKeyRealClock.IsActive(null));

        // HasScope branches
        var keyWithoutScopes = activeKeyWithNoExpiration;
        var keyWithEmptyScopes = activeKeyWithNoExpiration with { Scopes = new HashSet<string>() };
        var keyWithPopulatedScopes = activeKeyWithNoExpiration with { Scopes = new HashSet<string> { "read", "write" } };

        Assert.False(keyWithoutScopes.HasScope("read"));
        Assert.False(keyWithEmptyScopes.HasScope("read"));
        Assert.True(keyWithPopulatedScopes.HasScope("read"));
        Assert.True(keyWithPopulatedScopes.HasScope("write"));
        Assert.False(keyWithPopulatedScopes.HasScope("delete"));
    }

    // ==========================================
    // OpaqueToken Tests
    // ==========================================

    [Fact]
    public void ConstructorsAndProperties_ValidTokenString_InitializesAndComputesEqualityCorrectly()
    {
        var rawToken = "opq_9f8a7b6c5d4e3f2a1b0c";
        var token1 = new OpaqueToken(rawToken);
        var token2 = new OpaqueToken(rawToken);
        var token3 = new OpaqueToken("opq_different_token");
        OpaqueToken def = default;

        Assert.Equal(rawToken, token1.Value);
        Assert.Equal(rawToken.Length, token1.Length);
        Assert.False(token1.IsEmpty);
        Assert.Equal("[REDACTED TOKEN]", token1.ToString());

        Assert.Equal(string.Empty, def.Value);
        Assert.Equal(0, def.Length);
        Assert.True(def.IsEmpty);
        Assert.Equal(0, def.GetHashCode());

        Assert.True(token1.Equals(token2));
        Assert.True(token1 == token2);
        Assert.False(token1 != token2);
        Assert.Equal(token1.GetHashCode(), token2.GetHashCode());
        Assert.Equal(string.GetHashCode(rawToken, StringComparison.Ordinal), token1.GetHashCode());

        Assert.False(token1.Equals(token3));
        Assert.False(token1 == token3);
        Assert.True(token1 != token3);

        Assert.False(token1.Equals(def));
        Assert.True(def.Equals(default));

        var ex = Assert.Throws<ArgumentException>(() => new OpaqueToken(""));
        Assert.Contains("Token value cannot be null, empty, or whitespace.", ex.Message);
        Assert.Equal("value", ex.ParamName);

        Assert.Throws<ArgumentException>(() => new OpaqueToken("   "));
        Assert.Throws<ArgumentException>(() => new OpaqueToken(null!));
    }

    // ==========================================
    // KeyMetadata Tests
    // ==========================================

    [Fact]
    public void KeyMetadata_LifecycleState_And_Usability_CoverAllBranches()
    {
        var now = DateTimeOffset.UtcNow;
        var keyId = KeyIdentifier.New();

        var activeKeyNoExp = new KeyMetadata(
            KeyId: keyId,
            Version: KeyVersion.Initial,
            Purpose: KeyPurpose.Encryption,
            Status: KeyStatus.Active,
            AlgorithmId: "AES-256-GCM",
            CreatedAtUtc: now.AddDays(-10),
            ExpiresAtUtc: null);

        var activeKeyFutureExp = activeKeyNoExp with { ExpiresAtUtc = now.AddDays(30) };
        var activeKeyExpired = activeKeyNoExp with { ExpiresAtUtc = now.AddDays(-1) };
        var activeKeyExactNow = activeKeyNoExp with { ExpiresAtUtc = now };

        var retiredKey = activeKeyNoExp with { Status = KeyStatus.Retired };
        var revokedKey = activeKeyNoExp with { Status = KeyStatus.Revoked, RevokedAtUtc = now };
        var destroyedKey = activeKeyNoExp with { Status = KeyStatus.Destroyed };

        // IsUsableForNewOperations
        Assert.True(activeKeyNoExp.IsUsableForNewOperations(now));
        Assert.True(activeKeyNoExp.IsUsableForNewOperations(null)); // nowUtc = null default
        Assert.True(activeKeyFutureExp.IsUsableForNewOperations(now));
        Assert.True(activeKeyFutureExp.IsUsableForNewOperations(now.AddDays(5)));
        Assert.False(activeKeyFutureExp.IsUsableForNewOperations(now.AddDays(50))); // Far future overrides current time
        Assert.False(activeKeyExpired.IsUsableForNewOperations(now));
        Assert.False(activeKeyExactNow.IsUsableForNewOperations(now)); // Exact boundary
        Assert.False(retiredKey.IsUsableForNewOperations(now));
        Assert.False(revokedKey.IsUsableForNewOperations(now));
        Assert.False(destroyedKey.IsUsableForNewOperations(now));

        // Test with null nowUtc against real clock
        var expiredRealClock = activeKeyNoExp with { ExpiresAtUtc = DateTimeOffset.UtcNow.AddMinutes(-10) };
        Assert.False(expiredRealClock.IsUsableForNewOperations(null));

        var futureRealClock = activeKeyNoExp with { ExpiresAtUtc = DateTimeOffset.UtcNow.AddHours(2) };
        Assert.True(futureRealClock.IsUsableForNewOperations(null));

        // IsUsableForDecryption
        Assert.True(activeKeyNoExp.IsUsableForDecryption());
        Assert.True(retiredKey.IsUsableForDecryption());
        Assert.False(revokedKey.IsUsableForDecryption());
        Assert.False(destroyedKey.IsUsableForDecryption());
    }

    // ==========================================
    // Enum Members Verification
    // ==========================================

    [Fact]
    public void KeyPurpose_EnumValues_MatchExpectedIntegers()
    {
        Assert.Equal(1, (int)KeyPurpose.Encryption);
        Assert.Equal(2, (int)KeyPurpose.Signing);
        Assert.Equal(3, (int)KeyPurpose.Hashing);
        Assert.Equal(4, (int)KeyPurpose.TokenProtection);
        Assert.Equal(5, (int)KeyPurpose.SecretProtection);
        Assert.Equal(6, (int)KeyPurpose.KeyWrapping);
    }

    [Fact]
    public void KeyStatus_EnumValues_MatchExpectedIntegers()
    {
        Assert.Equal(1, (int)KeyStatus.Active);
        Assert.Equal(2, (int)KeyStatus.Retired);
        Assert.Equal(3, (int)KeyStatus.Revoked);
        Assert.Equal(4, (int)KeyStatus.Destroyed);
    }
}
