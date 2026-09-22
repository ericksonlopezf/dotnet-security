// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Tests.Passwords;

using System;
using System.Security.Cryptography;
using System.Text;
using EricksonLopez.Security.Abstractions.Passwords;
using EricksonLopez.Security.Passwords;
using AwesomeAssertions;
using Xunit;

public sealed class PasswordHasherBoundaryMutationTests
{
    [Fact]
    public void Argon2id_HashPassword_ProducesDifferentSalts()
    {
        var hasher = new Argon2idPasswordHasher();
        var h1 = hasher.HashPassword("TestPass123!");
        var h2 = hasher.HashPassword("TestPass123!");
        h1.Should().NotBe(h2);
    }

    [Fact]
    public void Argon2id_VerifyPassword_BoundaryLengths_HandledCorrectly()
    {
        var hasher = new Argon2idPasswordHasher();

        // Password length 256 (allowed) vs 257 (rejected fast)
        var p256 = new string('A', 256);
        var p257 = new string('A', 257);
        var validHash = hasher.HashPassword("TestPass123!");

        hasher.VerifyPassword(p256, validHash).Should().Be(PasswordVerificationResult.Failed);
        hasher.VerifyPassword(p257, validHash).Should().Be(PasswordVerificationResult.Failed);

        // Hashed password length 512 vs 513
        var prefix = "$argon2id$v=19$m=65536,t=3,p=4$";
        var pad512 = prefix + new string('A', 512 - prefix.Length);
        var pad513 = prefix + new string('A', 513 - prefix.Length);

        pad512.Length.Should().Be(512);
        pad513.Length.Should().Be(513);

        hasher.VerifyPassword("password", pad512).Should().Be(PasswordVerificationResult.Failed);
        hasher.VerifyPassword("password", pad513).Should().Be(PasswordVerificationResult.Failed);
    }

    [Fact]
    public void Argon2id_VerifyPassword_MissingParameters_ReturnsFailed()
    {
        var hasher = new Argon2idPasswordHasher();

        // Missing p=
        var noP = "$argon2id$v=19$m=65536,t=3$c2FsdHNhbHQ=$aGFzaGhhc2hoYXNoMTY1";
        hasher.VerifyPassword("password", noP).Should().Be(PasswordVerificationResult.Failed);

        // Missing t=
        var noT = "$argon2id$v=19$m=65536,p=4$c2FsdHNhbHQ=$aGFzaGhhc2hoYXNoMTY1";
        hasher.VerifyPassword("password", noT).Should().Be(PasswordVerificationResult.Failed);

        // Missing m=
        var noM = "$argon2id$v=19$t=3,p=4$c2FsdHNhbHQ=$aGFzaGhhc2hoYXNoMTY1";
        hasher.VerifyPassword("password", noM).Should().Be(PasswordVerificationResult.Failed);

        // Stored iterations boundary
        var tHigh = $"$argon2id$v=19$m=65536,t={Argon2idPasswordHasher.MaxAllowedTimeCost + 1},p=4$c2FsdHNhbHQ=$aGFzaGhhc2hoYXNoMTY1";
        hasher.VerifyPassword("password", tHigh).Should().Be(PasswordVerificationResult.Failed);

        // Stored parallelism boundary
        var pHigh = $"$argon2id$v=19$m=65536,t=3,p={Argon2idPasswordHasher.MaxAllowedParallelism + 1}$c2FsdHNhbHQ=$aGFzaGhhc2hoYXNoMTY1";
        hasher.VerifyPassword("password", pHigh).Should().Be(PasswordVerificationResult.Failed);

        // Salt length boundary (< 8 chars, > 128 chars)
        var saltShort = "$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaGhhc2hoYXNoMTY1"; // 6 chars
        hasher.VerifyPassword("password", saltShort).Should().Be(PasswordVerificationResult.Failed);
        var saltLong = "$argon2id$v=19$m=65536,t=3,p=4$" + new string('A', 129) + "$aGFzaGhhc2hoYXNoMTY1";
        hasher.VerifyPassword("password", saltLong).Should().Be(PasswordVerificationResult.Failed);

        // Hash length boundary (< 16 chars, > 128 chars)
        var hashShort = "$argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHQ=$aGFzaDE1"; // 6 chars
        hasher.VerifyPassword("password", hashShort).Should().Be(PasswordVerificationResult.Failed);
        var hashLong = "$argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHQ=$" + new string('A', 129);
        hasher.VerifyPassword("password", hashLong).Should().Be(PasswordVerificationResult.Failed);
    }

    [Fact]
    public void Argon2id_NeedsRehash_MissingPOrM_ReturnsTrue()
    {
        var hasher = new Argon2idPasswordHasher(iterations: 3, memorySizeKb: 65536, parallelism: 1);
        // Hash missing p=
        var noP = "$argon2id$v=19$m=65536,t=3$c2FsdHNhbHQ=$aGFzaGhhc2hoYXNoMTY1";
        hasher.NeedsRehash(noP).Should().BeTrue();

        // Hash missing m=
        var noM = "$argon2id$v=19$t=3,p=1$c2FsdHNhbHQ=$aGFzaGhhc2hoYXNoMTY1";
        hasher.NeedsRehash(noM).Should().BeTrue();

        // Hash with wrong parts count
        hasher.NeedsRehash("invalid").Should().BeTrue();
    }

    [Fact]
    public void LegacyPbkdf2_Constructor_ValidatesSaltSize()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new LegacyPbkdf2PasswordHasher(saltSizeBytes: 7));
        Assert.Throws<ArgumentOutOfRangeException>(() => new LegacyPbkdf2PasswordHasher(saltSizeBytes: 65));
        var valid = new LegacyPbkdf2PasswordHasher(saltSizeBytes: 8);
        valid.Should().NotBeNull();
    }

    [Fact]
    public void LegacyPbkdf2_VerifyPassword_BoundaryChecks_BehaveCorrectly()
    {
        var hasher = LegacyPbkdf2PasswordHasher.Default;

        // Length 512 vs 513
        var prefix = "$legacy-pbkdf2$v=19$m=65536,t=3,p=4$";
        var pad512 = prefix + new string('A', 512 - prefix.Length);
        var pad513 = prefix + new string('A', 513 - prefix.Length);
        hasher.VerifyPassword("pass", pad512).Should().Be(PasswordVerificationResult.Failed);
        hasher.VerifyPassword("pass", pad513).Should().Be(PasswordVerificationResult.Failed);

        // Missing t= parameter
        var noT = "$legacy-pbkdf2$v=19$m=65536,p=4$c2FsdHNhbHQ=$aGFzaGhhc2hoYXNoMTY1";
        hasher.VerifyPassword("pass", noT).Should().Be(PasswordVerificationResult.Failed);

        // Out-of-bounds t
        var tHigh = $"$legacy-pbkdf2$v=19$m=65536,t={LegacyPbkdf2PasswordHasher.MaxAllowedTimeCost + 1},p=4$c2FsdHNhbHQ=$aGFzaGhhc2hoYXNoMTY1";
        hasher.VerifyPassword("pass", tHigh).Should().Be(PasswordVerificationResult.Failed);

        // Salt length string boundaries
        var saltShort = "$legacy-pbkdf2$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaGhhc2hoYXNoMTY1";
        hasher.VerifyPassword("pass", saltShort).Should().Be(PasswordVerificationResult.Failed);
        var saltLong = "$legacy-pbkdf2$v=19$m=65536,t=3,p=4$" + new string('A', 129) + "$aGFzaGhhc2hoYXNoMTY1";
        hasher.VerifyPassword("pass", saltLong).Should().Be(PasswordVerificationResult.Failed);

        // Hash length string boundaries
        var hashShort = "$legacy-pbkdf2$v=19$m=65536,t=3,p=4$c2FsdHNhbHQ=$aGFzaDE1";
        hasher.VerifyPassword("pass", hashShort).Should().Be(PasswordVerificationResult.Failed);
        var hashLong = "$legacy-pbkdf2$v=19$m=65536,t=3,p=4$c2FsdHNhbHQ=$" + new string('A', 129);
        hasher.VerifyPassword("pass", hashLong).Should().Be(PasswordVerificationResult.Failed);

        // Invalid base64 characters
        var invalidB64Salt = "$legacy-pbkdf2$v=19$m=65536,t=3,p=4$!@#$%^&*()_+=$aGFzaGhhc2hoYXNoMTY1";
        hasher.VerifyPassword("pass", invalidB64Salt).Should().Be(PasswordVerificationResult.Failed);
        var invalidB64Hash = "$legacy-pbkdf2$v=19$m=65536,t=3,p=4$c2FsdHNhbHQ=$!@#$%^&*()_+======";
        hasher.VerifyPassword("pass", invalidB64Hash).Should().Be(PasswordVerificationResult.Failed);

        // Base64 decoded salt < 8 bytes (e.g. 4 bytes base64: "AAAAAA==")
        var shortDecodedSalt = "$legacy-pbkdf2$v=19$m=65536,t=3,p=4$AAAAAA==$aGFzaGhhc2hoYXNoMTY1";
        hasher.VerifyPassword("pass", shortDecodedSalt).Should().Be(PasswordVerificationResult.Failed);

        // Base64 decoded hash < 16 bytes
        var shortDecodedHash = "$legacy-pbkdf2$v=19$m=65536,t=3,p=4$c2FsdHNhbHQ=$AAAAAA==";
        hasher.VerifyPassword("pass", shortDecodedHash).Should().Be(PasswordVerificationResult.Failed);

        // NeedsRehash with invalid parts
        hasher.NeedsRehash("invalid").Should().BeTrue();
    }

    [Fact]
    public void Pbkdf2_VerifyPassword_RehashThreshold_DistinguishesSuccessFromRehashNeeded()
    {
        var hasherLow = new Pbkdf2PasswordHasher(iterations: 100_000);
        var hashLow = hasherLow.HashPassword("TestPass123!");

        // When verified with same iterations -> Success
        hasherLow.VerifyPassword("TestPass123!", hashLow).Should().Be(PasswordVerificationResult.Success);

        // When verified with higher iterations -> SuccessRehashNeeded
        var hasherHigh = new Pbkdf2PasswordHasher(iterations: 210_000);
        hasherHigh.VerifyPassword("TestPass123!", hashLow).Should().Be(PasswordVerificationResult.SuccessRehashNeeded);

        // Exceeds max iterations
        var tooManyIters = $"$pbkdf2-sha512$i={Pbkdf2PasswordHasher.MaxStoredIterations + 1}$s=c2FsdHNhbHQ=$aGFzaGhhc2hoYXNoMTY1";
        hasherLow.VerifyPassword("TestPass123!", tooManyIters).Should().Be(PasswordVerificationResult.Failed);

        // Password length 512 vs 513
        var prefix = "$pbkdf2-sha512$i=100000$s=";
        var pad512 = prefix + new string('A', 512 - prefix.Length);
        var pad513 = prefix + new string('A', 513 - prefix.Length);
        hasherLow.VerifyPassword("pass", pad512).Should().Be(PasswordVerificationResult.Failed);
        hasherLow.VerifyPassword("pass", pad513).Should().Be(PasswordVerificationResult.Failed);

        // Salt string length boundaries for PBKDF2
        var shortSalt = "$pbkdf2-sha512$i=100000$s=c2FsdA==$aGFzaGhhc2hoYXNoMTY1"; // 8 chars salt < 13
        hasherLow.VerifyPassword("pass", shortSalt).Should().Be(PasswordVerificationResult.Failed);

        // Hash string length boundaries
        var shortHash = "$pbkdf2-sha512$i=100000$s=c2FsdHNhbHRzYWx0$aGFzaDE1"; // < 22 chars
        hasherLow.VerifyPassword("pass", shortHash).Should().Be(PasswordVerificationResult.Failed);
    }

    [Fact]
    public void CompositePasswordHasher_BoundaryAndExceptionHandling()
    {
        var primary = new Pbkdf2PasswordHasher(100_000);
        var composite = new CompositePasswordHasher(primary);

        // 512 vs 513 length boundary
        var pad512 = "$pbkdf2-sha512$" + new string('A', 512 - 15);
        var pad513 = "$pbkdf2-sha512$" + new string('A', 513 - 15);
        composite.VerifyPassword("pass", pad512).Should().Be(PasswordVerificationResult.Failed);
        composite.VerifyPassword("pass", pad513).Should().Be(PasswordVerificationResult.Failed);

        // PBKDF2.V1 boundary tests
        // Valid PBKDF2.V1 hash components:
        // salt: 16 bytes = 24 chars base64
        // hash: 32 bytes = 44 chars base64
        var saltB64 = Convert.ToBase64String(new byte[16]);
        var hashB64 = Convert.ToBase64String(new byte[32]);

        // iters < 1000 or > 600_000
        composite.VerifyPassword("pass", $"PBKDF2.V1$999${saltB64}${hashB64}").Should().Be(PasswordVerificationResult.Failed);
        composite.VerifyPassword("pass", $"PBKDF2.V1$600001${saltB64}${hashB64}").Should().Be(PasswordVerificationResult.Failed);

        // salt length < 8 chars or > 128 chars
        composite.VerifyPassword("pass", $"PBKDF2.V1$10000$c2FsdA==${hashB64}").Should().Be(PasswordVerificationResult.Failed);
        composite.VerifyPassword("pass", $"PBKDF2.V1$10000${new string('A', 129)}${hashB64}").Should().Be(PasswordVerificationResult.Failed);

        // hash length < 16 chars or > 128 chars
        composite.VerifyPassword("pass", $"PBKDF2.V1$10000${saltB64}$c2FsdA==").Should().Be(PasswordVerificationResult.Failed);
        composite.VerifyPassword("pass", $"PBKDF2.V1$10000${saltB64}${new string('A', 129)}").Should().Be(PasswordVerificationResult.Failed);

        // Invalid base64 in PBKDF2.V1 triggers catch block
        composite.VerifyPassword("pass", $"PBKDF2.V1$10000${saltB64}$invalid!base64!!").Should().Be(PasswordVerificationResult.Failed);

        // Decoded hash < 16 bytes (e.g. 4 bytes base64 = "AAAAAA==")
        var shortDecoded = Convert.ToBase64String(new byte[8]); // 8 bytes < 16
        composite.VerifyPassword("pass", $"PBKDF2.V1$10000${saltB64}${shortDecoded}").Should().Be(PasswordVerificationResult.Failed);

        // Legacy spoofed Argon2id fallback
        var legacy = LegacyPbkdf2PasswordHasher.Default;
        var legacyHash = legacy.HashPassword("secret");
        composite.VerifyPassword("secret", legacyHash).Should().Be(PasswordVerificationResult.SuccessRehashNeeded);
    }

    [Fact]
    public void Pbkdf2_VerifyPassword_Tier1Format_ReturnsSuccessOrRehashNeeded()
    {
        var hasher = new Pbkdf2PasswordHasher(iterations: 10_000);
        byte[] salt = new byte[16];
        byte[] derivedLow = Rfc2898DeriveBytes.Pbkdf2("testpass", salt, 5000, HashAlgorithmName.SHA512, 32);
        var hashLow = $"PBKDF2.V1$5000${Convert.ToBase64String(salt)}${Convert.ToBase64String(derivedLow)}";

        // 5000 < 10000 -> SuccessRehashNeeded
        hasher.VerifyPassword("testpass", hashLow).Should().Be(PasswordVerificationResult.SuccessRehashNeeded);

        byte[] derivedExact = Rfc2898DeriveBytes.Pbkdf2("testpass", salt, 10000, HashAlgorithmName.SHA512, 32);
        var hashExact = $"PBKDF2.V1$10000${Convert.ToBase64String(salt)}${Convert.ToBase64String(derivedExact)}";

        // 10000 == 10000 -> Success (kills mutant: storedIterations <= _iterations which would return SuccessRehashNeeded)
        hasher.VerifyPassword("testpass", hashExact).Should().Be(PasswordVerificationResult.Success);

        byte[] derivedHigh = Rfc2898DeriveBytes.Pbkdf2("testpass", salt, 15000, HashAlgorithmName.SHA512, 32);
        var hashHigh = $"PBKDF2.V1$15000${Convert.ToBase64String(salt)}${Convert.ToBase64String(derivedHigh)}";

        // 15000 > 10000 -> Success
        hasher.VerifyPassword("testpass", hashHigh).Should().Be(PasswordVerificationResult.Success);
    }

    [Fact]
    public void LegacyPbkdf2_NeedsRehash_MalformedParts_ReturnsTrue()
    {
        var hasher = LegacyPbkdf2PasswordHasher.Default;

        // Malformed parts count starting with $legacy-pbkdf2$
        hasher.NeedsRehash("$legacy-pbkdf2$v=19$m=65536,t=3,p=4$c2FsdA==").Should().BeTrue();
        hasher.NeedsRehash("$legacy-pbkdf2$v=19$onlytwo").Should().BeTrue();
    }
}
