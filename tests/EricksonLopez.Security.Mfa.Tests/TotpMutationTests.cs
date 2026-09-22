// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Mfa.Tests;

using System;
using System.Collections.Concurrent;
using AwesomeAssertions;
using Microsoft.Extensions.Time.Testing;
using Xunit;

public sealed class TotpMutationTests
{
    private const string Secret = "JBSWY3DPEHPK3PXP";

    [Fact]
    public void VerifyCode_ReplayWithinSameTimeStepAtDifferentSeconds_IsBlocked()
    {
        // Kills Mutant (stepTime.ToUnixTimeSeconds() / opt.PeriodSeconds) -> (*)
        var fakeTime = new FakeTimeProvider(new DateTimeOffset(2050, 8, 30, 12, 0, 0, TimeSpan.Zero));
        var service = new TotpService(fakeTime);
        var options = new TotpOptions
        {
            PeriodSeconds = 30,
            AllowedDriftSteps = 0,
            PreventReplay = true
        };

        var code = service.ComputeCode(Secret, fakeTime.GetUtcNow(), options);

        // Verify at t = 0
        service.VerifyCode(Secret, code, fakeTime.GetUtcNow(), options).Should().BeTrue();

        // Advance by 1 second (still inside the same 30-second step)
        fakeTime.Advance(TimeSpan.FromSeconds(1));

        // Replaying same code at t = 1s MUST be blocked because stepIndex is identical
        var replayed = service.VerifyCode(Secret, code, fakeTime.GetUtcNow(), options);
        replayed.Should().BeFalse("same TOTP code must not be reusable within the same 30-second time step");
    }

    [Fact]
    public void VerifyCode_ReplayExpiryCalculation_PreservesReplayBlockingUntilExpiry()
    {
        // Kills Mutants:
        // Expiry = checkTime.AddSeconds((opt.AllowedDriftSteps + 2) * opt.PeriodSeconds)
        // With AllowedDriftSteps = 1 and PeriodSeconds = 30, Expiry delta = (1 + 2) * 30 = 90s.
        var fakeTime = new FakeTimeProvider(new DateTimeOffset(2050, 8, 30, 12, 0, 0, TimeSpan.Zero));
        var service = new TotpService(fakeTime);
        var options = new TotpOptions
        {
            PeriodSeconds = 30,
            AllowedDriftSteps = 1,
            PreventReplay = true
        };

        var initialTime = fakeTime.GetUtcNow();
        var code = service.ComputeCode(Secret, initialTime, options);

        // 1. First verification succeeds
        service.VerifyCode(Secret, code, initialTime, options).Should().BeTrue();

        // 2. Inspect recorded expiry directly via internal accessor
        service.ConsumedCodes.Should().NotBeEmpty();

        foreach (var expiry in service.ConsumedCodes.Values)
        {
            // The exact expiry must be initialTime + 90 seconds.
            // Mutant computes (1 + 2) / 30 = 0s or (1 - 2) * 30 = -30s.
            var expectedExpiry = initialTime.AddSeconds((1 + 2) * 30);
            expiry.Should().Be(expectedExpiry, "expiry must match (AllowedDriftSteps + 2) * PeriodSeconds exactly");
        }
    }

    [Fact]
    public void VerifyCode_AutomaticPruningThreshold_TriggersWhenCountExceeds1000()
    {
        // Kills Mutants: (_consumedCodes.Count >= 1000) and (!(_consumedCodes.Count > 1000))
        var fakeTime = new FakeTimeProvider(new DateTimeOffset(2050, 8, 30, 12, 0, 0, TimeSpan.Zero));
        var service = new TotpService(fakeTime);
        var options = new TotpOptions
        {
            PeriodSeconds = 30,
            AllowedDriftSteps = 0,
            PreventReplay = true
        };

        // Populate 1000 expired entries directly
        var expiredTime = fakeTime.GetUtcNow().AddSeconds(-100);
        for (int i = 0; i < 1000; i++)
        {
            service.ConsumedCodes[$"expired-key-{i}"] = expiredTime;
        }

        service.ConsumedCodesCount.Should().Be(1000);

        // Before adding the 1001st key via VerifyCode, make sure rate-limiting check allows prune
        fakeTime.Advance(TimeSpan.FromSeconds(2));

        // When code #1001 is verified, Count becomes 1001 > 1000, which triggers PruneExpiredCodes
        var code = service.ComputeCode(Secret, fakeTime.GetUtcNow(), options);
        var verified = service.VerifyCode(Secret, code, fakeTime.GetUtcNow(), options);
        verified.Should().BeTrue();

        // All 1000 expired keys should now have been pruned, leaving only the newly added valid key!
        service.ConsumedCodesCount.Should().Be(1, "all 1000 expired codes must be pruned once count exceeds 1000");
    }

    [Fact]
    public void VerifyCode_AutomaticPruningThreshold_DoesNotTriggerWhenCountEqualsThreshold()
    {
        // Kills Mutant: (_consumedCodes.Count >= RoutinePruneThreshold)
        var fakeTime = new FakeTimeProvider(new DateTimeOffset(2050, 8, 30, 12, 0, 0, TimeSpan.Zero));
        var service = new TotpService(fakeTime);
        var options = new TotpOptions
        {
            PeriodSeconds = 30,
            AllowedDriftSteps = 0,
            PreventReplay = true
        };

        // Populate 999 expired entries directly
        var expiredTime = fakeTime.GetUtcNow().AddSeconds(-100);
        for (int i = 0; i < 999; i++)
        {
            service.ConsumedCodes[$"expired-key-{i}"] = expiredTime;
        }

        fakeTime.Advance(TimeSpan.FromSeconds(2));

        // When code #1000 is verified, Count becomes exactly 1000 == RoutinePruneThreshold (1000).
        // Since 1000 > 1000 is FALSE, PruneExpiredCodes must NOT be triggered yet!
        var code = service.ComputeCode(Secret, fakeTime.GetUtcNow(), options);
        var verified = service.VerifyCode(Secret, code, fakeTime.GetUtcNow(), options);
        verified.Should().BeTrue();

        // Expired keys must still be present because count does not exceed 1000
        service.ConsumedCodesCount.Should().Be(1000, "pruning must NOT trigger when count is exactly equal to threshold");
    }

    [Fact]
    public void VerifyCode_PruningRateLimiting_BypassesThrottleWhenAtMaxCapacity()
    {
        // Kills Mutant: (_consumedCodes.Count <= MaxConsumedCodesCapacity) vs (<)
        var fakeTime = new FakeTimeProvider(new DateTimeOffset(2050, 8, 30, 12, 0, 0, TimeSpan.Zero));
        var service = new TotpService(fakeTime)
        {
            MaxConsumedCodesCapacity = 10,
            RoutinePruneThreshold = 5
        };
        var options = new TotpOptions
        {
            PeriodSeconds = 30,
            AllowedDriftSteps = 0,
            PreventReplay = true
        };

        var expiredTime = fakeTime.GetUtcNow().AddSeconds(-100);

        // Step 1: establish _lastPruneTicks with initial prune
        for (int i = 0; i < 6; i++)
        {
            service.ConsumedCodes[$"init-exp-{i}"] = expiredTime;
        }
        fakeTime.Advance(TimeSpan.FromSeconds(2));
        var code1 = service.ComputeCode(Secret, fakeTime.GetUtcNow(), options);
        service.VerifyCode(Secret, code1, fakeTime.GetUtcNow(), options).Should().BeTrue();
        service.ConsumedCodesCount.Should().Be(1);

        // Step 2: add 8 expired entries so count is 9. Next addition reaches 10 == MaxConsumedCodesCapacity
        for (int i = 0; i < 8; i++)
        {
            service.ConsumedCodes[$"exp-at-cap-{i}"] = expiredTime;
        }
        service.ConsumedCodesCount.Should().Be(9);

        // Advance by only 100ms (< 1s throttle)
        fakeTime.Advance(TimeSpan.FromMilliseconds(100));

        const string distinctSecret = "HXDMVJECJJWSRB3H";
        var code2 = service.ComputeCode(distinctSecret, fakeTime.GetUtcNow(), options);
        // Adding 10th code reaches exactly MaxConsumedCodesCapacity (10).
        // Since Count < Max (10 < 10) is FALSE, throttle is bypassed and pruning runs!
        service.VerifyCode(distinctSecret, code2, fakeTime.GetUtcNow(), options).Should().BeTrue();

        // Expired items pruned! Only the 2 active codes remain
        service.ConsumedCodesCount.Should().Be(2, "throttle must be bypassed when count equals MaxConsumedCodesCapacity");
    }

    [Fact]
    public void VerifyCode_PruningRateLimiting_ThrottlesUnderOneSecondUnlessMaxCapacity()
    {
        // Kills Mutants:
        // nowTicks - lastTicks < TimeSpan.FromSeconds(1).Ticks && _consumedCodes.Count < MaxConsumedCodesCapacity
        var fakeTime = new FakeTimeProvider(new DateTimeOffset(2050, 8, 30, 12, 0, 0, TimeSpan.Zero));
        var service = new TotpService(fakeTime);
        var options = new TotpOptions
        {
            PeriodSeconds = 30,
            AllowedDriftSteps = 0,
            PreventReplay = true
        };

        // Initial verification establishes _lastPruneTicks when count > 1000
        var expiredTime = fakeTime.GetUtcNow().AddSeconds(-100);
        for (int i = 0; i < 1005; i++)
        {
            service.ConsumedCodes[$"exp-{i}"] = expiredTime;
        }

        // Trigger first prune
        fakeTime.Advance(TimeSpan.FromSeconds(2));
        var code1 = service.ComputeCode(Secret, fakeTime.GetUtcNow(), options);
        service.VerifyCode(Secret, code1, fakeTime.GetUtcNow(), options).Should().BeTrue();
        service.ConsumedCodesCount.Should().Be(1);

        // Add 1005 expired entries again
        for (int i = 0; i < 1005; i++)
        {
            service.ConsumedCodes[$"exp2-{i}"] = expiredTime;
        }

        // Advance by only 200 ms (< 1 second threshold)
        fakeTime.Advance(TimeSpan.FromMilliseconds(200));

        // Use a distinct secret so it is not rejected as a replay of code1
        const string secret2 = "HXDMVJECJJWSRB3H";
        var tNow = fakeTime.GetUtcNow();
        var code3 = service.ComputeCode(secret2, tNow, options);
        service.VerifyCode(secret2, code3, tNow, options).Should().BeTrue();

        // Expired entries were NOT cleared yet due to rate-limiting throttling
        service.ConsumedCodes.ContainsKey("exp2-0").Should().BeTrue("throttling must prevent full dictionary scan within 1 second");

        // Advance past 1 second (1500 ms) and verify: pruning runs and clears
        fakeTime.Advance(TimeSpan.FromMilliseconds(1500));
        const string secret3 = "GEZDGNBVGY3TQOJQ";
        var tAfter = fakeTime.GetUtcNow();
        var code4 = service.ComputeCode(secret3, tAfter, options);
        service.VerifyCode(secret3, code4, tAfter, options).Should().BeTrue();
        // Expired entries should now be cleared
        service.ConsumedCodes.ContainsKey("exp2-0").Should().BeFalse();
    }

    [Fact]
    public void VerifyCode_Pruning_PreservesBoundaryAndFutureEntries()
    {
        // Kills Mutants: kvp.Value < now (mutated to <=, >, !( < ))
        var fakeTime = new FakeTimeProvider(new DateTimeOffset(2050, 8, 30, 12, 0, 0, TimeSpan.Zero));
        var service = new TotpService(fakeTime);
        var options = new TotpOptions
        {
            PeriodSeconds = 30,
            AllowedDriftSteps = 0,
            PreventReplay = true
        };

        var now = fakeTime.GetUtcNow();

        // 1. Strictly expired (< now)
        service.ConsumedCodes["strictly-expired"] = now.AddSeconds(-1);
        // 2. Exactly boundary (== now) - per RFC and (kvp.Value < now), must NOT be pruned yet!
        service.ConsumedCodes["boundary-now"] = now;
        // 3. Strictly future (> now)
        service.ConsumedCodes["future-valid"] = now.AddSeconds(30);

        // Fill remaining up to 1002 to trigger pruning
        for (int i = 0; i < 1000; i++)
        {
            service.ConsumedCodes[$"fill-{i}"] = now.AddSeconds(-50);
        }

        fakeTime.Advance(TimeSpan.FromSeconds(2));
        var checkTime = fakeTime.GetUtcNow();

        // Reset boundary to checkTime so that kvp.Value == checkTime
        service.ConsumedCodes["boundary-now"] = checkTime;
        service.ConsumedCodes["future-valid"] = checkTime.AddSeconds(30);

        var code = service.ComputeCode(Secret, checkTime, options);
        service.VerifyCode(Secret, code, checkTime, options).Should().BeTrue();

        // strictly-expired and fill-* were < checkTime -> PRUNED
        service.ConsumedCodes.ContainsKey("strictly-expired").Should().BeFalse();
        service.ConsumedCodes.ContainsKey("fill-0").Should().BeFalse();

        // boundary-now (== checkTime) must NOT be pruned by (kvp.Value < now)
        service.ConsumedCodes.ContainsKey("boundary-now").Should().BeTrue("entries at exact boundary (kvp.Value == now) must not be pruned");

        // future-valid (> checkTime) must NOT be pruned
        service.ConsumedCodes.ContainsKey("future-valid").Should().BeTrue("future entries must remain active in replay cache");
    }

    [Fact]
    public void VerifyCode_MaxCapacity_WithExpiredEntries_PrunesAndSucceeds()
    {
        // Tests VerifyCode lines 195-204 when _consumedCodes.Count >= MaxConsumedCodesCapacity
        // but entries are expired, so PruneExpiredCodes successfully reduces count
        var fakeTime = new FakeTimeProvider(new DateTimeOffset(2050, 8, 30, 12, 0, 0, TimeSpan.Zero));
        var service = new TotpService(fakeTime);
        var options = new TotpOptions
        {
            PeriodSeconds = 30,
            AllowedDriftSteps = 0,
            PreventReplay = true
        };

        // Populate 50,000 expired entries
        var expiredTime = fakeTime.GetUtcNow().AddSeconds(-100);
        for (int i = 0; i < TotpService.MaxCapacity; i++)
        {
            service.ConsumedCodes[$"key-{i}"] = expiredTime;
        }

        service.ConsumedCodesCount.Should().Be(TotpService.MaxCapacity);

        // Verification must trigger PruneExpiredCodes, clear expired items, and succeed
        var code = service.ComputeCode(Secret, fakeTime.GetUtcNow(), options);
        var result = service.VerifyCode(Secret, code, fakeTime.GetUtcNow(), options);
        result.Should().BeTrue("pruning must clear expired entries and allow valid authentication");
        service.ConsumedCodesCount.Should().Be(1);
    }

    [Fact]
    public void VerifyCode_MaxCapacityExceeded_AllActive_FailsClosed()
    {
        // Tests fail-closed behavior when cache is saturated with active tokens
        var fakeTime = new FakeTimeProvider(new DateTimeOffset(2050, 8, 30, 12, 0, 0, TimeSpan.Zero));
        var service = new TotpService(fakeTime);
        var options = new TotpOptions
        {
            PeriodSeconds = 30,
            AllowedDriftSteps = 0,
            PreventReplay = true
        };

        // Fill up to MaxConsumedCodesCapacity (50_000) with non-expired future timestamps
        var futureTime = fakeTime.GetUtcNow().AddDays(1);
        for (int i = 0; i < TotpService.MaxCapacity; i++)
        {
            service.ConsumedCodes[$"key-{i}"] = futureTime;
        }

        service.ConsumedCodesCount.Should().Be(TotpService.MaxCapacity);

        // Now attempt to verify when all 50,000 keys are non-expired
        // Since capacity is saturated and none can be expired, it must fail-closed (return false)
        var code = service.ComputeCode(Secret, fakeTime.GetUtcNow(), options);
        var result = service.VerifyCode(Secret, code, fakeTime.GetUtcNow(), options);
        result.Should().BeFalse("when replay cache is saturated and cannot prune, verification must fail-closed");
    }

    [Fact]
    public void VerifyCode_CapacityBoundary_AtMaxMinusOne_Succeeds()
    {
        // Tests the boundary condition: 49,999 entries (MaxCapacity - 1)
        var fakeTime = new FakeTimeProvider(new DateTimeOffset(2050, 8, 30, 12, 0, 0, TimeSpan.Zero));
        var service = new TotpService(fakeTime);
        var options = new TotpOptions
        {
            PeriodSeconds = 30,
            AllowedDriftSteps = 0,
            PreventReplay = true
        };

        var futureTime = fakeTime.GetUtcNow().AddDays(1);
        for (int i = 0; i < TotpService.MaxCapacity - 1; i++)
        {
            service.ConsumedCodes[$"key-{i}"] = futureTime;
        }

        service.ConsumedCodesCount.Should().Be(TotpService.MaxCapacity - 1);

        // At 49,999, it is strictly less than MaxCapacity (50,000). Verification succeeds.
        var code = service.ComputeCode(Secret, fakeTime.GetUtcNow(), options);
        var result = service.VerifyCode(Secret, code, fakeTime.GetUtcNow(), options);
        result.Should().BeTrue("under capacity limit, verification succeeds");
        service.ConsumedCodesCount.Should().Be(TotpService.MaxCapacity);
    }

    [Fact]
    public void VerifyCode_EmptyDecodedSecret_ReturnsFalse()
    {
        // Kills Mutant: TotpService.cs line 174 (secretBytes.Length == 0 -> return false)
        var service = new TotpService();
        service.VerifyCode("====", "123456").Should().BeFalse();
    }

    [Fact]
    public void ComputeCode_EmptyDecodedSecret_ThrowsArgumentException()
    {
        // Kills Mutant: TotpService.cs line 117 (throw new ArgumentException("Secret key cannot be empty or zero bytes."))
        var service = new TotpService();
        var ex = Assert.Throws<ArgumentException>(() => service.ComputeCode("====", DateTimeOffset.UtcNow));
        ex.Message.Should().Contain("Secret key cannot be empty or zero bytes.");
    }

    [Fact]
    public void VerifyCode_PruningRateLimiting_ExactlyOneSecondBoundary_ExecutesPrune()
    {
        // Kills Mutant: nowTicks - lastTicks <= TimeSpan.FromSeconds(1).Ticks
        var fakeTime = new FakeTimeProvider(new DateTimeOffset(2050, 8, 30, 12, 0, 0, TimeSpan.Zero));
        var service = new TotpService(fakeTime);
        var options = new TotpOptions
        {
            PeriodSeconds = 30,
            AllowedDriftSteps = 0,
            PreventReplay = true
        };

        // Populate 1005 expired entries
        var expiredTime = fakeTime.GetUtcNow().AddSeconds(-100);
        for (int i = 0; i < 1005; i++)
        {
            service.ConsumedCodes[$"exp-{i}"] = expiredTime;
        }

        // Establish initial _lastPruneTicks
        fakeTime.Advance(TimeSpan.FromSeconds(2));
        var code1 = service.ComputeCode(Secret, fakeTime.GetUtcNow(), options);
        service.VerifyCode(Secret, code1, fakeTime.GetUtcNow(), options).Should().BeTrue();
        service.ConsumedCodesCount.Should().Be(1);

        // Add 1005 expired entries again
        for (int i = 0; i < 1005; i++)
        {
            service.ConsumedCodes[$"exp2-{i}"] = expiredTime;
        }

        // Advance by EXACTLY 1 second (10,000,000 ticks)
        // With (< 1s), (1s < 1s) is false -> throttle does NOT trigger -> pruning runs!
        // With (<= 1s), (1s <= 1s) is true -> throttle WOULD trigger -> pruning would be skipped!
        fakeTime.Advance(TimeSpan.FromSeconds(1));
        const string secret2 = "HXDMVJECJJWSRB3H";
        var tNow = fakeTime.GetUtcNow();
        var code2 = service.ComputeCode(secret2, tNow, options);
        service.VerifyCode(secret2, code2, tNow, options).Should().BeTrue();

        // Expired entries must have been pruned at exactly 1 second
        service.ConsumedCodes.ContainsKey("exp2-0").Should().BeFalse("at exactly 1.0s elapsed, pruning must run");
    }

    [Fact]
    public void VerifyCode_PruningRateLimiting_AtMaxCapacityUnderOneSecond_ForcesPrune()
    {
        // Kills Mutant: _consumedCodes.Count <= MaxConsumedCodesCapacity
        var fakeTime = new FakeTimeProvider(new DateTimeOffset(2050, 8, 30, 12, 0, 0, TimeSpan.Zero));
        var service = new TotpService(fakeTime);
        var options = new TotpOptions
        {
            PeriodSeconds = 30,
            AllowedDriftSteps = 0,
            PreventReplay = true
        };

        // Establish initial _lastPruneTicks
        fakeTime.Advance(TimeSpan.FromSeconds(2));
        var code1 = service.ComputeCode(Secret, fakeTime.GetUtcNow(), options);
        service.VerifyCode(Secret, code1, fakeTime.GetUtcNow(), options).Should().BeTrue();
        service.ConsumedCodes.Clear();

        // Populate exactly MaxCapacity (50,000) expired entries
        var expiredTime = fakeTime.GetUtcNow().AddSeconds(-100);
        for (int i = 0; i < TotpService.MaxCapacity; i++)
        {
            service.ConsumedCodes[$"key-{i}"] = expiredTime;
        }

        // Advance by only 100 ms (< 1s)
        fakeTime.Advance(TimeSpan.FromMilliseconds(100));

        // When count == MaxCapacity (50,000):
        // Original: (50000 < 50000) is FALSE -> throttle bypassed -> prune executes!
        // Mutant: (50000 <= 50000) is TRUE -> throttle triggers -> prune skipped -> fails-closed!
        const string secret2 = "HXDMVJECJJWSRB3H";
        var tNow = fakeTime.GetUtcNow();
        var code2 = service.ComputeCode(secret2, tNow, options);
        service.VerifyCode(secret2, code2, tNow, options).Should().BeTrue("at capacity limit, throttle must be bypassed to prune expired entries");
        service.ConsumedCodesCount.Should().Be(1);
    }

    [Theory]
    [InlineData("M")]         // Remainder 1
    [InlineData("MYY")]       // Remainder 3
    [InlineData("MYYYYY")]    // Remainder 6
    public void Base32Encoding_InvalidQuantumLengths_ThrowsFormatException(string invalidInput)
    {
        // Kills Mutants: Base32Encoding.cs lines 95-97 (remainder is 1 or 3 or 6)
        var ex = Assert.Throws<FormatException>(() => Base32Encoding.FromBase32String(invalidInput));
        ex.Message.Should().Contain("RFC 4648 prohibits unpadded quantum lengths mod 8 of 1, 3, or 6");
    }

    [Fact]
    public void Base32Encoding_NonZeroPaddingBits_ThrowsFormatException()
    {
        // Kills Mutants: Base32Encoding.cs lines 100-103
        // "MZ" has 2 chars (10 bits). 8 bits make 1 byte, leaving 2 non-zero padding bits.
        var ex = Assert.Throws<FormatException>(() => Base32Encoding.FromBase32String("MZ"));
        ex.Message.Should().Contain("Non-zero padding bits detected in Base32 string");
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void RecoveryCodeGenerator_HashCode_NullOrWhitespace_ThrowsArgumentException(string? invalidCode)
    {
        // Kills Mutant: RecoveryCodeGenerator.cs line 93 (throw message mutation)
        var ex = Assert.Throws<ArgumentException>(() => RecoveryCodeGenerator.HashCode(invalidCode!));
        ex.Message.Should().Contain("Recovery code cannot be null or whitespace.");
    }
}
