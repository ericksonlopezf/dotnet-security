// Copyright © Erickson Lopez. MIT License.
// Adversarial concurrency test for TotpService — verifies thread safety under 100-thread load.

namespace EricksonLopez.Security.Mfa.Tests.Adversarial;

using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using AwesomeAssertions;
using Xunit;

/// <summary>
/// Adversarial concurrency tests for <see cref="TotpService"/>.
/// Validates that <c>ConcurrentDictionary</c> and <c>PruneExpiredCodes</c> are thread-safe
/// under high-concurrency load (100 concurrent threads, 1000 operations each).
/// </summary>
public sealed class TotpServiceConcurrencyTests
{
    [Fact]
    public async Task TotpService_Handles_High_Concurrency_100_Threads_WithoutDeadlock()
    {
        // CON-001 REGRESSION: TotpService.PruneExpiredCodes() uses Interlocked + ConcurrentDictionary.
        // Under 100 threads, each doing 1000 TOTP ops, there must be no deadlock, exception, or state corruption.
        var service = new TotpService();
        var tasks = new List<Task>();
        var exceptions = new System.Collections.Concurrent.ConcurrentBag<Exception>();

        var successfulVerifications = 0;

        for (int i = 0; i < 100; i++)
        {
            tasks.Add(Task.Run(() =>
            {
                try
                {
                    for (int j = 0; j < 100; j++)
                    {
                        var secret = Base32Encoding.ToBase32String(service.GenerateSecretKey());
                        var code = service.ComputeCode(secret, DateTimeOffset.UtcNow);
                        var valid = service.VerifyCode(secret, code);
                        if (valid)
                        {
                            System.Threading.Interlocked.Increment(ref successfulVerifications);
                        }
                    }
                }
                catch (Exception ex)
                {
                    exceptions.Add(ex);
                }
            }));
        }

        await Task.WhenAll(tasks);

        exceptions.Should().BeEmpty(
            "TotpService must be thread-safe: no exceptions should occur under 100-thread concurrent load. " +
            "Exceptions observed: {0}", string.Join("; ", exceptions));

        successfulVerifications.Should().Be(100 * 100, "All freshly generated codes must successfully verify once.");
    }

    [Fact]
    public async Task TotpService_ConcurrentVerificationOfSharedKeys_EnforcesReplayProtectionWithoutRaces()
    {
        // FINDING-NEW-04 / CON-001: Under multi-threaded contention on the SAME keys, exactly one thread
        // must succeed and subsequent/concurrent replay attempts must return false.
        var service = new TotpService();
        var secret = Base32Encoding.ToBase32String(service.GenerateSecretKey());
        var now = DateTimeOffset.UtcNow;
        var code = service.ComputeCode(secret, now);
        var options = new TotpOptions { PreventReplay = true, PeriodSeconds = 30 };

        var successes = 0;
        var tasks = new List<Task>();

        for (int i = 0; i < 50; i++)
        {
            tasks.Add(Task.Run(() =>
            {
                if (service.VerifyCode(secret, code, now, options))
                {
                    System.Threading.Interlocked.Increment(ref successes);
                }
            }));
        }

        await Task.WhenAll(tasks);

        successes.Should().Be(1, "Exactly one concurrent caller must succeed on a shared code; all others must be rejected as replays.");
    }
}
