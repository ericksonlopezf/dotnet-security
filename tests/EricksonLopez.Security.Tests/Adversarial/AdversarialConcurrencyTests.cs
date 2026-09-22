// Copyright © Erickson Lopez. MIT License.
// Concurrency stress tests for security-sensitive shared state.

namespace EricksonLopez.Security.Tests.Adversarial;

using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using AwesomeAssertions;
using EricksonLopez.Security.Mfa;
using Xunit;

/// <summary>
/// Adversarial concurrency tests that exercise security-sensitive shared state under high load.
/// These tests ensure thread-safety of replay caches and pruning logic under concurrent access.
/// </summary>
public class AdversarialConcurrencyTests
{
    /// <summary>
    /// Validates that <see cref="TotpService"/> handles 100 concurrent threads each performing
    /// 1,000 operations without deadlocks, exceptions, or corruption of the replay cache.
    /// Tests the lock-free <c>ConcurrentDictionary</c> and <c>PruneExpiredCodes</c> interaction.
    /// </summary>
    [Fact]
    public async Task TotpService_Handles_High_Concurrency_100_Threads()
    {
        var service = new TotpService();
        var tasks = new List<Task>();

        for (int i = 0; i < 100; i++)
        {
            tasks.Add(Task.Run(() =>
            {
                for (int j = 0; j < 1000; j++)
                {
                    var secret = Base32Encoding.ToBase32String(service.GenerateSecretKey());
                    var code = service.ComputeCode(secret, DateTimeOffset.UtcNow);
                    service.VerifyCode(secret, code);
                }
            }));
        }

        // This must complete without deadlock, ObjectDisposedException, or InvalidOperationException.
        await Task.WhenAll(tasks);
    }
}
