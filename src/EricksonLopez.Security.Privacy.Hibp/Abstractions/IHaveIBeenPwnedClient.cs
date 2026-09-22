// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Privacy.Hibp.Abstractions;

using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using EricksonLopez.Result;
using EricksonLopez.Security.Privacy.Hibp.Models;

/// <summary>
/// Defines a client contract for querying the Have I Been Pwned (HIBP) API using privacy-preserving k-Anonymity.
/// </summary>
public interface IHaveIBeenPwnedClient
{
    /// <summary>
    /// Determines whether a plaintext password has been exposed in data breaches without sending the full hash or plaintext over the network.
    /// </summary>
    /// <param name="password">The plaintext password to check.</param>
    /// <param name="cancellationToken">A token that can be used to cancel the asynchronous operation.</param>
    /// <returns>A task representing the asynchronous operation. The task result contains a result with the check outcome.</returns>
    Task<Result<PwnedPasswordCheckResult>> CheckPasswordAsync(string password, CancellationToken cancellationToken = default);

    /// <summary>
    /// Queries the HIBP range API with a 5-character SHA-1 hexadecimal prefix.
    /// </summary>
    /// <param name="hashPrefix">The 5-character uppercase SHA-1 prefix.</param>
    /// <param name="cancellationToken">A token that can be used to cancel the asynchronous operation.</param>
    /// <returns>A task representing the asynchronous operation. The task result contains a collection of matching hash suffixes and breach counts.</returns>
    Task<Result<IReadOnlyList<PwnedPasswordEntry>>> GetRangeAsync(string hashPrefix, CancellationToken cancellationToken = default);
}
