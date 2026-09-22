// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Privacy.Hibp.Abstractions;

using System.Threading;
using System.Threading.Tasks;
using EricksonLopez.Result;
using Result = global::EricksonLopez.Result.Result;

/// <summary>
/// Defines a validator contract for enforcing that user passwords have not been compromised in publicly known data breaches.
/// </summary>
public interface IPasswordPwnedValidator
{
    /// <summary>
    /// Validates that the provided password has not been exposed in data breaches exceeding the configured threshold.
    /// </summary>
    /// <param name="password">The plaintext password to validate.</param>
    /// <param name="cancellationToken">A token that can be used to cancel the asynchronous operation.</param>
    /// <returns>A task representing the asynchronous operation. The task result contains a successful result if clean, or a validation failure describing the breach count.</returns>
    Task<Result> ValidateNotPwnedAsync(string password, CancellationToken cancellationToken = default);
}
