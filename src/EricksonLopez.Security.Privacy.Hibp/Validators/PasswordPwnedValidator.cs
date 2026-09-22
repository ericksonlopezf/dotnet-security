// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Privacy.Hibp.Validators;

using System;
using System.Threading;
using System.Threading.Tasks;
using EricksonLopez.Result;
using EricksonLopez.Security.Abstractions.Errors;
using EricksonLopez.Security.Privacy.Hibp.Abstractions;
using EricksonLopez.Security.Privacy.Hibp.Models;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Result = global::EricksonLopez.Result.Result;

/// <summary>
/// Validates that passwords have not appeared in known public data breaches.
/// </summary>
public sealed class PasswordPwnedValidator : IPasswordPwnedValidator
{
    private readonly IHaveIBeenPwnedClient _client;
    private readonly HibpOptions _options;
    private readonly ILogger<PasswordPwnedValidator> _logger;

    /// <summary>
    /// Initializes a new instance of the <see cref="PasswordPwnedValidator"/> class.
    /// </summary>
    /// <param name="client">The Have I Been Pwned API client for performing range queries.</param>
    /// <param name="options">The configured HIBP integration options accessor.</param>
    /// <param name="logger">Optional logger instance for diagnostic events.</param>
    /// <exception cref="ArgumentNullException"><paramref name="client"/> or <paramref name="options"/> is <see langword="null"/></exception>
    public PasswordPwnedValidator(
        IHaveIBeenPwnedClient client,
        IOptions<HibpOptions> options,
        ILogger<PasswordPwnedValidator>? logger = null)
    {
        _client = client ?? throw new ArgumentNullException(nameof(client));
        _options = options?.Value ?? throw new ArgumentNullException(nameof(options));
        _logger = logger ?? NullLogger<PasswordPwnedValidator>.Instance;
    }

    /// <inheritdoc />
    public async Task<Result> ValidateNotPwnedAsync(string password, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(password))
        {
            return Result.Success();
        }

        var checkResult = await _client.CheckPasswordAsync(password, cancellationToken).ConfigureAwait(false);
        if (checkResult.IsFailure)
        {
            _logger.LogWarning("HIBP password validation failed to query external service: {Error}", checkResult.Error.Description);
            // In case of external service outage, return failure or propagate based on security posture
            return Result.Failure(checkResult.Error);
        }

        var outcome = checkResult.Value;
        if (outcome.BreachCount > _options.MaxAllowedBreachCount)
        {
            _logger.LogWarning("Password compromise detected: password appeared in {Count} known data breaches.", outcome.BreachCount);
            return Result.Failure(
                SecurityError.SecurityPolicyViolation(
                    "Password.Breached",
                    $"The chosen password was found in {outcome.BreachCount:N0} publicly known data breaches and cannot be used."));
        }

        return Result.Success();
    }
}
