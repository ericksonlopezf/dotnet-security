// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Privacy.Hibp.Tests;

using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using AwesomeAssertions;
using EricksonLopez.Result;
using EricksonLopez.Security.Privacy.Hibp.Abstractions;
using EricksonLopez.Security.Privacy.Hibp.Models;
using EricksonLopez.Security.Privacy.Hibp.Validators;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NSubstitute;
using Xunit;

public sealed class PasswordPwnedValidatorTests
{
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public async Task ValidateNotPwnedAsync_NullOrEmptyPassword_ReturnsSuccess(string? emptyPassword)
    {
        var mockClient = new StrictEmptyGuardHibpClient();
        var options = Options.Create(new HibpOptions { MaxAllowedBreachCount = 0 });
        var validator = new PasswordPwnedValidator(mockClient, options);

        var result = await validator.ValidateNotPwnedAsync(emptyPassword!);

        result.IsSuccess.Should().BeTrue();
    }

    [Fact]
    public async Task ValidateNotPwnedAsync_CleanPassword_ReturnsSuccess()
    {
        var mockClient = new FakeHibpClient(breachCount: 0);
        var options = Options.Create(new HibpOptions { MaxAllowedBreachCount = 0 });
        var validator = new PasswordPwnedValidator(mockClient, options, NullLogger<PasswordPwnedValidator>.Instance);

        var result = await validator.ValidateNotPwnedAsync("super_secret_clean_password");

        result.IsSuccess.Should().BeTrue();
    }

    [Fact]
    public async Task ValidateNotPwnedAsync_ClientReturnsFailure_PropagatesError()
    {
        var mockClient = new FailingHibpClient(Error.Failure("Security.ServiceUnavailable", "Outage"));
        var options = Options.Create(new HibpOptions());
        var validator = new PasswordPwnedValidator(mockClient, options);

        var result = await validator.ValidateNotPwnedAsync("any_password");

        result.IsFailure.Should().BeTrue();
        result.Error.Code.Should().Be("Security.ServiceUnavailable");
    }

    [Theory]
    [InlineData(10, 0, false)] // Exceeds threshold 0 -> Fail
    [InlineData(5, 5, true)]   // Exactly at threshold 5 -> Success
    [InlineData(6, 5, false)]  // Exceeds threshold 5 by 1 -> Fail
    [InlineData(4, 5, true)]   // Below threshold 5 -> Success
    public async Task ValidateNotPwnedAsync_BreachCountThresholdBoundary_EvaluatesCorrectly(long breachCount, long maxAllowed, bool expectedSuccess)
    {
        var mockClient = new FakeHibpClient(breachCount: breachCount);
        var options = Options.Create(new HibpOptions { MaxAllowedBreachCount = maxAllowed });
        var validator = new PasswordPwnedValidator(mockClient, options);

        var result = await validator.ValidateNotPwnedAsync("test_password");

        result.IsSuccess.Should().Be(expectedSuccess);
        if (!expectedSuccess)
        {
            result.Error.Code.Should().Be("Security.PolicyViolation");
            result.Error.Description.Should().Contain("Password.Breached");
            result.Error.Description.Should().Contain(breachCount.ToString("N0"));
        }
    }

    [Fact]
    public void Constructor_NullArguments_ThrowsArgumentNullException()
    {
        var options = Options.Create(new HibpOptions());
        var mockClient = new FakeHibpClient(0);

        Assert.Throws<ArgumentNullException>(() => new PasswordPwnedValidator(null!, options));
        Assert.Throws<ArgumentNullException>(() => new PasswordPwnedValidator(mockClient, null!));
    }

    [Fact]
    public async Task ValidateNotPwnedAsync_WhenCheckFails_LogsWarningToProvidedLogger()
    {
        var fakeLogger = new EricksonLopez.Security.Testing.Logging.FakeLogger<PasswordPwnedValidator>();

        var mockClient = Substitute.For<IHaveIBeenPwnedClient>();
        mockClient.CheckPasswordAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(Result<PwnedPasswordCheckResult>.Failure(Error.Failure("Err", "Fail"))));

        var validator = new PasswordPwnedValidator(mockClient, Options.Create(new HibpOptions()), fakeLogger);
        var result = await validator.ValidateNotPwnedAsync("password123");

        result.IsFailure.Should().BeTrue();
        fakeLogger.Count.Should().Be(1);
        fakeLogger.Entries[0].LogLevel.Should().Be(LogLevel.Warning);
    }

    private sealed class FakeHibpClient : IHaveIBeenPwnedClient
    {
        private readonly long _breachCount;

        public FakeHibpClient(long breachCount)
        {
            _breachCount = breachCount;
        }

        public Task<Result<PwnedPasswordCheckResult>> CheckPasswordAsync(string password, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(Result<PwnedPasswordCheckResult>.Success(new PwnedPasswordCheckResult("12345", _breachCount)));
        }

        public Task<Result<IReadOnlyList<PwnedPasswordEntry>>> GetRangeAsync(string hashPrefix, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(Result<IReadOnlyList<PwnedPasswordEntry>>.Success(new List<PwnedPasswordEntry>()));
        }
    }

    private sealed class FailingHibpClient : IHaveIBeenPwnedClient
    {
        private readonly Error _error;

        public FailingHibpClient(Error error)
        {
            _error = error;
        }

        public Task<Result<PwnedPasswordCheckResult>> CheckPasswordAsync(string password, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(Result<PwnedPasswordCheckResult>.Failure(_error));
        }

        public Task<Result<IReadOnlyList<PwnedPasswordEntry>>> GetRangeAsync(string hashPrefix, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(Result<IReadOnlyList<PwnedPasswordEntry>>.Failure(_error));
        }
    }

    private sealed class StrictEmptyGuardHibpClient : IHaveIBeenPwnedClient
    {
        public Task<Result<PwnedPasswordCheckResult>> CheckPasswordAsync(string password, CancellationToken cancellationToken = default)
        {
            throw new InvalidOperationException("CheckPasswordAsync should not be invoked for null or empty password.");
        }

        public Task<Result<IReadOnlyList<PwnedPasswordEntry>>> GetRangeAsync(string hashPrefix, CancellationToken cancellationToken = default)
        {
            throw new InvalidOperationException("GetRangeAsync should not be invoked for null or empty password.");
        }
    }
}
