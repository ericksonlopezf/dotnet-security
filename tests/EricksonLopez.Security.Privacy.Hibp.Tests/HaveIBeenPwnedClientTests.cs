// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Privacy.Hibp.Tests;

using System;
using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using AwesomeAssertions;
using EricksonLopez.Security.Privacy.Hibp.Clients;
using EricksonLopez.Security.Privacy.Hibp.Models;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NSubstitute;
using EricksonLopez.Security.Testing.Http;
using Xunit;

[Trait("Category", "Integration")]
public sealed class HaveIBeenPwnedClientTests
{
    [Fact]
    [SuppressMessage("Security", "CA5350:Do Not Use Weak Cryptographic Algorithms", Justification = "Testing SHA-1 calculation for HIBP range query.")]
    public async Task CheckPasswordAsync_PasswordInBreachList_ReturnsBreachCount()
    {
        // Arrange: password "password123" -> SHA1: CBFDAC6008F9CAB4083784CBD1874F76618D2A97
        // Prefix: CBFDA, Suffix: C6008F9CAB4083784CBD1874F76618D2A97
        const string password = "password123";
        var hashBytes = SHA1.HashData(Encoding.UTF8.GetBytes(password));
        var fullHex = Convert.ToHexString(hashBytes);
        var prefix = fullHex[..5];
        var suffix = fullHex[5..];

        // Add duplicate suffix to ensure first match is used via break statement
        var responseBody = $"{suffix}:12345\r\n{suffix}:99999\r\n00000000000000000000000000000000000:1\r\n";

        var handler = new TestHttpMessageHandler(responseBody, HttpStatusCode.OK);
        var httpClient = new HttpClient(handler) { BaseAddress = new Uri("https://api.pwnedpasswords.com/") };
        var options = Options.Create(new HibpOptions());

        var client = new HaveIBeenPwnedClient(httpClient, options, NullLogger<HaveIBeenPwnedClient>.Instance);

        // Act
        var result = await client.CheckPasswordAsync(password);

        // Assert
        result.IsSuccess.Should().BeTrue();
        result.Value.IsPwned.Should().BeTrue();
        result.Value.BreachCount.Should().Be(12345);
        result.Value.HashPrefix.Should().Be(prefix);
        handler.LastRequest!.RequestUri!.ToString().Should().EndWith("range/" + prefix);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public async Task CheckPasswordAsync_NullOrEmptyPassword_ReturnsZeroCountResult(string? emptyPassword)
    {
        var handler = new TestHttpMessageHandler(string.Empty, HttpStatusCode.OK);
        var httpClient = new HttpClient(handler) { BaseAddress = new Uri("https://api.pwnedpasswords.com/") };
        var options = Options.Create(new HibpOptions());

        var client = new HaveIBeenPwnedClient(httpClient, options);

        var result = await client.CheckPasswordAsync(emptyPassword!);

        result.IsSuccess.Should().BeTrue();
        result.Value.HashPrefix.Should().Be("00000");
        result.Value.BreachCount.Should().Be(0);
        result.Value.IsPwned.Should().BeFalse();
    }

    [Fact]
    public async Task CheckPasswordAsync_RangeApiFails_ReturnsFailure()
    {
        var handler = new TestHttpMessageHandler("Error", HttpStatusCode.ServiceUnavailable);
        var httpClient = new HttpClient(handler) { BaseAddress = new Uri("https://api.pwnedpasswords.com/") };
        var options = Options.Create(new HibpOptions());

        var client = new HaveIBeenPwnedClient(httpClient, options);

        var result = await client.CheckPasswordAsync("some_password");

        result.IsFailure.Should().BeTrue();
        result.Error.Code.Should().Be("Security.ServiceUnavailable");
    }

    [Fact]
    public async Task CheckPasswordAsync_PasswordNotInBreachList_ReturnsZeroBreachCount()
    {
        const string password = "super_unique_secure_password_99999!";
        var responseBody = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:10\r\n";

        var handler = new TestHttpMessageHandler(responseBody, HttpStatusCode.OK);
        var httpClient = new HttpClient(handler) { BaseAddress = new Uri("https://api.pwnedpasswords.com/") };
        var options = Options.Create(new HibpOptions());

        var client = new HaveIBeenPwnedClient(httpClient, options);

        // Act
        var result = await client.CheckPasswordAsync(password);

        // Assert
        result.IsSuccess.Should().BeTrue();
        result.Value.IsPwned.Should().BeFalse();
        result.Value.BreachCount.Should().Be(0);
    }

    [Fact]
    public async Task GetRangeAsync_ConfiguredHeaders_AreSentCorrectly()
    {
        var handler = new TestHttpMessageHandler("00000000000000000000000000000000000:1\r\n", HttpStatusCode.OK);
        var httpClient = new HttpClient(handler) { BaseAddress = new Uri("https://api.pwnedpasswords.com/") };
        var options = Options.Create(new HibpOptions
        {
            UserAgent = "Custom-Agent-1.0",
            AddPadding = true
        });

        var client = new HaveIBeenPwnedClient(httpClient, options);

        var result = await client.GetRangeAsync("ABCDE");

        result.IsSuccess.Should().BeTrue();
        handler.LastRequest!.RequestUri!.ToString().Should().EndWith("range/ABCDE");
        handler.LastRequestHeaders.Should().NotBeNull();
        handler.LastRequestHeaders!.UserAgent.ToString().Should().Contain("Custom-Agent-1.0");
        handler.LastRequestHeaders!.GetValues("Add-Padding").Should().Contain("true");
    }

    [Fact]
    public async Task GetRangeAsync_WithoutPaddingOrAgent_OmitsHeaders()
    {
        var handler = new TestHttpMessageHandler("00000000000000000000000000000000000:1\r\n", HttpStatusCode.OK);
        var httpClient = new HttpClient(handler) { BaseAddress = new Uri("https://api.pwnedpasswords.com/") };
        var options = Options.Create(new HibpOptions
        {
            UserAgent = "",
            AddPadding = false
        });

        var client = new HaveIBeenPwnedClient(httpClient, options);

        var result = await client.GetRangeAsync("ABCDE");

        result.IsSuccess.Should().BeTrue();
        handler.LastRequestHeaders.Should().NotBeNull();
        handler.LastRequestHeaders!.Contains("Add-Padding").Should().BeFalse();
    }

    [Theory]
    [InlineData("A")]
    [InlineData("ABC")]
    [InlineData("ABCDEF")]
    public async Task GetRangeAsync_InvalidPrefixLength_ReturnsFailure(string invalidPrefix)
    {
        var handler = new TestHttpMessageHandler(string.Empty, HttpStatusCode.OK);
        var httpClient = new HttpClient(handler) { BaseAddress = new Uri("https://api.pwnedpasswords.com/") };
        var options = Options.Create(new HibpOptions());

        var client = new HaveIBeenPwnedClient(httpClient, options);

        var result = await client.GetRangeAsync(invalidPrefix);

        result.IsFailure.Should().BeTrue();
        result.Error.Code.Should().Be("Security.InvalidKey");
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public async Task GetRangeAsync_NullOrWhitespacePrefix_ThrowsArgumentException(string? invalidPrefix)
    {
        var handler = new TestHttpMessageHandler(string.Empty, HttpStatusCode.OK);
        var httpClient = new HttpClient(handler) { BaseAddress = new Uri("https://api.pwnedpasswords.com/") };
        var options = Options.Create(new HibpOptions());

        var client = new HaveIBeenPwnedClient(httpClient, options);

        var act = async () => await client.GetRangeAsync(invalidPrefix!);
        await act.Should().ThrowAsync<ArgumentException>();
    }

    [Fact]
    public async Task GetRangeAsync_MalformedResponseLines_SkipsInvalidEntries()
    {
        // Line 1: valid
        // Line 2: whitespace (ignored)
        // Line 3: no colon (ignored)
        // Line 4: non-numeric count (ignored)
        // Line 5: colon at start (ignored)
        // Line 6: valid
        var responseBody = "AAAAAAAA:100\r\n   \r\nNO_COLON_LINE\r\nBBBBBBBB:not-a-number\r\n:50\r\nCCCCCCCC:200\r\n";

        var handler = new TestHttpMessageHandler(responseBody, HttpStatusCode.OK);
        var httpClient = new HttpClient(handler) { BaseAddress = new Uri("https://api.pwnedpasswords.com/") };
        var options = Options.Create(new HibpOptions());

        var client = new HaveIBeenPwnedClient(httpClient, options);

        var result = await client.GetRangeAsync("12345");

        result.IsSuccess.Should().BeTrue();
        result.Value.Count.Should().Be(2);
        result.Value[0].Suffix.Should().Be("AAAAAAAA");
        result.Value[0].BreachCount.Should().Be(100);
        result.Value[1].Suffix.Should().Be("CCCCCCCC");
        result.Value[1].BreachCount.Should().Be(200);
    }

    [Fact]
    public async Task GetRangeAsync_HttpException_ReturnsFailure()
    {
        var handler = new TestHttpMessageHandler(new HttpRequestException("DNS error"));
        var httpClient = new HttpClient(handler) { BaseAddress = new Uri("https://api.pwnedpasswords.com/") };
        var options = Options.Create(new HibpOptions());

        var client = new HaveIBeenPwnedClient(httpClient, options);

        var result = await client.GetRangeAsync("12345");

        result.IsFailure.Should().BeTrue();
        result.Error.Code.Should().Be("Security.ServiceUnavailable");
        result.Error.Description.Should().Contain("DNS error");
    }

    [Fact]
    public async Task GetRangeAsync_CancellationTokenRequested_RethrowsOperationCanceledException()
    {
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        var handler = new TestHttpMessageHandler(new OperationCanceledException(cts.Token));
        var httpClient = new HttpClient(handler) { BaseAddress = new Uri("https://api.pwnedpasswords.com/") };
        var options = Options.Create(new HibpOptions());

        var client = new HaveIBeenPwnedClient(httpClient, options);

        var act = async () => await client.GetRangeAsync("12345", cts.Token);
        await act.Should().ThrowAsync<OperationCanceledException>();
    }

    [Fact]
    public void Constructor_NullArguments_ThrowsArgumentNullException()
    {
        var options = Options.Create(new HibpOptions());
        var httpClient = new HttpClient();

        Assert.Throws<ArgumentNullException>(() => new HaveIBeenPwnedClient(null!, options));
        Assert.Throws<ArgumentNullException>(() => new HaveIBeenPwnedClient(httpClient, null!));
    }

    [Fact]
    public async Task GetRangeAsync_WhenResponseFails_LogsWarningToProvidedLogger()
    {
        var fakeLogger = new EricksonLopez.Security.Testing.Logging.FakeLogger<HaveIBeenPwnedClient>();

        var handler = new TestHttpMessageHandler("Error", HttpStatusCode.InternalServerError);
        var httpClient = new HttpClient(handler) { BaseAddress = new Uri("https://api.pwnedpasswords.com/") };
        var options = Options.Create(new HibpOptions());

        var client = new HaveIBeenPwnedClient(httpClient, options, fakeLogger);
        var result = await client.GetRangeAsync("ABCDE");

        result.IsFailure.Should().BeTrue();
        fakeLogger.Count.Should().Be(1);
        fakeLogger.Entries[0].LogLevel.Should().Be(LogLevel.Warning);
    }

    [Fact]
    [SuppressMessage("Security", "CA5350:Do Not Use Weak Cryptographic Algorithms", Justification = "Testing SHA-1 calculation for HIBP range query.")]
    public async Task CheckPasswordAsync_LongPasswordExceeding256Bytes_RentsArrayPoolBufferAndReturnsCorrectResult()
    {
        var longPassword = new string('X', 300);
        var hashBytes = SHA1.HashData(Encoding.UTF8.GetBytes(longPassword));
        var fullHex = Convert.ToHexString(hashBytes);
        var prefix = fullHex[..5];
        var suffix = fullHex[5..];

        var responseBody = $"{suffix}:777\r\n";
        var handler = new TestHttpMessageHandler(responseBody, HttpStatusCode.OK);
        var httpClient = new HttpClient(handler) { BaseAddress = new Uri("https://api.pwnedpasswords.com/") };
        var options = Options.Create(new HibpOptions());
        var client = new HaveIBeenPwnedClient(httpClient, options, NullLogger<HaveIBeenPwnedClient>.Instance);

        var result = await client.CheckPasswordAsync(longPassword);

        result.IsSuccess.Should().BeTrue();
        result.Value.IsPwned.Should().BeTrue();
        result.Value.BreachCount.Should().Be(777);
        result.Value.HashPrefix.Should().Be(prefix);
    }

    [Theory]
    [InlineData(84)] // maxByteCount = 255 <= 256 (stackalloc)
    [InlineData(85)] // maxByteCount = 258 > 256 (ArrayPool.Rent)
    [SuppressMessage("Security", "CA5350:Do Not Use Weak Cryptographic Algorithms", Justification = "Testing SHA-1 calculation for HIBP range query.")]
    public async Task CheckPasswordAsync_BoundaryPasswords_Around256MaxBytes_ComputesCorrectSha1(int length)
    {
        var password = new string('B', length);
        var hashBytes = SHA1.HashData(Encoding.UTF8.GetBytes(password));
        var fullHex = Convert.ToHexString(hashBytes);
        var prefix = fullHex[..5];
        var suffix = fullHex[5..];

        var responseBody = $"{suffix}:123\r\n";
        var handler = new TestHttpMessageHandler(responseBody, HttpStatusCode.OK);
        var httpClient = new HttpClient(handler) { BaseAddress = new Uri("https://api.pwnedpasswords.com/") };
        var options = Options.Create(new HibpOptions());
        var client = new HaveIBeenPwnedClient(httpClient, options, NullLogger<HaveIBeenPwnedClient>.Instance);

        var result = await client.CheckPasswordAsync(password);

        result.IsSuccess.Should().BeTrue();
        result.Value.IsPwned.Should().BeTrue();
        result.Value.BreachCount.Should().Be(123);
        result.Value.HashPrefix.Should().Be(prefix);
    }
}
