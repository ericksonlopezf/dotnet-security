// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Testing.Tests;

using System;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using AwesomeAssertions;
using EricksonLopez.Security.Testing.Http;
using Xunit;

public sealed class TestHttpMessageHandlerTests
{
    [Fact]
    public async Task StringContentConstructor_ReturnsConfiguredResponseAndRecordsRequest()
    {
        using var handler = new TestHttpMessageHandler("Hello Secure World!", HttpStatusCode.Accepted, "text/plain");
        handler.LastRequest.Should().BeNull();
        handler.LastRequestHeaders.Should().BeNull();
        using var client = new HttpClient(handler);

        var response = await client.GetAsync("https://api.example.com/data");

        response.StatusCode.Should().Be(HttpStatusCode.Accepted);
        var content = await response.Content.ReadAsStringAsync();
        content.Should().Be("Hello Secure World!");

        handler.RequestCount.Should().Be(1);
        handler.LastRequest.Should().NotBeNull();
        handler.LastRequest!.RequestUri.Should().Be(new Uri("https://api.example.com/data"));
        handler.Requests.Should().HaveCount(1);
    }

    [Fact]
    public async Task SyncHandlerConstructor_InvokesSyncDelegate()
    {
        using var handler = new TestHttpMessageHandler(req =>
        {
            var res = new HttpResponseMessage(HttpStatusCode.Created);
            res.Headers.Add("X-Test-Id", "123");
            return res;
        });
        using var client = new HttpClient(handler);

        var response = await client.PostAsync("https://api.example.com/items", new StringContent("{}"));

        response.StatusCode.Should().Be(HttpStatusCode.Created);
        response.Headers.GetValues("X-Test-Id").Should().Contain("123");
        handler.LastRequestHeaders.Should().NotBeNull();
    }

    [Fact]
    public async Task AsyncHandlerConstructor_InvokesAsyncDelegate()
    {
        using var handler = new TestHttpMessageHandler(async (req, ct) =>
        {
            await Task.Yield();
            return new HttpResponseMessage(HttpStatusCode.NoContent);
        });
        using var client = new HttpClient(handler);

        var response = await client.DeleteAsync("https://api.example.com/items/42");

        response.StatusCode.Should().Be(HttpStatusCode.NoContent);
    }

    [Fact]
    public async Task ExceptionConstructor_ThrowsConfiguredException()
    {
        var expectedEx = new HttpRequestException("Simulated connection timeout");
        using var handler = new TestHttpMessageHandler(expectedEx);
        using var client = new HttpClient(handler);

        var act = async () => await client.GetAsync("https://api.example.com/timeout");

        await act.Should().ThrowAsync<HttpRequestException>()
            .WithMessage("Simulated connection timeout");
    }

    [Fact]
    public async Task Dispose_MarksHandlerAsDisposedAndThrowsOnAccess()
    {
        var handler = new TestHttpMessageHandler("OK");
        handler.IsDisposed.Should().BeFalse();

        handler.Dispose();
        handler.IsDisposed.Should().BeTrue();

        using var client = new HttpClient(handler);
        var act = async () => await client.GetAsync("https://api.example.com");

        await act.Should().ThrowAsync<ObjectDisposedException>();
    }

    [Fact]
    public void Constructor_NullArguments_ThrowArgumentNullException()
    {
        Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> nullAsync = null!;
        Func<HttpRequestMessage, HttpResponseMessage> nullSync = null!;
        Exception nullEx = null!;

        Assert.Throws<ArgumentNullException>(() => new TestHttpMessageHandler(nullAsync));
        Assert.Throws<ArgumentNullException>(() => new TestHttpMessageHandler(nullSync));
        Assert.Throws<ArgumentNullException>(() => new TestHttpMessageHandler(nullEx));
    }

    [Fact]
    public async Task SyncHandlerConstructor_WithCancellationToken_Cancels()
    {
        using var handler = new TestHttpMessageHandler(req => new HttpResponseMessage(HttpStatusCode.OK));
        using var invoker = new HttpMessageInvoker(handler);
        using var req = new HttpRequestMessage(HttpMethod.Get, "https://api.example.com");
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        var act = async () => await invoker.SendAsync(req, cts.Token);
        await act.Should().ThrowAsync<OperationCanceledException>();
    }

    [Fact]
    public async Task StringContentConstructor_WithCancellationToken_Cancels()
    {
        using var handler = new TestHttpMessageHandler("Test Content");
        using var invoker = new HttpMessageInvoker(handler);
        using var req = new HttpRequestMessage(HttpMethod.Get, "https://api.example.com");
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        var act = async () => await invoker.SendAsync(req, cts.Token);
        await act.Should().ThrowAsync<OperationCanceledException>();
    }

    [Fact]
    public async Task SendAsync_NullRequest_ThrowsArgumentNullException()
    {
        using var handler = new TestHttpMessageHandler("OK");
        var sendMethod = typeof(HttpMessageHandler).GetMethod("SendAsync", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)!;
        var task = (Task<HttpResponseMessage>)sendMethod.Invoke(handler, [null, CancellationToken.None])!;

        var act = async () => await task;
        await act.Should().ThrowAsync<ArgumentNullException>();
    }
}
