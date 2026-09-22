// Copyright © Erickson Lopez. MIT License.

namespace EricksonLopez.Security.Testing.Http;

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

/// <summary>
/// Provides a configurable test double implementation of <see cref="HttpMessageHandler"/> for deterministic HTTP testing.
/// </summary>
public sealed class TestHttpMessageHandler : HttpMessageHandler
{
    private readonly Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> _asyncHandler;
    private readonly ConcurrentBag<HttpRequestMessage> _requests = new();

    /// <summary>
    /// Gets the most recent request sent through this handler, if any.
    /// </summary>
    public HttpRequestMessage? LastRequest { get; private set; }

    /// <summary>
    /// Gets the headers from the most recent request sent through this handler, if any.
    /// </summary>
    public HttpRequestHeaders? LastRequestHeaders => LastRequest?.Headers;

    /// <summary>
    /// Gets the collection of all requests received by this handler.
    /// </summary>
    public IReadOnlyCollection<HttpRequestMessage> Requests => _requests;

    /// <summary>
    /// Gets the total number of requests handled.
    /// </summary>
    public int RequestCount => _requests.Count;

    /// <summary>
    /// Gets a value indicating whether this handler has been disposed.
    /// </summary>
    public bool IsDisposed { get; private set; }

    /// <summary>
    /// Initializes a new instance of the <see cref="TestHttpMessageHandler"/> class with an asynchronous handler delegate.
    /// </summary>
    /// <param name="asyncHandler">The delegate invoked on each request.</param>
    /// <exception cref="ArgumentNullException"><paramref name="asyncHandler"/> is <see langword="null"/></exception>
    public TestHttpMessageHandler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> asyncHandler)
    {
        ArgumentNullException.ThrowIfNull(asyncHandler);
        _asyncHandler = asyncHandler;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="TestHttpMessageHandler"/> class with a synchronous handler delegate.
    /// </summary>
    /// <param name="syncHandler">The delegate invoked on each request.</param>
    /// <exception cref="ArgumentNullException"><paramref name="syncHandler"/> is <see langword="null"/></exception>
    public TestHttpMessageHandler(Func<HttpRequestMessage, HttpResponseMessage> syncHandler)
    {
        ArgumentNullException.ThrowIfNull(syncHandler);
        _asyncHandler = (req, ct) =>
        {
            if (ct.IsCancellationRequested)
            {
                return Task.FromCanceled<HttpResponseMessage>(ct);
            }
            return Task.FromResult(syncHandler(req));
        };
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="TestHttpMessageHandler"/> class returning a constant string response and status code.
    /// </summary>
    /// <param name="responseContent">The string content to return.</param>
    /// <param name="statusCode">The HTTP status code (defaults to OK).</param>
    /// <param name="mediaType">The media type for the response content (defaults to "text/plain").</param>
    public TestHttpMessageHandler(string responseContent, HttpStatusCode statusCode = HttpStatusCode.OK, string mediaType = "text/plain")
    {
        _asyncHandler = (req, ct) =>
        {
            if (ct.IsCancellationRequested)
            {
                return Task.FromCanceled<HttpResponseMessage>(ct);
            }
            var response = new HttpResponseMessage(statusCode)
            {
                Content = new StringContent(responseContent, Encoding.UTF8, mediaType)
            };
            return Task.FromResult(response);
        };
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="TestHttpMessageHandler"/> class that throws a specified exception when invoked.
    /// </summary>
    /// <param name="exceptionToThrow">The exception to throw on send.</param>
    /// <exception cref="ArgumentNullException"><paramref name="exceptionToThrow"/> is <see langword="null"/></exception>
    public TestHttpMessageHandler(Exception exceptionToThrow)
    {
        ArgumentNullException.ThrowIfNull(exceptionToThrow);
        _asyncHandler = (req, ct) => Task.FromException<HttpResponseMessage>(exceptionToThrow);
    }

    /// <inheritdoc />
    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(IsDisposed, this);
        ArgumentNullException.ThrowIfNull(request);

        LastRequest = request;
        _requests.Add(request);

        return await _asyncHandler(request, cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    protected override void Dispose(bool disposing)
    {
        IsDisposed = true;
        base.Dispose(disposing);
    }
}
