using System.Net;
using System.Net.Sockets;

namespace SimpleSign.Cli.Tests;

/// <summary>
/// Serves an in-process <see cref="HttpMessageHandler"/> (a PSC or CSC simulator) on a real
/// loopback port, for CLI commands that create their own <see cref="HttpClient"/>.
/// </summary>
public sealed class LoopbackHttpServer : IDisposable
{
    private readonly HttpListener _listener = new();
    private readonly HttpMessageInvoker _invoker;
    private readonly CancellationTokenSource _stop = new();
    private readonly Task _loop;

    public LoopbackHttpServer(HttpMessageHandler handler)
    {
        _invoker = new HttpMessageInvoker(handler, disposeHandler: false);
        using (var probe = new TcpListener(IPAddress.Loopback, 0))
        {
            probe.Start();
            BaseUri = new Uri($"http://127.0.0.1:{((IPEndPoint)probe.LocalEndpoint).Port}/");
        }

        _listener.Prefixes.Add(BaseUri.AbsoluteUri);
        _listener.Start();
        _loop = Task.Run(LoopAsync);
    }

    public Uri BaseUri { get; }

    public void Dispose()
    {
        _stop.Cancel();
        _listener.Stop();
        try
        {
            _loop.Wait(TimeSpan.FromSeconds(2));
        }
        catch (AggregateException)
        {
            // The loop ends with the listener.
        }

        _listener.Close();
        _invoker.Dispose();
        _stop.Dispose();
    }

    private async Task LoopAsync()
    {
        while (!_stop.IsCancellationRequested)
        {
            HttpListenerContext context;
            try
            {
                context = await _listener.GetContextAsync();
            }
            catch (Exception) when (_stop.IsCancellationRequested)
            {
                return;
            }

            using var request = new HttpRequestMessage(new HttpMethod(context.Request.HttpMethod), context.Request.Url);
            if (context.Request.Headers["Authorization"] is { } authorization)
            {
                request.Headers.TryAddWithoutValidation("Authorization", authorization);
            }

            if (context.Request.HasEntityBody)
            {
                using var body = new MemoryStream();
                await context.Request.InputStream.CopyToAsync(body);
                request.Content = new ByteArrayContent(body.ToArray());
                if (context.Request.ContentType is { } contentType)
                {
                    request.Content.Headers.TryAddWithoutValidation("Content-Type", contentType);
                }
            }

            using var response = await _invoker.SendAsync(request, CancellationToken.None);
            byte[] payload = await response.Content.ReadAsByteArrayAsync();
            context.Response.StatusCode = (int)response.StatusCode;
            context.Response.ContentType = response.Content.Headers.ContentType?.ToString();
            await context.Response.OutputStream.WriteAsync(payload);
            context.Response.Close();
        }
    }
}
