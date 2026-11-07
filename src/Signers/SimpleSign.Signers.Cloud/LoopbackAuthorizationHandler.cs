using System.Diagnostics;
using System.Net;
using System.Text;

namespace SimpleSign.Signers.Cloud;

/// <summary>
/// Completes an OAuth 2.0 authorization in the user's browser for desktop and CLI apps: listens
/// on a loopback redirect URI (e.g. <c>http://127.0.0.1:43821/callback</c>), opens the
/// authorization page and returns when the service redirects back (RFC 8252 §7.3).
/// </summary>
public sealed class LoopbackAuthorizationHandler : IAuthorizationCodeHandler
{
    private readonly Action<Uri> _openBrowser;
    private readonly TimeSpan _timeout;

    /// <summary>Creates a handler.</summary>
    /// <param name="openBrowser">
    /// Opens the authorization page. Default: the system browser. Pass your own to show the URL
    /// instead (e.g. print it in a terminal without a browser).
    /// </param>
    /// <param name="timeout">How long to wait for the user. Default: 5 minutes.</param>
    public LoopbackAuthorizationHandler(Action<Uri>? openBrowser = null, TimeSpan? timeout = null)
    {
        _openBrowser = openBrowser ?? OpenInSystemBrowser;
        _timeout = timeout ?? TimeSpan.FromMinutes(5);
    }

    /// <inheritdoc />
    /// <exception cref="ArgumentException"><paramref name="redirectUri"/> is not an <c>http</c> loopback URI.</exception>
    /// <exception cref="TimeoutException">The user did not finish in time.</exception>
    public async ValueTask<Uri> AuthorizeAsync(Uri authorizationUri, Uri redirectUri, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(authorizationUri);
        ArgumentNullException.ThrowIfNull(redirectUri);
        if (redirectUri.Scheme != Uri.UriSchemeHttp || !redirectUri.IsLoopback)
        {
            throw new ArgumentException("The redirect URI must be an http loopback URI such as http://127.0.0.1:43821/callback.", nameof(redirectUri));
        }

        using var listener = new HttpListener();
        listener.Prefixes.Add($"{redirectUri.Scheme}://{redirectUri.Authority}{DirectoryOf(redirectUri.AbsolutePath)}");
        listener.Start();
        try
        {
            _openBrowser(authorizationUri);

            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(_timeout);
            while (true)
            {
                var contextTask = listener.GetContextAsync();
                var finished = await Task.WhenAny(contextTask, Task.Delay(Timeout.Infinite, timeout.Token)).ConfigureAwait(false);
                if (finished != contextTask)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    throw new TimeoutException("The authorization was not completed in time.");
                }

                var context = await contextTask.ConfigureAwait(false);
                if (!string.Equals(context.Request.Url?.AbsolutePath, redirectUri.AbsolutePath, StringComparison.Ordinal))
                {
                    context.Response.StatusCode = (int)HttpStatusCode.NotFound;
                    context.Response.Close();
                    continue;
                }

                await RespondAsync(context.Response).ConfigureAwait(false);
                return context.Request.Url!;
            }
        }
        finally
        {
            listener.Stop();
        }
    }

    private static string DirectoryOf(string path)
    {
        int slash = path.LastIndexOf('/');
        return slash <= 0 ? "/" : path[..(slash + 1)];
    }

    private static async Task RespondAsync(HttpListenerResponse response)
    {
        byte[] body = Encoding.UTF8.GetBytes(
            "<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>SimpleSign</title></head>" +
            "<body style=\"font-family:sans-serif\"><p>Authorization received. You can close this window.</p>" +
            "<p>Autorização recebida. Você já pode fechar esta janela.</p></body></html>");
        response.ContentType = "text/html; charset=utf-8";
        response.ContentLength64 = body.Length;
        await response.OutputStream.WriteAsync(body).ConfigureAwait(false);
        response.Close();
    }

    /// <summary>Opens <paramref name="uri"/> in the system's default browser.</summary>
    /// <param name="uri">The page to open: an absolute http or https URL.</param>
    /// <exception cref="ArgumentException"><paramref name="uri"/> is not an absolute http(s) URL (the shell would open other schemes, such as file:, with other programs).</exception>
    public static void OpenInSystemBrowser(Uri uri)
    {
        ArgumentNullException.ThrowIfNull(uri);
        if (!uri.IsAbsoluteUri || (uri.Scheme != Uri.UriSchemeHttps && uri.Scheme != Uri.UriSchemeHttp))
        {
            throw new ArgumentException("Only absolute http(s) URLs are opened in the browser.", nameof(uri));
        }

        // A fixed program with the URL as its one argument, never the URL as the program to run
        // (explorer.exe opens a URL in the default browser, as open and xdg-open do).
        string program = OperatingSystem.IsWindows() ? "explorer.exe" : OperatingSystem.IsMacOS() ? "open" : "xdg-open";
        var start = new ProcessStartInfo(program) { UseShellExecute = false };
        start.ArgumentList.Add(uri.AbsoluteUri);

        using var process = Process.Start(start);
    }
}
