using System.Net;
using System.Net.Http;
using System.Text.Json;

namespace SimpleSign.HostSigner;

internal sealed class TrayContext : ApplicationContext
{
    internal const int Port = 21590;
    internal const string Version = "0.2.0";
    private const string GitHubRepo = "eupassarin/SimpleSign";

    private readonly NotifyIcon _tray;
    private readonly HttpListener _listener;
    private readonly CancellationTokenSource _cts = new();
    private readonly MainForm _form;

    public TrayContext()
    {
        _form = new MainForm();
        _form.Log($"SimpleSign HostSigner v{Version}");

        _tray = new NotifyIcon
        {
            Icon = LoadIcon(),
            Text = $"SimpleSign HostSigner v{Version}",
            Visible = true,
            ContextMenuStrip = BuildMenu(),
        };
        _tray.DoubleClick += (_, _) => ShowMainForm();

        _listener = new HttpListener();
        _listener.Prefixes.Add($"http://127.0.0.1:{Port}/");
        _listener.Prefixes.Add($"http://localhost:{Port}/");

        try
        {
            _listener.Start();
            _form.Log($"Listening on http://localhost:{Port}");
            _ = ListenLoopAsync(_cts.Token);
        }
        catch (HttpListenerException ex)
        {
            _form.Log($"ERROR: Could not start listener — {ex.Message}");
            MessageBox.Show(
                $"Could not bind to port {Port}.\n\n{ex.Message}",
                "SimpleSign HostSigner",
                MessageBoxButtons.OK,
                MessageBoxIcon.Error);
        }

        _ = CheckForUpdatesAsync();
    }

    private static Icon LoadIcon()
    {
        // Try embedded PNG resource → convert to Icon
        using var stream = typeof(TrayContext).Assembly.GetManifestResourceStream("SimpleSign.HostSigner.icon.png");
        if (stream is not null)
        {
            using var bmp = new Bitmap(stream);
            return Icon.FromHandle(bmp.GetHicon());
        }

        // Fallback: extract from exe
        var exePath = Environment.ProcessPath;
        if (exePath is not null)
        {
            try
            {
                var icon = Icon.ExtractAssociatedIcon(exePath);
                if (icon is not null)
                    return icon;
            }
            catch { /* fall through */ }
        }

        return SystemIcons.Shield;
    }

    private ContextMenuStrip BuildMenu()
    {
        var menu = new ContextMenuStrip();
        menu.Items.Add("Open", null, (_, _) => ShowMainForm());
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add("Exit", null, (_, _) => Exit());
        return menu;
    }

    private void ShowMainForm()
    {
        _form.RefreshCertificates();
        _form.Show();
        _form.BringToFront();
        if (_form.WindowState == FormWindowState.Minimized)
        {
            _form.WindowState = FormWindowState.Normal;
        }
    }

    private void Exit()
    {
        _cts.Cancel();
        _tray.Visible = false;
        _tray.Dispose();
        try
        { _listener.Stop(); }
        catch { /* shutting down */ }
        Application.Exit();
    }

    private async Task ListenLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            HttpListenerContext ctx;
            try
            {
                ctx = await _listener.GetContextAsync().WaitAsync(ct);
            }
            catch (OperationCanceledException) { break; }
            catch (HttpListenerException) { break; }

            _ = Task.Run(() => HandleRequestAsync(ctx), ct);
        }
    }

    private async Task HandleRequestAsync(HttpListenerContext ctx)
    {
        var req = ctx.Request;
        var resp = ctx.Response;

        // CORS
        var origin = req.Headers["Origin"];
        var allowedOrigin = IsAllowedOrigin(origin) ? origin : $"http://localhost:{Port}";
        resp.Headers.Add("Access-Control-Allow-Origin", allowedOrigin);
        resp.Headers.Add("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
        resp.Headers.Add("Access-Control-Allow-Headers", "Content-Type");

        if (req.HttpMethod == "OPTIONS")
        {
            resp.StatusCode = 204;
            resp.Close();
            return;
        }

        try
        {
            var path = req.Url?.AbsolutePath ?? "";

            // API routes
            if (path.Equals("/api/certificates", StringComparison.OrdinalIgnoreCase) && req.HttpMethod == "GET")
            {
                await HandleGetCertificatesAsync(req, resp);
            }
            else if (path.Equals("/api/sign", StringComparison.OrdinalIgnoreCase) && req.HttpMethod == "POST")
            {
                await HandleSignAsync(req, resp);
            }
            else if (path.Equals("/api/sign-file", StringComparison.OrdinalIgnoreCase) && req.HttpMethod == "POST")
            {
                await HandleSignFileAsync(req, resp);
            }
            else if (path.Equals("/api/inspect", StringComparison.OrdinalIgnoreCase) && req.HttpMethod == "POST")
            {
                await HandleInspectAsync(req, resp);
            }
            else if (path.Equals("/api/validate", StringComparison.OrdinalIgnoreCase) && req.HttpMethod == "POST")
            {
                await HandleValidateAsync(req, resp);
            }
            else if (path.Equals("/api/health", StringComparison.OrdinalIgnoreCase) && req.HttpMethod == "GET")
            {
                await WriteJsonAsync(resp, new HealthResponse { Status = "ok", Version = Version });
            }
            else if (path.Equals("/api/version", StringComparison.OrdinalIgnoreCase) && req.HttpMethod == "GET")
            {
                await HandleVersionCheckAsync(resp);
            }
            // Static file serving for WebView2 SPA
            else if (req.HttpMethod == "GET")
            {
                await ServeStaticFileAsync(path, resp);
            }
            else
            {
                resp.StatusCode = 404;
                await WriteJsonAsync(resp, new ErrorResponse { Error = "Not found" });
            }
        }
        catch (Exception ex)
        {
            _form.Log($"ERROR: {ex.Message}");
            resp.StatusCode = 500;
            try
            { await WriteJsonAsync(resp, new ErrorResponse { Error = "An internal error occurred. Check HostSigner logs for details." }); }
            catch { resp.Close(); }
        }
    }

    private async Task HandleGetCertificatesAsync(HttpListenerRequest req, HttpListenerResponse resp)
    {
        var filter = req.QueryString["filterIcpBrasil"];
        var filterIcp = string.Equals(filter, "true", StringComparison.OrdinalIgnoreCase);

        _form.Log($"GET /api/certificates (filterIcpBrasil={filterIcp})");

        var certs = CertificateService.ListSigningCertificates(filterIcp);
        _form.Log($"  → {certs.Count} certificate(s) found");

        await WriteJsonAsync(resp, certs);
    }

    private async Task HandleSignAsync(HttpListenerRequest req, HttpListenerResponse resp)
    {
        using var reader = new StreamReader(req.InputStream, req.ContentEncoding);
        var body = await reader.ReadToEndAsync();
        var request = JsonSerializer.Deserialize(body, HostSignerJsonContext.Default.SignRequest);

        if (request is null || string.IsNullOrEmpty(request.Thumbprint))
        {
            resp.StatusCode = 400;
            await WriteJsonAsync(resp, new ErrorResponse { Error = "Thumbprint is required" });
            return;
        }

        _form.Log($"POST /api/sign (thumbprint={request.Thumbprint[..8]}…, {request.SignRequests?.Count ?? 0} hash(es))");

        var results = CertificateService.SignHashes(request);
        var errors = results.Where(r => r.Error is not null).ToList();

        _form.Log(errors.Count > 0
            ? $"  → {results.Count - errors.Count} signed, {errors.Count} error(s)"
            : $"  → {results.Count} signed OK");

        await WriteJsonAsync(resp, results);
    }

    private async Task HandleVersionCheckAsync(HttpListenerResponse resp)
    {
        var info = await GetLatestVersionAsync();
        await WriteJsonAsync(resp, info);
    }

    private async Task<VersionInfo> GetLatestVersionAsync()
    {
        var info = new VersionInfo { Current = Version };
        try
        {
            using var http = new HttpClient();
            http.DefaultRequestHeaders.Add("User-Agent", $"SimpleSign-HostSigner/{Version}");
            http.Timeout = TimeSpan.FromSeconds(10);

            var url = $"https://api.github.com/repos/{GitHubRepo}/releases/latest";
            var json = await http.GetStringAsync(url);

            // Parse tag_name from response (lightweight, no full JSON model)
            using var doc = JsonDocument.Parse(json);
            if (doc.RootElement.TryGetProperty("tag_name", out var tag))
            {
                var latest = tag.GetString()?.TrimStart('v') ?? Version;
                info.Latest = latest;
                info.UpdateAvailable = CompareVersions(latest, Version) > 0;
                if (info.UpdateAvailable && doc.RootElement.TryGetProperty("html_url", out var htmlUrl))
                {
                    info.DownloadUrl = htmlUrl.GetString();
                }
            }
        }
        catch (Exception ex)
        {
            _form.Log($"Version check failed: {ex.Message}");
            info.Latest = Version;
        }

        return info;
    }

    private async Task CheckForUpdatesAsync()
    {
        try
        {
            await Task.Delay(3000);
            var info = await GetLatestVersionAsync();
            if (info.UpdateAvailable)
            {
                _form.Log($"Update available: v{info.Latest} (current: v{info.Current})");
                _tray.ShowBalloonTip(
                    5000,
                    "SimpleSign Update Available",
                    $"Version {info.Latest} is available (you have {info.Current}).\nDouble-click the tray icon for details.",
                    ToolTipIcon.Info);
                _form.SetUpdateAvailable(info.Latest!, info.DownloadUrl);
            }
            else
            {
                _form.Log("Version is up to date");
            }
        }
        catch { /* non-critical */ }
    }

    private static int CompareVersions(string a, string b)
    {
        static int[] Parse(string v) => v.Split(['.', '-'], StringSplitOptions.RemoveEmptyEntries)
            .Select(p => int.TryParse(p, out var n) ? n : 0).ToArray();
        var pa = Parse(a);
        var pb = Parse(b);
        for (int i = 0; i < Math.Max(pa.Length, pb.Length); i++)
        {
            var va = i < pa.Length ? pa[i] : 0;
            var vb = i < pb.Length ? pb[i] : 0;
            if (va != vb)
                return va.CompareTo(vb);
        }
        return 0;
    }

    private static async Task ServeStaticFileAsync(string path, HttpListenerResponse resp)
    {
        if (path == "/")
            path = "/index.html";
        var resourceName = "SimpleSign.HostSigner.wwwroot" + path.Replace('/', '.');

        using var stream = typeof(TrayContext).Assembly.GetManifestResourceStream(resourceName);
        if (stream is null)
        {
            resp.StatusCode = 404;
            resp.Close();
            return;
        }

        resp.ContentType = path switch
        {
            _ when path.EndsWith(".html") => "text/html; charset=utf-8",
            _ when path.EndsWith(".js") => "application/javascript; charset=utf-8",
            _ when path.EndsWith(".css") => "text/css; charset=utf-8",
            _ when path.EndsWith(".json") => "application/json; charset=utf-8",
            _ when path.EndsWith(".svg") => "image/svg+xml",
            _ when path.EndsWith(".png") => "image/png",
            _ => "application/octet-stream"
        };

        resp.ContentLength64 = stream.Length;
        await stream.CopyToAsync(resp.OutputStream);
        resp.Close();
    }

    private async Task HandleSignFileAsync(HttpListenerRequest req, HttpListenerResponse resp)
    {
        using var reader = new StreamReader(req.InputStream, req.ContentEncoding);
        var body = await reader.ReadToEndAsync();
        using var doc = JsonDocument.Parse(body);
        var root = doc.RootElement;

        var filePath = root.GetProperty("filePath").GetString();
        var thumbprint = root.GetProperty("thumbprint").GetString();

        if (string.IsNullOrEmpty(filePath) || string.IsNullOrEmpty(thumbprint))
        {
            resp.StatusCode = 400;
            await WriteJsonAsync(resp, new ErrorResponse { Error = "filePath and thumbprint are required" });
            return;
        }

        if (!ValidateFilePath(filePath, out var pathError))
        {
            resp.StatusCode = 400;
            await WriteJsonAsync(resp, new ErrorResponse { Error = pathError });
            return;
        }

        _form.Log($"POST /api/sign-file ({Path.GetFileName(filePath)})");

        var options = new Services.SignFileOptions(
            FilePath: filePath,
            Thumbprint: thumbprint,
            TsaUrl: root.TryGetProperty("tsaUrl", out var tsa) ? tsa.GetString() : null,
            Reason: root.TryGetProperty("reason", out var r) ? r.GetString() : null,
            Location: root.TryGetProperty("location", out var l) ? l.GetString() : null,
            SignerName: root.TryGetProperty("signerName", out var sn) ? sn.GetString() : null,
            ContactInfo: root.TryGetProperty("contactInfo", out var ci) ? ci.GetString() : null,
            FieldName: root.TryGetProperty("fieldName", out var fn) ? fn.GetString() : null,
            HashAlgorithm: root.TryGetProperty("hashAlgorithm", out var ha) ? ha.GetString() ?? "SHA-256" : "SHA-256",
            EnableLtv: root.TryGetProperty("enableLtv", out var ltv) && ltv.GetBoolean(),
            PreservePdfA: root.TryGetProperty("preservePdfA", out var pdfa) && pdfa.GetBoolean(),
            ArchivalTimestamp: root.TryGetProperty("archivalTimestamp", out var arch) && arch.GetBoolean(),
            CertificationLevel: root.TryGetProperty("certificationLevel", out var docmdp) ? docmdp.GetString() ?? "none" : "none",
            VisibleStamp: root.TryGetProperty("visibleStamp", out var vs) && vs.GetBoolean()
        );

        try
        {
            var outputPath = await Services.SigningService.SignPdfAsync(options);
            _form.Log($"  → Signed: {Path.GetFileName(outputPath)}");
            await WriteJsonAsync(resp, new SignFileResponse { OutputPath = outputPath });
        }
        catch (Exception ex)
        {
            _form.Log($"ERROR sign-file: {ex.Message}");
            resp.StatusCode = 500;
            await WriteJsonAsync(resp, new ErrorResponse { Error = "Signing failed. Check HostSigner logs for details." });
        }
    }

    private async Task HandleInspectAsync(HttpListenerRequest req, HttpListenerResponse resp)
    {
        using var reader = new StreamReader(req.InputStream, req.ContentEncoding);
        var body = await reader.ReadToEndAsync();
        using var doc = JsonDocument.Parse(body);
        var filePath = doc.RootElement.GetProperty("filePath").GetString();

        if (string.IsNullOrEmpty(filePath))
        {
            resp.StatusCode = 400;
            await WriteJsonAsync(resp, new ErrorResponse { Error = "filePath is required" });
            return;
        }

        if (!ValidateFilePath(filePath, out var pathError))
        {
            resp.StatusCode = 400;
            await WriteJsonAsync(resp, new ErrorResponse { Error = pathError });
            return;
        }

        _form.Log($"POST /api/inspect ({Path.GetFileName(filePath)})");

        try
        {
            var result = await Services.InspectionService.InspectAsync(filePath);
            await WriteJsonAsync(resp, result);
        }
        catch (Exception ex)
        {
            _form.Log($"ERROR inspect: {ex.Message}");
            resp.StatusCode = 500;
            await WriteJsonAsync(resp, new ErrorResponse { Error = "Inspection failed. Check HostSigner logs for details." });
        }
    }

    private async Task HandleValidateAsync(HttpListenerRequest req, HttpListenerResponse resp)
    {
        using var reader = new StreamReader(req.InputStream, req.ContentEncoding);
        var body = await reader.ReadToEndAsync();
        using var doc = JsonDocument.Parse(body);
        var filePath = doc.RootElement.GetProperty("filePath").GetString();

        if (string.IsNullOrEmpty(filePath))
        {
            resp.StatusCode = 400;
            await WriteJsonAsync(resp, new ErrorResponse { Error = "filePath is required" });
            return;
        }

        if (!ValidateFilePath(filePath, out var pathError))
        {
            resp.StatusCode = 400;
            await WriteJsonAsync(resp, new ErrorResponse { Error = pathError });
            return;
        }

        _form.Log($"POST /api/validate ({Path.GetFileName(filePath)})");

        try
        {
            var results = await Services.ValidationService.ValidateAsync(filePath);
            await WriteJsonAsync(resp, results);
        }
        catch (Exception ex)
        {
            _form.Log($"ERROR validate: {ex.Message}");
            resp.StatusCode = 500;
            await WriteJsonAsync(resp, new ErrorResponse { Error = "Validation failed. Check HostSigner logs for details." });
        }
    }

    private static async Task WriteJsonAsync<T>(HttpListenerResponse resp, T data)
    {
        resp.ContentType = "application/json; charset=utf-8";
        var json = JsonSerializer.SerializeToUtf8Bytes(data, HostSignerJsonContext.Default.Options);
        resp.ContentLength64 = json.Length;
        await resp.OutputStream.WriteAsync(json);
        resp.Close();
    }

    /// <summary>
    /// Validates that a file path is absolute, exists, ends with .pdf, and does not traverse outside user-accessible directories.
    /// </summary>
    private static bool ValidateFilePath(string filePath, out string error)
    {
        error = string.Empty;

        if (!Path.IsPathFullyQualified(filePath))
        {
            error = "File path must be absolute.";
            return false;
        }

        // Resolve to canonical form to prevent path traversal (e.g., ..\..\)
        var fullPath = Path.GetFullPath(filePath);
        if (!fullPath.Equals(filePath, StringComparison.OrdinalIgnoreCase) &&
            !fullPath.Equals(filePath.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar), StringComparison.OrdinalIgnoreCase))
        {
            error = "File path contains invalid traversal sequences.";
            return false;
        }

        if (!fullPath.EndsWith(".pdf", StringComparison.OrdinalIgnoreCase))
        {
            error = "Only PDF files are supported.";
            return false;
        }

        if (!File.Exists(fullPath))
        {
            error = "File not found.";
            return false;
        }

        return true;
    }

    /// <summary>
    /// Checks if the Origin header is from an allowed localhost address.
    /// </summary>
    private static bool IsAllowedOrigin(string? origin)
    {
        if (string.IsNullOrEmpty(origin))
            return false;
        return origin.StartsWith($"http://localhost:{Port}", StringComparison.OrdinalIgnoreCase)
            || origin.StartsWith($"http://127.0.0.1:{Port}", StringComparison.OrdinalIgnoreCase)
            || origin.StartsWith($"http://localhost:", StringComparison.OrdinalIgnoreCase)
            || origin.StartsWith($"http://127.0.0.1:", StringComparison.OrdinalIgnoreCase);
    }
}
