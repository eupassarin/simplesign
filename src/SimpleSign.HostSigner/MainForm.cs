using System.Runtime.InteropServices;
using System.Text.Json;
using Microsoft.Web.WebView2.WinForms;

namespace SimpleSign.HostSigner;

internal sealed class MainForm : Form
{
    private readonly WebView2 _webView;

    public MainForm()
    {
        Text = "SimpleSign";
        Size = new Size(930, 550);
        StartPosition = FormStartPosition.CenterScreen;
        MinimumSize = new Size(800, 500);
        BackColor = Color.FromArgb(9, 9, 11);
        ShowInTaskbar = false;

        EnableDarkTitleBar();

        using var iconStream = typeof(TrayContext).Assembly.GetManifestResourceStream("SimpleSign.HostSigner.icon.png");
        if (iconStream is not null)
        {
            using var bmp = new Bitmap(iconStream);
            Icon = Icon.FromHandle(bmp.GetHicon());
        }

        _webView = new WebView2 { Dock = DockStyle.Fill };
        Controls.Add(_webView);

        Load += async (_, _) => await InitWebViewAsync();

        FormClosing += (_, e) =>
        {
            if (e.CloseReason == CloseReason.UserClosing)
            { e.Cancel = true; Hide(); }
        };
    }

    private async Task InitWebViewAsync()
    {
        await _webView.EnsureCoreWebView2Async();

        // Dark background while loading
        _webView.DefaultBackgroundColor = Color.FromArgb(9, 9, 11);

        // Handle messages from JS
        _webView.CoreWebView2.WebMessageReceived += (_, args) =>
        {
            try
            {
                var msg = JsonSerializer.Deserialize<JsonElement>(args.WebMessageAsJson);
                var action = msg.GetProperty("action").GetString();
                switch (action)
                {
                    case "browseFiles":
                        BrowseFiles();
                        break;
                    case "browseInspect":
                        BrowseForPage("inspectFile");
                        break;
                    case "browseValidate":
                        BrowseForPage("validateFile");
                        break;
                    case "openUrl":
                        var url = msg.GetProperty("url").GetString();
                        if (url is not null)
                            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(url) { UseShellExecute = true });
                        break;
                }
            }
            catch { /* ignore malformed messages */ }
        };

        // Send host info
        var hostInfo = JsonSerializer.Serialize(new
        {
            action = "hostInfo",
            pid = Environment.ProcessId,
            runtime = Environment.Version.ToString()
        });
        _webView.CoreWebView2.PostWebMessageAsJson(hostInfo);

        // Navigate to our SPA served by the HTTP listener
        _webView.CoreWebView2.Navigate($"http://localhost:{TrayContext.Port}/");
    }

    private void BrowseFiles()
    {
        if (InvokeRequired)
        { Invoke(BrowseFiles); return; }
        using var ofd = new OpenFileDialog { Filter = "PDF Files|*.pdf", Multiselect = true, Title = "Select PDF files" };
        if (ofd.ShowDialog() == DialogResult.OK)
        {
            var json = JsonSerializer.Serialize(new { action = "filesSelected", files = ofd.FileNames });
            _webView.CoreWebView2.PostWebMessageAsJson(json);
        }
    }

    private void BrowseForPage(string messageAction)
    {
        if (InvokeRequired)
        { Invoke(() => BrowseForPage(messageAction)); return; }
        using var ofd = new OpenFileDialog { Filter = "PDF Files|*.pdf", Title = "Select a PDF file" };
        if (ofd.ShowDialog() == DialogResult.OK)
        {
            var json = JsonSerializer.Serialize(new { action = messageAction, file = ofd.FileName });
            _webView.CoreWebView2.PostWebMessageAsJson(json);
        }
    }

    public void Log(string message)
    {
        if (_webView?.CoreWebView2 is null)
            return;
        try
        {
            var json = JsonSerializer.Serialize(new { action = "log", message });
            if (InvokeRequired)
                BeginInvoke(() => _webView.CoreWebView2?.PostWebMessageAsJson(json));
            else
                _webView.CoreWebView2.PostWebMessageAsJson(json);
        }
        catch { /* not yet initialized */ }
    }

    public void SetUpdateAvailable(string latestVersion, string? downloadUrl) => Log($"Update available: v{latestVersion}");
    public void RefreshCertificates() { /* Frontend handles refresh via API */ }

    private void EnableDarkTitleBar()
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            return;
        try
        {
            int value = 1;
            DwmSetWindowAttribute(Handle, 20, ref value, sizeof(int));
        }
        catch { }
    }

    [DllImport("dwmapi.dll", PreserveSig = true)]
    private static extern int DwmSetWindowAttribute(IntPtr hwnd, int attribute, ref int pvAttribute, int cbAttribute);
}
