using System.Globalization;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Layout;
using SimpleSign.Agent.Localization;
using SimpleSign.Agent.Server;
using SimpleSign.Agent.Services;

namespace SimpleSign.Agent.Views.Pages;

/// <summary>
/// The built-in end-to-end test: the window calls the agent over HTTP exactly as a web page does
/// (health, certificates, sign) and then verifies the signature. Each step shows the request, the
/// answer and the JavaScript that makes the same call.
/// </summary>
internal sealed class TestPage : AgentPage
{
    private readonly HashSet<int> _expanded = [];
    private SelfTestStep? _health;
    private SelfTestStep? _list;
    private IReadOnlyList<AgentCertificate> _certificates = [];
    private AgentCertificate? _selected;
    private SelfTestSignature? _signature;
    private int _running;

    public TestPage(MainWindow host)
        : base(host)
    {
    }

    protected override Control Build()
    {
        bool available = Controller.State == AgentState.Running;
        var run = Ui.Button(L.T(_health is null ? "test.run" : "test.runAgain"), Icons.Play, "primary", () => _ = RunAsync());
        run.IsEnabled = available && _running == 0;
        var column = Ui.Col(12,
            Ui.Split(
                Ui.Col(4, Ui.Text(L.T("test.title"), "h1"), Ui.Text(L.T("test.intro"), "muted wrap")),
                run.With(b => b.VerticalAlignment = VerticalAlignment.Top)));
        if (!available)
        {
            column.Children.Add(new Border { Child = Ui.Row(8, Ui.Icon(Icons.Alert, 15, "Warning"), Ui.Text(L.T("test.unavailable"), "wrap")) }.Class("well"));
        }

        string origin = $"http://127.0.0.1:{Port}";
        column.Children.Add(Step(1, L.T("test.health.title"), L.T("test.health.subtitle"), _health,
            _health is { Ok: true } ? L.T("test.health.ok") : null,
            $"const health = await (await fetch(\"{origin}/api/health\")).json();"));

        var pick = _list is { Ok: true } && _certificates.Count > 0 ? Picker() : null;
        column.Children.Add(Step(2, L.T("test.list.title"), L.T("test.list.subtitle"), _list,
            _list is { Ok: true } ? L.T(_certificates.Count == 0 ? "test.list.none" : "test.list.ok", _certificates.Count) : null,
            $"const certificates = await (await fetch(\"{origin}/api/certificates\")).json();",
            pick));

        column.Children.Add(Step(3, L.T("test.sign.title"), L.T("test.sign.subtitle"), _signature?.Step,
            _signature is { Step.Ok: true } ? L.T("test.sign.ok", _signature.SignatureBytes) : null,
            $$"""
            const [result] = await (await fetch("{{origin}}/api/sign", {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({
                thumbprint: certificates[0].thumbprint,
                hashAlgorithm: "SHA256",
                documentName: "contract.pdf",
                signRequests: [{ id: "1", authenticatedAttributeBase64 }]
              })
            })).json();
            """));

        column.Children.Add(Verification());
        return Ui.Page(column);
    }

    private int Port => Controller.Server.IsRunning ? Controller.Server.Port : Controller.Settings.AgentPort;

    private Control Picker()
    {
        var rows = Ui.Col(6);
        foreach (var certificate in _certificates)
        {
            string name = CommonName(certificate.Name);
            string details = string.Join(" · ", new[]
            {
                certificate.Source == "pkcs11" ? $"Token {certificate.TokenLabel}" : L.T("test.list.store"),
                certificate.SignatureAlgorithm,
                DateTime.TryParse(certificate.ExpireDate, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var expires)
                    ? L.T("cert.validUntil", expires.ToLocalTime().ToString("d", L.Culture))
                    : null,
            }.Where(s => !string.IsNullOrEmpty(s)));
            bool selected = ReferenceEquals(certificate, _selected);
            var row = new Button
            {
                Content = Ui.Split(
                    Ui.Row(10, Ui.Icon(Icons.Key, 15, "MutedFg"), Ui.Col(1, Ui.Text(name, "strong"), Ui.Text(details, "muted small"))),
                    selected ? Ui.Icon(Icons.CircleCheck, 16) : null),
            }.Class("row");
            row.Classes.Set("on", selected);
            row.IsEnabled = _running == 0;
            row.Click += (_, _) =>
            {
                _selected = certificate;
                _signature = null;
                Rebuild();
            };
            rows.Children.Add(row);
        }

        var sign = Ui.Button(L.T("test.sign.run"), Icons.Mark, "primary", () => _ = SignAsync());
        sign.IsEnabled = _selected is not null && _running == 0 && Controller.State == AgentState.Running;
        sign.HorizontalAlignment = HorizontalAlignment.Left;
        return Ui.Col(10, Ui.Text(L.T("test.list.pick"), "small muted"), rows, sign, Ui.Text(L.T("test.sign.hint"), "muted small wrap"));
    }

    private Border Verification()
    {
        var signature = _signature;
        string kind = signature is null || !signature.Step.Ok ? "" : signature.Verified ? "ok" : "err";
        var head = Head(4, L.T("test.verify.title"), L.T("test.verify.subtitle"), kind, running: false, null);
        if (signature is null || !signature.Step.Ok)
        {
            return Ui.Card(head);
        }

        return Ui.Card(Ui.Col(10, head, Ui.Text(L.T(signature.Verified ? "test.verify.ok" : "test.verify.failed"), signature.Verified ? "success wrap" : "destructive wrap")
            .With(t => t.Margin = new Thickness(40, 0, 0, 0))));
    }

    private Border Step(int number, string title, string subtitle, SelfTestStep? step, string? summary, string script, Control? extra = null)
    {
        bool running = _running == number;
        string kind = step is null ? "" : step.Ok ? "ok" : "err";
        string? badge = step is null ? null : $"{(step.Status == 0 ? "—" : step.Status.ToString(CultureInfo.InvariantCulture))} · {step.Elapsed.TotalMilliseconds.ToString("0", L.Culture)} ms";
        var column = Ui.Col(10, Head(number, title, subtitle, kind, running, badge));
        var body = Ui.Col(10);
        body.Margin = new Thickness(40, 0, 0, 0);
        if (step is { Ok: false })
        {
            body.Children.Add(Ui.Text(step.Error ?? L.T("test.failed", step.Status), "destructive wrap"));
        }
        else if (summary is not null)
        {
            body.Children.Add(Ui.Text(summary, "wrap"));
        }

        if (extra is not null)
        {
            body.Children.Add(extra);
        }

        bool open = _expanded.Contains(number);
        var toggle = new Button
        {
            Content = Ui.Row(4, Ui.Icon(open ? Icons.ChevronDown : Icons.ChevronRight, 13), Ui.Text(L.T(open ? "test.details.hide" : "test.details.show"), "small")),
            HorizontalAlignment = HorizontalAlignment.Left,
        }.Class("link");
        toggle.Click += (_, _) =>
        {
            if (!_expanded.Remove(number))
            {
                _expanded.Add(number);
            }

            Rebuild();
        };
        body.Children.Add(toggle);
        if (open)
        {
            if (step is not null)
            {
                string request = $"{step.Method} {step.Url}" + (step.RequestBody is null ? "" : "\n\n" + SelfTest.Pretty(step.RequestBody));
                body.Children.Add(Labeled(L.T("test.details.request"), Ui.Code(request, 200)));
                body.Children.Add(Labeled(L.T("test.details.response"), Ui.Code($"HTTP {step.Status}\n\n{SelfTest.Pretty(step.ResponseBody)}", 220)));
            }

            body.Children.Add(Labeled(L.T("test.details.script"), Ui.Code(script, 220)));
        }

        column.Children.Add(body);
        return Ui.Card(column);
    }

    private static Control Labeled(string label, Control content) => Ui.Col(4, Ui.Text(label, "xs muted strong"), content);

    private static Grid Head(int number, string title, string subtitle, string kind, bool running, string? badge)
    {
        Control marker = running ? Ui.Icon(Icons.Clock, 16, "Info")
            : kind == "ok" ? Ui.Icon(Icons.CircleCheck, 16, "Success")
            : kind == "err" ? Ui.Icon(Icons.CircleX, 16, "Destructive")
            : Ui.Text(number.ToString(CultureInfo.InvariantCulture), "small muted strong").With(t => t.HorizontalAlignment = HorizontalAlignment.Center);
        var box = new Border { Width = 28, Height = 28, CornerRadius = new CornerRadius(14), Child = marker }.Class("iconbox " + (running ? "info" : kind));
        marker.HorizontalAlignment = HorizontalAlignment.Center;
        marker.VerticalAlignment = VerticalAlignment.Center;
        return Ui.Split(
            Ui.Row(12, box, Ui.Col(1, Ui.Text(title, "h3"), Ui.Text(subtitle, "muted small mono"))),
            running ? Ui.Badge(L.T("test.running"), "solid") : badge is null ? null : Ui.Badge(badge, kind == "err" ? "err" : ""));
    }

    private async Task RunAsync()
    {
        _health = null;
        _list = null;
        _certificates = [];
        _selected = null;
        _signature = null;
        using var test = new SelfTest(Port);
        try
        {
            _running = 1;
            Rebuild();
            _health = await test.HealthAsync(Host.Lifetime);
            if (_health.Ok)
            {
                _running = 2;
                Rebuild();
                (_list, _certificates) = await test.CertificatesAsync(Host.Lifetime);
                _selected = _certificates.FirstOrDefault();
            }
        }
        catch (OperationCanceledException)
        {
            return;
        }

        _running = 0;
        Rebuild();
    }

    private async Task SignAsync()
    {
        if (_selected is not { } certificate)
        {
            return;
        }

        using var test = new SelfTest(Port);
        try
        {
            _running = 3;
            _signature = null;
            Rebuild();
            _signature = await test.SignAsync(certificate, Host.Lifetime);
        }
        catch (OperationCanceledException)
        {
            return;
        }

        _running = 0;
        Rebuild();
    }

    /// <summary>The CN of a distinguished name ("CN=Fulano, O=…" → "Fulano").</summary>
    private static string CommonName(string? subject)
    {
        if (string.IsNullOrEmpty(subject))
        {
            return "";
        }

        try
        {
            var name = new System.Security.Cryptography.X509Certificates.X500DistinguishedName(subject);
            foreach (var part in name.EnumerateRelativeDistinguishedNames())
            {
                if (part.GetSingleElementType().Value == "2.5.4.3")
                {
                    return part.GetSingleElementValue() ?? subject;
                }
            }
        }
        catch (System.Security.Cryptography.CryptographicException)
        {
            // Not a parseable name: show it as it came.
        }

        return subject;
    }
}
