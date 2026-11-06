using Avalonia;
using Avalonia.Controls;
using Avalonia.Layout;
using SimpleSign.Agent.Localization;
using SimpleSign.Agent.Services;

namespace SimpleSign.Agent.Views.Pages;

/// <summary>The agent's state, a few counts and the certificates it can sign with.</summary>
internal sealed class OverviewPage : AgentPage
{
    public OverviewPage(MainWindow host)
        : base(host)
    {
    }

    public override void OnActivity(LogEntry? entry) => Rebuild();

    protected override Control Build() => Ui.Page(Ui.Col(16, Hero(), Counts(), Certificates()));

    private Border Hero()
    {
        var state = Controller.State;
        string key = state.ToString().ToLowerInvariant();
        var (icon, kind, brush) = state switch
        {
            AgentState.Running => (Icons.Radio, "ok", "Success"),
            AgentState.Error => (Icons.Alert, "err", "Destructive"),
            _ => (Icons.Pause, "warn", "Warning"),
        };
        string detail = state switch
        {
            AgentState.Running => L.T("overview.running.detail", Controller.Address),
            AgentState.Error => Controller.Server.LastError ?? L.T("status.error"),
            _ => L.T("overview.paused.detail"),
        };
        var toggle = Ui.Switch(Controller.Settings.AgentEnabled, on => _ = Controller.SetEnabledAsync(on)).Tip(L.T("settings.enabled"));
        var head = Ui.Split(
            Ui.Row(14, Ui.IconBox(icon, kind, brush), Ui.Col(2, Ui.Text(L.T($"overview.{key}.title"), "h2"), Ui.Text(detail, "muted small wrap"))),
            toggle);
        if (state != AgentState.Error)
        {
            return Ui.Card(head);
        }

        var actions = Ui.Row(8,
            Ui.Button(L.T("overview.retry"), Icons.Refresh, "outline sm", () => _ = Controller.StartAsync()),
            Ui.Button(L.T("overview.changePort"), Icons.Settings, "sm", () => Host.OpenSheet(MainWindow.SettingsSheet)));
        actions.Margin = new Thickness(50, 0, 0, 0);
        return Ui.Card(Ui.Col(12, head, actions));
    }

    private Grid Counts()
    {
        var settings = Controller.Settings;
        var grid = new Grid { ColumnDefinitions = new ColumnDefinitions("*,12,*,12,*") };
        grid.Children.Add(Count(L.T("overview.count.certificates"), Host.Inventory?.Certificates.Count.ToString(L.Culture) ?? "…", Icons.Key).At(0));
        grid.Children.Add(Count(L.T("overview.count.sites"), settings.AllowedOrigins.Count.ToString(L.Culture), Icons.Globe, () => Host.Navigate(MainWindow.Sites)).At(2));
        grid.Children.Add(Count(L.T("overview.count.signatures"), Controller.Services.Signatures.ToString(L.Culture), Icons.Mark, () => Host.Navigate(MainWindow.Activity)).At(4));
        return grid;
    }

    private static Control Count(string label, string value, string icon, Action? open = null)
    {
        var content = Ui.Split(
            Ui.Col(4, Ui.Text(label, "muted small"), Ui.Text(value, "h1")),
            Ui.Icon(icon, 18, "MutedFg").With(i => i.VerticalAlignment = VerticalAlignment.Top));
        var card = Ui.Card(content).With(c => c.Padding = new Thickness(16, 14));
        if (open is not null)
        {
            card.Cursor = new Avalonia.Input.Cursor(Avalonia.Input.StandardCursorType.Hand);
            card.PointerPressed += (_, _) => open();
        }

        return card;
    }

    private Border Certificates()
    {
        var refresh = Ui.Button(L.T("common.refresh"), Icons.Refresh, "outline sm", () => _ = Host.RefreshInventoryAsync());
        refresh.IsEnabled = Host.Inventory is not null;
        var header = new Border
        {
            Padding = new Thickness(20, 16),
            Child = Ui.Split(Ui.Col(2, Ui.Text(L.T("overview.certificates.title"), "h3"), Ui.Text(L.T("overview.certificates.subtitle"), "muted small wrap")), refresh),
        };
        var list = Ui.Col(0, header);
        if (Host.Inventory is not { } inventory)
        {
            list.Children.Add(Ui.Line());
            list.Children.Add(new Border { Padding = new Thickness(20, 18), Child = Ui.Row(8, Ui.Icon(Icons.Clock, 14, "MutedFg"), Ui.Text(L.T("overview.certificates.loading"), "muted")) });
        }
        else if (inventory.Certificates.Count == 0)
        {
            list.Children.Add(Ui.Line());
            list.Children.Add(new Border
            {
                Padding = new Thickness(20, 28),
                Child = Ui.Col(8,
                    Ui.IconBox(Icons.Key, "", "MutedFg").With(b => b.HorizontalAlignment = HorizontalAlignment.Center),
                    Ui.Text(L.T("overview.certificates.empty"), "strong").With(Center),
                    Ui.Text(L.T("overview.certificates.emptyHint"), "muted small wrap").With(Center).With(t => t.MaxWidth = 460),
                    Ui.Button(L.T("overview.certificates.help"), Icons.ChevronRight, "outline sm", () => Host.Navigate(MainWindow.Documentation, "troubleshooting"))
                        .With(b => b.HorizontalAlignment = HorizontalAlignment.Center)),
            });
        }
        else
        {
            foreach (var entry in inventory.Certificates)
            {
                list.Children.Add(Ui.Line());
                list.Children.Add(CertificateRow(entry));
            }
        }

        return Ui.Card(list, "flush");
    }

    internal static Border CertificateRow(CertificateEntry entry)
    {
        string details = string.Join(" · ", new[] { entry.MaskedDocument, entry.Source, entry.Issuer }.Where(s => !string.IsNullOrEmpty(s)));
        int days = (int)Math.Floor((entry.Certificate.NotAfter - DateTime.Now).TotalDays);
        var validity = entry.IsExpired ? Ui.Badge(L.T("cert.expired"), "err")
            : days <= 30 ? Ui.Badge(L.T("cert.expiresIn", days), "warn")
            : Ui.Badge(entry.Validity);
        var left = Ui.Row(12,
            Ui.IconBox(entry.Kind == CertificateSourceKind.File ? Icons.File : Icons.Key),
            Ui.Col(2,
                Ui.Text(entry.Holder, "strong").With(t => t.TextTrimming = Avalonia.Media.TextTrimming.CharacterEllipsis),
                Ui.Text(details, "muted small").With(t => t.TextTrimming = Avalonia.Media.TextTrimming.CharacterEllipsis)));
        var badges = Ui.Row(6, entry.IsIcpBrasil ? Ui.Badge("ICP-Brasil", "solid", Icons.ShieldCheck) : null, validity);
        return new Border { Padding = new Thickness(20, 12), Child = Ui.Split(left, badges) };
    }

    private static void Center(TextBlock text)
    {
        text.HorizontalAlignment = HorizontalAlignment.Center;
        text.TextAlignment = Avalonia.Media.TextAlignment.Center;
    }
}
