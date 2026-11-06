using Avalonia;
using Avalonia.Controls;
using Avalonia.Layout;
using SimpleSign.Agent.Localization;
using SimpleSign.Agent.Services;

namespace SimpleSign.Agent.Views.Panels;

/// <summary>What the agent is, what it guarantees, and the facts of this installation.</summary>
internal sealed class AboutPanel
{
    private const string Repository = "https://github.com/eupassarin/SimpleSign";
    private readonly MainWindow _host;

    public AboutPanel(MainWindow host)
    {
        _host = host;
    }

    public Control Build()
    {
        var controller = _host.Controller;
        var inventory = _host.Inventory;
        var mark = new Border
        {
            Width = 56,
            Height = 56,
            CornerRadius = new CornerRadius(14),
            Child = Ui.Icon(Icons.Mark, 32, "PrimaryFg", filled: true).With(i => i.HorizontalAlignment = HorizontalAlignment.Center),
        }.Class("mark");
        var hero = Ui.Row(16, mark, Ui.Col(2,
            Ui.Text("SimpleSign Agent", "h1"),
            Ui.Row(8, Ui.Badge(L.T("about.version", Diagnostics.Version), "solid"), Ui.Text("MIT", "muted small"))));

        var promises = Ui.Col(14,
            Promise(Icons.Lock, L.T("about.promise.key"), L.T("about.promise.key.detail")),
            Promise(Icons.ShieldCheck, L.T("about.promise.consent"), L.T("about.promise.consent.detail")),
            Promise(Icons.Laptop, L.T("about.promise.local"), L.T("about.promise.local.detail")));

        string drivers = inventory is null ? "…" : inventory.Drivers.Count == 0 ? L.T("about.none") : string.Join("\n", inventory.Drivers);
        var facts = new Grid { ColumnDefinitions = new ColumnDefinitions("Auto,*") };
        Fact(facts, L.T("about.fact.state"), controller.StatusText);
        Fact(facts, L.T("about.fact.system"), $"{Diagnostics.OperatingSystemName} · {Diagnostics.Architecture}");
        Fact(facts, L.T("about.fact.runtime"), Diagnostics.Runtime);
        Fact(facts, L.T("about.fact.certificates"), inventory?.Certificates.Count.ToString(L.Culture) ?? "…");
        Fact(facts, L.T("about.fact.drivers"), drivers);
        Fact(facts, L.T("about.fact.settings"), controller.Services.Settings.Folder);
        var copy = Ui.Button(L.T("about.copy"), Icons.Copy, "outline sm");
        copy.Click += (_, _) => Ui.CopyText(copy, Diagnostics.Report(controller, inventory?.Drivers ?? [], inventory?.Certificates.Count ?? 0));
        copy.HorizontalAlignment = HorizontalAlignment.Left;
        var installation = Ui.Card(Ui.Col(12, Ui.Text(L.T("about.installation"), "h3"), facts, copy)).With(c => c.Padding = new Thickness(16));

        var standards = Ui.Col(6,
            Ui.Text(L.T("about.standards"), "h3"),
            Ui.Text(L.T("about.standards.detail"), "muted small wrap relaxed"));

        var links = Ui.Col(2,
            Link(Icons.Github, L.T("about.link.repository"), Repository),
            Link(Icons.External, L.T("about.link.releases"), Repository + "/releases"),
            Link(Icons.Alert, L.T("about.link.issue"), Repository + "/issues/new"));

        return Ui.Col(20,
            hero,
            Ui.Text(L.T("about.tagline"), "wrap relaxed"),
            promises,
            installation,
            standards,
            links,
            Ui.Line(),
            Ui.Text(L.T("about.credits"), "muted xs wrap"));
    }

    private static Grid Promise(string icon, string title, string detail)
    {
        var grid = new Grid { ColumnDefinitions = new ColumnDefinitions("Auto,*") };
        grid.Children.Add(Ui.IconBox(icon).With(b =>
        {
            b.VerticalAlignment = VerticalAlignment.Top;
            b.Margin = new Thickness(0, 0, 12, 0);
        }).At(0));
        grid.Children.Add(Ui.Col(2, Ui.Text(title, "strong wrap"), Ui.Text(detail, "muted small wrap")).At(1));
        return grid;
    }

    private static void Fact(Grid grid, string label, string value)
    {
        int row = grid.RowDefinitions.Count;
        grid.RowDefinitions.Add(new RowDefinition(GridLength.Auto));
        grid.Children.Add(Ui.Text(label, "muted small").With(t => t.Margin = new Thickness(0, 3, 16, 3)).At(0, row));
        grid.Children.Add(Ui.Selectable(value, "small wrap").With(t => t.Margin = new Thickness(0, 3)).At(1, row));
    }

    private static Button Link(string icon, string text, string url) =>
        Ui.Button(text, icon, "sm", () => Ui.OpenUrl(url)).With(b =>
        {
            b.HorizontalAlignment = HorizontalAlignment.Stretch;
            b.HorizontalContentAlignment = HorizontalAlignment.Left;
        });
}
