using Avalonia;
using Avalonia.Controls;
using SimpleSign.Agent.Localization;
using SimpleSign.Agent.Services;

namespace SimpleSign.Agent.Views.Pages;

/// <summary>The sites allowed to use the agent, and the blocked ones.</summary>
internal sealed class SitesPage : AgentPage
{
    public SitesPage(MainWindow host)
        : base(host)
    {
    }

    public override void OnActivity(LogEntry? entry) => Rebuild();

    protected override Control Build()
    {
        var origins = Controller.Server.Origins;
        var settings = Controller.Settings;
        var allowed = Section(L.T("sites.allowed.title"), L.T("sites.allowed.subtitle"), L.T("sites.allowed.empty"));
        foreach (string origin in settings.AllowedOrigins.Order(StringComparer.Ordinal))
        {
            Add(allowed, Row(origin, Ui.Badge(L.T("sites.always"), "ok"),
                Ui.Button(L.T("sites.block"), Icons.Ban, "sm destructive", () => origins.Block(origin)),
                Ui.Button(L.T("sites.remove"), Icons.Trash, "sm", () => origins.Forget(origin))));
        }

        foreach (string origin in origins.SessionOnly)
        {
            Add(allowed, Row(origin, Ui.Badge(L.T("sites.session")),
                Ui.Button(L.T("sites.block"), Icons.Ban, "sm destructive", () => origins.Block(origin)),
                Ui.Button(L.T("sites.remove"), Icons.Trash, "sm", () =>
                {
                    origins.Forget(origin);
                    Rebuild();
                })));
        }

        var blocked = Section(L.T("sites.blocked.title"), L.T("sites.blocked.subtitle"), L.T("sites.blocked.empty"));
        foreach (string origin in settings.BlockedOrigins.Order(StringComparer.Ordinal))
        {
            Add(blocked, Row(origin, Ui.Badge(L.T("sites.blockedBadge"), "err"),
                Ui.Button(L.T("sites.unblock"), Icons.Check, "sm", () => origins.Forget(origin))));
        }

        return Ui.Page(Ui.Col(16,
            Ui.Col(4, Ui.Text(L.T("sites.title"), "h1"), Ui.Text(L.T("sites.intro"), "muted wrap")),
            Ui.Card(allowed, "flush"),
            Ui.Card(blocked, "flush")));
    }

    /// <summary>A list with a header; its last child is the "nothing here" row until an item is added.</summary>
    private static StackPanel Section(string title, string subtitle, string empty) => Ui.Col(0,
        new Border { Padding = new Thickness(20, 16), Child = Ui.Col(2, Ui.Text(title, "h3"), Ui.Text(subtitle, "muted small wrap")) },
        Ui.Line(),
        new Border { Padding = new Thickness(20, 18), Child = Ui.Text(empty, "muted small"), Tag = "empty" });

    private static void Add(StackPanel section, Control row)
    {
        if (section.Children[^1] is Border { Tag: "empty" })
        {
            section.Children.RemoveAt(section.Children.Count - 1);
        }
        else
        {
            section.Children.Add(Ui.Line());
        }

        section.Children.Add(row);
    }

    private static Border Row(string origin, Control badge, params Control[] actions) => new()
    {
        Padding = new Thickness(20, 10),
        Child = Ui.Split(Ui.Row(10, Ui.Icon(Icons.Globe, 15, "MutedFg"), Ui.Selectable(origin, "mono"), badge), Ui.Row(4, actions)),
    };
}
