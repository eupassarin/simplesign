using System.Text;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Layout;
using SimpleSign.Agent.Localization;
using SimpleSign.Agent.Services;

namespace SimpleSign.Agent.Views.Pages;

/// <summary>What the agent did since it started: requests, answers and errors, newest first.</summary>
internal sealed class ActivityPage : AgentPage
{
    private bool _errorsOnly;
    private StackPanel? _list;

    public ActivityPage(MainWindow host)
        : base(host)
    {
    }

    /// <summary>The state does not change the log: nothing to rebuild.</summary>
    public override void OnAgentChanged()
    {
    }

    public override void OnActivity(LogEntry? entry)
    {
        if (entry is null || _list is null || _list.Children is [Border { Tag: "empty" }])
        {
            Rebuild();
        }
        else if (!_errorsOnly || entry.IsError)
        {
            _list.Children.Insert(0, Ui.Line());
            _list.Children.Insert(0, Row(entry));
        }
    }

    protected override Control Build()
    {
        var log = Controller.Services.Log;
        var entries = log.Entries.Where(e => !_errorsOnly || e.IsError).Reverse().ToList();
        var filter = Ui.Segmented([(false, L.T("activity.all")), (true, L.T("activity.errors"))], _errorsOnly, value =>
        {
            _errorsOnly = value;
            Rebuild();
        });
        var copy = Ui.Button(L.T("common.copy"), Icons.Copy, "outline sm");
        copy.Click += (_, _) => Ui.CopyText(copy, Plain(entries));
        copy.IsEnabled = entries.Count > 0;
        var clear = Ui.Button(L.T("activity.clear"), Icons.Trash, "sm", log.Clear);
        clear.IsEnabled = log.Entries.Count > 0;

        _list = Ui.Col(0);
        if (entries.Count == 0)
        {
            _list.Children.Add(new Border { Padding = new Thickness(20, 24), Tag = "empty", Child = Ui.Text(L.T(_errorsOnly ? "activity.noErrors" : "activity.empty"), "muted small") });
        }
        else
        {
            foreach (var entry in entries)
            {
                if (_list.Children.Count > 0)
                {
                    _list.Children.Add(Ui.Line());
                }

                _list.Children.Add(Row(entry));
            }
        }

        return Ui.Page(Ui.Col(16,
            Ui.Split(
                Ui.Col(4, Ui.Text(L.T("activity.title"), "h1"), Ui.Text(L.T("activity.intro"), "muted wrap")),
                Ui.Row(6, filter, copy, clear).With(r => r.VerticalAlignment = VerticalAlignment.Bottom)),
            Ui.Card(_list, "flush")));
    }

    private static Border Row(LogEntry entry)
    {
        var grid = new Grid { ColumnDefinitions = new ColumnDefinitions("Auto,Auto,*") };
        grid.Children.Add(Ui.Text(entry.TimeText, "mono muted").With(t => t.Margin = new Thickness(0, 1, 12, 0)).At(0));
        grid.Children.Add(Ui.Dot(entry.IsError ? "err" : "ok").With(d =>
        {
            d.Margin = new Thickness(0, 5, 10, 0);
            d.VerticalAlignment = VerticalAlignment.Top;
        }).At(1));
        grid.Children.Add(Ui.Selectable(entry.Message, entry.IsError ? "wrap destructive" : "wrap").At(2));
        return new Border { Padding = new Thickness(20, 9), Child = grid };
    }

    private static string Plain(IEnumerable<LogEntry> entries)
    {
        var text = new StringBuilder();
        foreach (var entry in entries)
        {
            text.Append(entry.Time.ToString("yyyy-MM-dd HH:mm:ss", System.Globalization.CultureInfo.InvariantCulture)).Append(entry.IsError ? " ! " : "   ").AppendLine(entry.Message);
        }

        return text.ToString();
    }
}
