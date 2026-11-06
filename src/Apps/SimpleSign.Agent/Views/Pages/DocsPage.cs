using Avalonia;
using Avalonia.Controls;
using SimpleSign.Agent.Docs;
using SimpleSign.Agent.Localization;

namespace SimpleSign.Agent.Views.Pages;

/// <summary>The documentation shipped inside the agent, one topic at a time.</summary>
internal sealed class DocsPage : AgentPage
{
    private string _topic = DocLibrary.Topics[0];

    public DocsPage(MainWindow host)
        : base(host)
    {
    }

    /// <summary>Only the port changes the text; it is read when the page is built.</summary>
    public override void OnAgentChanged()
    {
    }

    public void Show(string topic)
    {
        _topic = DocLibrary.Topics.Contains(topic) ? topic : DocLibrary.Topics[0];
        Rebuild();
    }

    protected override Control Build()
    {
        var tabs = new StackPanel { Orientation = Avalonia.Layout.Orientation.Horizontal, Spacing = 20 };
        foreach (string topic in DocLibrary.Topics)
        {
            var tab = new Button { Content = Ui.Text(L.T("docs.topic." + topic)) }.Class("tab");
            tab.Classes.Set("on", topic == _topic);
            tab.Click += (_, _) => Show(topic);
            tabs.Children.Add(tab);
        }

        string text = DocLibrary.Load(_topic, L.Language, Controller.Settings.AgentPort);
        var document = MarkdownView.Render(Markdown.Parse(text), Open);
        var header = new Border { Padding = new Thickness(24, 6, 24, 0), Child = tabs };
        var dock = new DockPanel();
        DockPanel.SetDock(header, Dock.Top);
        var line = Ui.Line();
        DockPanel.SetDock(line, Dock.Top);
        dock.Children.Add(header);
        dock.Children.Add(line);
        dock.Children.Add(Ui.Page(document, 760, centered: false));
        return dock;
    }

    private void Open(string target)
    {
        if (target.StartsWith('#'))
        {
            Show(target[1..]);
        }
        else
        {
            Ui.OpenUrl(target);
        }
    }
}
