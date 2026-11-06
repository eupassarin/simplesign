using Avalonia.Controls;
using Avalonia.Layout;
using Avalonia.Markup.Xaml;
using SimpleSign.Agent.Server;
using SimpleSign.Agent.Services;

namespace SimpleSign.Agent.Views;

/// <summary>Lists the origins the user allowed permanently and lets them revoke each one.</summary>
internal sealed partial class OriginsWindow : Window
{
    private readonly SettingsStore? _settings;
    private readonly OriginPolicy? _origins;

    public OriginsWindow()
    {
        AvaloniaXamlLoader.Load(this);
        this.FindControl<Button>("CloseButton")!.Click += (_, _) => Close();
    }

    public OriginsWindow(SettingsStore settings, OriginPolicy origins, string status)
        : this()
    {
        _settings = settings;
        _origins = origins;
        this.FindControl<TextBlock>("StatusText")!.Text = status;
        Load();
    }

    private void Load()
    {
        var list = this.FindControl<StackPanel>("OriginList")!;
        list.Children.Clear();
        var allowed = _settings!.Current.AllowedOrigins;
        if (allowed.Count == 0)
        {
            list.Children.Add(new TextBlock { Text = "Nenhum site autorizado.", Classes = { "caption" } });
            return;
        }

        foreach (string origin in allowed.ToList())
        {
            var remove = new Button { Content = "Remover", VerticalAlignment = VerticalAlignment.Center };
            remove.Click += (_, _) =>
            {
                _origins!.Forget(origin);
                Load();
            };
            var row = new DockPanel();
            DockPanel.SetDock(remove, Dock.Right);
            row.Children.Add(remove);
            row.Children.Add(new TextBlock { Text = origin, VerticalAlignment = VerticalAlignment.Center });
            list.Children.Add(row);
        }
    }
}
