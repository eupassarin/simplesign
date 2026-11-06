using System.Globalization;
using Avalonia.Controls;
using Avalonia.Layout;
using SimpleSign.Agent.Localization;
using SimpleSign.Agent.Services;

namespace SimpleSign.Agent.Views.Panels;

/// <summary>The settings, in the panel that slides over the window.</summary>
internal sealed class SettingsPanel
{
    private static readonly int[] s_pinMinutes = [0, 5, 15, 30, 60];
    private readonly MainWindow _host;
    private string? _port;
    private string? _portError;

    public SettingsPanel(MainWindow host)
    {
        _host = host;
    }

    public Control Build()
    {
        var controller = _host.Controller;
        var settings = controller.Settings;

        var agent = Ui.Col(16,
            Ui.Setting(L.T("settings.enabled"), L.T("settings.enabled.hint"), Ui.Switch(settings.AgentEnabled, on => _ = controller.SetEnabledAsync(on))),
            AgentController.CanStartAtLogin
                ? Ui.Setting(L.T("settings.login"), L.T("settings.login.hint"), Ui.Switch(AgentController.StartsAtLogin, controller.SetStartAtLogin))
                : null,
            Port(controller),
            Ui.Col(8,
                Ui.Setting(L.T("settings.pin"), L.T("settings.pin.hint"), null),
                Ui.Segmented(
                    [.. s_pinMinutes.Select(m => (m, m == 0 ? L.T("settings.pin.never") : L.T("settings.pin.minutes", m)))],
                    s_pinMinutes.Contains(settings.PinCacheMinutes) ? settings.PinCacheMinutes : 0,
                    minutes => controller.Update(s => s.PinCacheMinutes = minutes))));

        var appearance = Ui.Col(16,
            Ui.Col(8,
                Ui.Setting(L.T("settings.language"), L.T("settings.language.hint"), null),
                Ui.Segmented([.. L.Languages.Select(l => (l.Id, l.Label))], L.Language, id => Appearance.SetLanguage(controller, id))),
            Ui.Col(8,
                Ui.Setting(L.T("settings.theme"), null, null),
                Ui.Segmented([.. Appearance.Themes.Select(t => (t, L.T("theme." + t)))], settings.Theme, theme => Appearance.SetTheme(controller, theme))));

        string folder = controller.Services.Settings.Folder;
        var data = Ui.Col(8,
            Ui.Setting(L.T("settings.file"), L.T("settings.file.hint"), null),
            Ui.Selectable(Path.Combine(folder, "settings.json"), "mono muted wrap"),
            Ui.Button(L.T("settings.openFolder"), Icons.Folder, "outline sm", () => Ui.OpenFolder(folder)).With(b => b.HorizontalAlignment = HorizontalAlignment.Left));

        return Ui.Col(20,
            Group(L.T("settings.group.agent"), agent),
            Ui.Line(),
            Group(L.T("settings.group.appearance"), appearance),
            Ui.Line(),
            Group(L.T("settings.group.data"), data));
    }

    private static StackPanel Group(string title, Control content) => Ui.Col(14, Ui.Text(title.ToUpper(L.Culture), "xs muted strong"), content);

    private StackPanel Port(AgentController controller)
    {
        var box = new TextBox { Text = _port ?? controller.Settings.AgentPort.ToString(CultureInfo.InvariantCulture), Width = 84, MaxLength = 5 };
        box.TextChanged += (_, _) => _port = box.Text;
        var apply = Ui.Button(L.T("settings.port.apply"), null, "outline", () =>
        {
            if (!int.TryParse(box.Text, NumberStyles.None, CultureInfo.InvariantCulture, out int port) || port is < 1024 or > 65535)
            {
                _portError = L.T("settings.port.invalid");
                _host.OpenSheet(MainWindow.SettingsSheet);
                return;
            }

            _portError = null;
            _port = null;
            _ = controller.SetPortAsync(port);
        });
        var column = Ui.Col(6, Ui.Setting(L.T("settings.port"), L.T("settings.port.hint"), Ui.Row(6, box, apply)));
        string? problem = _portError ?? (controller.State == AgentState.Error ? controller.Server.LastError : null);
        if (problem is not null)
        {
            column.Children.Add(Ui.Text(problem, "destructive small wrap"));
        }

        return column;
    }
}
