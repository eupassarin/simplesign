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

        var store = controller.Services.Settings;
        bool pinLocked = store.IsLocked(ManagedPolicy.PinCache);
        var agent = Ui.Col(16,
            Ui.Setting(L.T("settings.enabled"), L.T("settings.enabled.hint"), Ui.Switch(settings.AgentEnabled, on => _ = controller.SetEnabledAsync(on))),
            AgentController.CanStartAtLogin
                ? Ui.Setting(L.T("settings.login"), L.T("settings.login.hint"), Ui.Switch(AgentController.StartsAtLogin, controller.SetStartAtLogin))
                : null,
            Port(controller),
            Ui.Col(8,
                Ui.Setting(L.T("settings.pin"), Hint(L.T("settings.pin.hint"), pinLocked), null),
                Ui.Segmented(
                    [.. s_pinMinutes.Select(m => (m, m == 0 ? L.T("settings.pin.never") : L.T("settings.pin.minutes", m)))],
                    s_pinMinutes.Contains(settings.PinCacheMinutes) ? settings.PinCacheMinutes : 0,
                    minutes => controller.Update(s => s.PinCacheMinutes = minutes),
                    !pinLocked)));

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
            Group(L.T("settings.group.trust"), Trust(controller)),
            Ui.Line(),
            Group(L.T("settings.group.security"), Security(controller)),
            Ui.Line(),
            Group(L.T("settings.group.appearance"), appearance),
            Ui.Line(),
            Group(L.T("settings.group.data"), data));
    }

    private static StackPanel Group(string title, Control content) => Ui.Col(14, Ui.Text(title.ToUpper(L.Culture), "xs muted strong"), content);

    /// <summary>Adds "fixed by your administrator" to a hint when the policy locks the setting.</summary>
    private static string Hint(string hint, bool locked) => locked ? hint + " " + L.T("settings.locked") : hint;

    /// <summary>
    /// The signed-request mode and what the administrator's policy fixes. Both are read from files
    /// (settings.json, policy.json), not edited here: a public key is not something to paste into a settings panel.
    /// </summary>
    private static StackPanel Security(AgentController controller)
    {
        var store = controller.Services.Settings;
        var settings = store.Current;
        int keys = settings.SignedRequestKeys?.Count ?? 0;
        string state = !settings.SignedRequestsRequired ? L.T("settings.signed.off")
            : keys == 0 ? L.T("settings.signed.onNoKey")
            : L.T("settings.signed.on", keys);
        var column = Ui.Col(16,
            Ui.Col(6,
                Ui.Setting(L.T("settings.signed"), Hint(L.T("settings.signed.hint"), store.IsLocked(ManagedPolicy.SignedRequests)), null),
                Ui.Badge(state, settings.SignedRequestsRequired && keys == 0 ? "err" : settings.SignedRequestsRequired ? "ok" : "")
                    .With(b => b.HorizontalAlignment = HorizontalAlignment.Left)),
            Ui.Col(6,
                Ui.Setting(L.T("settings.policy"), null, null),
                Ui.Text(store.Policy.Path is { } path ? L.T("settings.policy.file", path) : L.T("settings.policy.none"), "muted small wrap")));
        if (store.Policy.Error is { } error)
        {
            column.Children.Add(Ui.Text(error, "destructive small wrap"));
        }
        else if (LockedKeys(store) is { Length: > 0 } locked)
        {
            column.Children.Add(Ui.Text(L.T("settings.policy.locked", locked), "muted small wrap"));
        }

        return column;
    }

    private static string LockedKeys(SettingsStore store) => string.Join(", ", new[]
    {
        ManagedPolicy.Origins, ManagedPolicy.SignedRequests, ManagedPolicy.TrustFrameworks,
        ManagedPolicy.Port, ManagedPolicy.PinCache,
    }.Where(store.IsLocked));

    /// <summary>One switch per trust framework the agent ships with, plus the state of its trusted list.</summary>
    private static StackPanel Trust(AgentController controller)
    {
        var frameworks = controller.Services.TrustFrameworks;
        bool locked = controller.Services.Settings.IsLocked(ManagedPolicy.TrustFrameworks);
        var column = Ui.Col(16, Ui.Text(Hint(L.T("settings.trust.hint"), locked), "muted small wrap"));
        foreach (var framework in frameworks.All)
        {
            bool on = frameworks.IsEnabled(framework.Id);
            string hint = L.T(framework.HintKey);
            if (on && framework.NeedsTrustedList)
            {
                var state = frameworks.StateOf(framework);
                hint += " · " + state.Status switch
                {
                    TrustFrameworkStatus.Ready => L.T("settings.trust.ready", state.AnchorCount),
                    TrustFrameworkStatus.Unavailable => L.T("settings.trust.offline"),
                    _ => L.T("settings.trust.loading"),
                };
            }

            column.Children.Add(Ui.Setting(
                L.T(framework.NameKey),
                hint,
                Ui.Switch(on, want => Toggle(controller, framework.Id, want), !locked)));
        }

        return column;
    }

    private static void Toggle(AgentController controller, string id, bool on)
    {
        controller.Update(s =>
        {
            var ids = s.EnabledTrustFrameworks ??= [];
            ids.RemoveAll(i => string.Equals(i, id, StringComparison.OrdinalIgnoreCase));
            if (on)
            {
                ids.Add(id);
            }
        });
        controller.Services.TrustFrameworks.StartLoading();
    }

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
