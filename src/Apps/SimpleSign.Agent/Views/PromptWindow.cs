using Avalonia;
using Avalonia.Controls;
using Avalonia.Layout;
using SimpleSign.Agent.Localization;

namespace SimpleSign.Agent.Views;

/// <summary>Asks for a token PIN. The text is never logged and is cleared when the window closes.</summary>
internal sealed class PromptWindow : Window
{
    /// <summary>Asks for a secret.</summary>
    /// <param name="title">The dialog's title.</param>
    /// <param name="message">What is being asked and why.</param>
    /// <param name="confirmText">The confirm button's text.</param>
    /// <param name="warning">A warning shown above the box; null for none.</param>
    /// <param name="severe">Whether the warning is shown as an error rather than a caution.</param>
    public PromptWindow(string title, string message, string confirmText, string? warning = null, bool severe = false)
    {
        Title = "SimpleSign Agent";
        Icon = AgentIcons.Window();
        Width = 400;
        SizeToContent = SizeToContent.Height;
        CanResize = false;
        ShowInTaskbar = false;
        WindowStartupLocation = WindowStartupLocation.CenterScreen;

        var secret = new TextBox { PasswordChar = '●', Watermark = "••••••" };
        var cancel = Ui.Button(L.T("common.cancel"), null, "outline", Close);
        cancel.IsCancel = true;
        var confirm = Ui.Button(confirmText, Icons.Mark, "primary", () =>
        {
            Result = secret.Text ?? "";
            Close();
        });
        confirm.IsDefault = true;

        var caution = warning is null
            ? null
            : Ui.Row(8,
                Ui.Icon(Icons.Alert, 14, severe ? "Destructive" : "Warning"),
                Ui.Text(warning, (severe ? "destructive" : "warning") + " small wrap strong"));
        Content = new Border
        {
            Padding = new Thickness(24),
            Child = Ui.Col(14,
                Ui.Row(12, Ui.IconBox(Icons.Key), Ui.Text(title, "h2")),
                Ui.Text(message, "muted wrap relaxed"),
                caution,
                secret,
                Ui.Row(8, cancel, confirm).With(r => r.HorizontalAlignment = HorizontalAlignment.Right)),
        };
        Opened += (_, _) => secret.Focus();
        Closed += (_, _) => secret.Text = "";
    }

    /// <summary>The PIN, or null when cancelled.</summary>
    public string? Result { get; private set; }
}
