using Avalonia;
using Avalonia.Controls;
using Avalonia.Layout;
using SimpleSign.Agent.Localization;

namespace SimpleSign.Agent.Views;

/// <summary>Asks for a token PIN. The text is never logged and is cleared when the window closes.</summary>
internal sealed class PromptWindow : Window
{
    public PromptWindow(string title, string message, string confirmText)
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

        Content = new Border
        {
            Padding = new Thickness(24),
            Child = Ui.Col(14,
                Ui.Row(12, Ui.IconBox(Icons.Key), Ui.Text(title, "h2")),
                Ui.Text(message, "muted wrap relaxed"),
                secret,
                Ui.Row(8, cancel, confirm).With(r => r.HorizontalAlignment = HorizontalAlignment.Right)),
        };
        Opened += (_, _) => secret.Focus();
        Closed += (_, _) => secret.Text = "";
    }

    /// <summary>The PIN, or null when cancelled.</summary>
    public string? Result { get; private set; }
}
