using Avalonia.Controls;
using Avalonia.Markup.Xaml;

namespace SimpleSign.Desktop.Views;

/// <summary>Asks for a PIN or password (never logged, cleared on close), or shows a message.</summary>
internal sealed partial class PromptWindow : Window
{
    public PromptWindow()
        : this("", "", "OK")
    {
    }

    public PromptWindow(string title, string message, string confirmText, bool askSecret = true)
    {
        AvaloniaXamlLoader.Load(this);
        this.FindControl<TextBlock>("TitleText")!.Text = title;
        this.FindControl<TextBlock>("MessageText")!.Text = message;
        var secret = this.FindControl<TextBox>("SecretBox")!;
        secret.IsVisible = askSecret;
        this.FindControl<Button>("CancelButton")!.IsVisible = askSecret;
        this.FindControl<Avalonia.Controls.Shapes.Path>("Glyph")!.IsVisible = askSecret;
        var confirm = this.FindControl<Button>("ConfirmButton")!;
        confirm.Content = confirmText;
        confirm.Click += (_, _) =>
        {
            Result = askSecret ? secret.Text ?? "" : "";
            secret.Text = "";
            Close();
        };
        this.FindControl<Button>("CancelButton")!.Click += (_, _) => Close();
        Opened += (_, _) => secret.Focus();
        Closed += (_, _) => secret.Text = "";
    }

    public string? Result { get; private set; }
}
