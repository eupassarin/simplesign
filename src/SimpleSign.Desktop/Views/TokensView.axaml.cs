using Avalonia.Controls;
using Avalonia.Markup.Xaml;

namespace SimpleSign.Desktop.Views;

internal sealed partial class TokensView : UserControl
{
    public TokensView()
    {
        AvaloniaXamlLoader.Load(this);
    }
}
