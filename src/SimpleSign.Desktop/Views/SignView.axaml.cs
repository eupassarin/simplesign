using Avalonia.Controls;
using Avalonia.Markup.Xaml;

namespace SimpleSign.Desktop.Views;

internal sealed partial class SignView : UserControl
{
    public SignView()
    {
        AvaloniaXamlLoader.Load(this);
    }
}
