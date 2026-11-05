using Avalonia.Controls;
using Avalonia.Markup.Xaml;

namespace SimpleSign.Desktop.Views;

internal sealed partial class ValidateView : UserControl
{
    public ValidateView()
    {
        AvaloniaXamlLoader.Load(this);
    }
}
