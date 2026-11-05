using Avalonia.Controls;
using Avalonia.Markup.Xaml;

namespace SimpleSign.Desktop.Views;

internal sealed partial class InspectView : UserControl
{
    public InspectView()
    {
        AvaloniaXamlLoader.Load(this);
    }
}
