using Avalonia.Controls;
using Avalonia.Markup.Xaml;

namespace SimpleSign.Desktop.Views;

internal sealed partial class TimestampView : UserControl
{
    public TimestampView()
    {
        AvaloniaXamlLoader.Load(this);
    }
}
