using Avalonia.Controls;
using Avalonia.Markup.Xaml;

namespace SimpleSign.Desktop.Views;

internal sealed partial class HtmlToPdfView : UserControl
{
    public HtmlToPdfView()
    {
        AvaloniaXamlLoader.Load(this);
    }
}
