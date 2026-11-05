using Avalonia.Controls;
using Avalonia.Markup.Xaml;

namespace SimpleSign.Desktop.Controls;

internal sealed partial class PageChrome : UserControl
{
    public PageChrome()
    {
        AvaloniaXamlLoader.Load(this);
    }
}
