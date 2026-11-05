using Avalonia.Controls;
using Avalonia.Markup.Xaml;

namespace SimpleSign.Desktop.Views;

internal sealed partial class AgentView : UserControl
{
    public AgentView()
    {
        AvaloniaXamlLoader.Load(this);
    }
}
