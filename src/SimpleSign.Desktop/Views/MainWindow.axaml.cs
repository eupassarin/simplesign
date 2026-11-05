using Avalonia.Controls;
using Avalonia.Markup.Xaml;
using SimpleSign.Desktop.ViewModels;

namespace SimpleSign.Desktop.Views;

internal sealed partial class MainWindow : Window
{
    public MainWindow()
    {
        AvaloniaXamlLoader.Load(this);
        var tools = this.FindControl<ListBox>("ToolList")!;
        var system = this.FindControl<ListBox>("SystemList")!;
        // Two lists, one selection: picking in one clears the other.
        tools.SelectionChanged += (_, _) => Select(tools, system);
        system.SelectionChanged += (_, _) => Select(system, tools);
        DataContextChanged += (_, _) =>
        {
            if (DataContext is MainWindowViewModel vm)
            {
                tools.SelectedItem = vm.SelectedPage;
                vm.PropertyChanged += (_, e) =>
                {
                    if (e.PropertyName == nameof(MainWindowViewModel.AgentStatus))
                    {
                        UpdateAgentDot(vm);
                    }
                    else if (e.PropertyName == nameof(MainWindowViewModel.SelectedPage))
                    {
                        // Keep the sidebar in step when the page changes from code.
                        var target = vm.ToolPages.Contains(vm.SelectedPage) ? tools : system;
                        if (target.SelectedItem != vm.SelectedPage)
                        {
                            target.SelectedItem = vm.SelectedPage;
                        }
                    }
                };
                UpdateAgentDot(vm);
            }
        };
    }

    private void Select(ListBox from, ListBox other)
    {
        if (from.SelectedItem is PageViewModel page && DataContext is MainWindowViewModel vm)
        {
            other.SelectedItem = null;
            vm.SelectedPage = page;
            this.FindControl<ScrollViewer>("ContentScroll")!.Offset = default;
        }
    }

    private void UpdateAgentDot(MainWindowViewModel vm) =>
        this.FindControl<Avalonia.Controls.Shapes.Ellipse>("AgentDot")!.Fill =
            Converters.Brush(vm.Agent.IsRunning ? "App.Success" : "App.Secondary");
}
