using Avalonia;
using Avalonia.Headless;
using Avalonia.Headless.XUnit;
using Avalonia.Styling;
using Shouldly;
using SimpleSign.Desktop.Agent;
using SimpleSign.Desktop.ViewModels;
using SimpleSign.Desktop.Views;

namespace SimpleSign.Desktop.Tests;

/// <summary>Renders every page in light and dark (Skia, headless) and saves the PNGs for review and docs.</summary>
public sealed class ScreenshotTests
{
    public static TheoryData<int, string> Pages()
    {
        var data = new TheoryData<int, string>();
        for (int i = 0; i < 9; i++)
        {
            data.Add(i, "Light");
            data.Add(i, "Dark");
        }

        return data;
    }

    [AvaloniaTheory]
    [MemberData(nameof(Pages))]
    public async Task EveryPage_Renders(int index, string theme)
    {
        Application.Current!.RequestedThemeVariant = theme == "Dark" ? ThemeVariant.Dark : ThemeVariant.Light;
        var services = Fixtures.Services();
        var vm = new MainWindowViewModel(services, new AgentServer(services, new TokenSessionCache(), _ => Task.FromResult<IReadOnlyList<Services.CertificateEntry>>([])));
        var window = new MainWindow { DataContext = vm, Width = 1180, Height = 800 };
        window.Show();
        vm.SelectedPage = vm.Pages[index];
        await Task.Delay(50);
        Avalonia.Threading.Dispatcher.UIThread.RunJobs();

        using var frame = window.CaptureRenderedFrame();

        frame.ShouldNotBeNull();
        string folder = Path.Combine(AppContext.BaseDirectory, "screenshots");
        Directory.CreateDirectory(folder);
        frame.Save(Path.Combine(folder, $"{index:00}-{vm.Pages[index].GetType().Name.Replace("ViewModel", "", StringComparison.Ordinal)}-{theme}.png"));
        window.Close();
    }
}
