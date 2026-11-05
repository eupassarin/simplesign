using CommunityToolkit.Mvvm.ComponentModel;
using SimpleSign.Desktop.Agent;
using SimpleSign.Desktop.Services;

namespace SimpleSign.Desktop.ViewModels;

internal sealed partial class MainWindowViewModel : ObservableObject
{
    public MainWindowViewModel(AppServices services, AgentServer agent)
    {
        Agent = agent;
        Pages =
        [
            new SignViewModel(services),
            new ValidateViewModel(services),
            new InspectViewModel(services),
            new TimestampViewModel(services),
            new TokensViewModel(services),
            new IcpBrasilViewModel(services),
            new HtmlToPdfViewModel(services),
            new AgentViewModel(services, agent),
            new SettingsViewModel(services),
        ];
        _selectedPage = Pages[0];
        agent.StateChanged += (_, _) => Avalonia.Threading.Dispatcher.UIThread.Post(() => OnPropertyChanged(nameof(AgentStatus)));
    }

    public AgentServer Agent { get; }

    public IReadOnlyList<PageViewModel> Pages { get; }

    public IEnumerable<PageViewModel> ToolPages => Pages.Take(4);

    public IEnumerable<PageViewModel> SystemPages => Pages.Skip(4);

    [ObservableProperty]
    private PageViewModel _selectedPage;

    public string AgentStatus => Agent.IsRunning ? $"Agente ativo · 127.0.0.1:{Agent.Port}" : Agent.LastError ?? "Agente desligado";

    public T Page<T>() where T : PageViewModel => Pages.OfType<T>().Single();

    partial void OnSelectedPageChanged(PageViewModel value) => _ = value.OnShownAsync();
}
