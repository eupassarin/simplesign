using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using SimpleSign.Desktop.Agent;
using SimpleSign.Desktop.Services;

namespace SimpleSign.Desktop.ViewModels;

internal sealed partial class AgentViewModel : PageViewModel
{
    private readonly AgentServer _agent;

    public AgentViewModel(AppServices services, AgentServer agent)
        : base(services, "Agente local", "Permite que sites peçam assinaturas com seus certificados — sempre com a sua confirmação.", "Icon.Agent")
    {
        _agent = agent;
        _isEnabled = services.Settings.Current.AgentEnabled;
        _port = services.Settings.Current.AgentPort;
        foreach (var entry in services.Log.Entries)
        {
            Log.Insert(0, entry);
        }

        services.Log.Added += (_, entry) => Avalonia.Threading.Dispatcher.UIThread.Post(() =>
        {
            Log.Insert(0, entry);
            if (Log.Count > 300)
            {
                Log.RemoveAt(Log.Count - 1);
            }
        });
        agent.StateChanged += (_, _) => Avalonia.Threading.Dispatcher.UIThread.Post(Refresh);
        services.Settings.Changed += (_, _) => Avalonia.Threading.Dispatcher.UIThread.Post(LoadOrigins);
        LoadOrigins();
    }

    public ObservableCollection<string> AllowedOrigins { get; } = [];

    public ObservableCollection<LogEntry> Log { get; } = [];

    [ObservableProperty]
    private bool _isEnabled;

    [ObservableProperty]
    private decimal _port;

    public string Status => _agent.IsRunning ? $"Ouvindo em http://127.0.0.1:{_agent.Port}" : _agent.LastError ?? "Desligado";

    public bool IsRunning => _agent.IsRunning;

    public static string Example => """
        // Detecta o agente
        await fetch("http://127.0.0.1:21590/api/health");
        // Lista certificados (o usuário autoriza o site na primeira vez)
        const certs = await (await fetch("http://127.0.0.1:21590/api/certificates")).json();
        // Assina os atributos assinados (DER, base64) — o usuário confirma cada assinatura
        await fetch("http://127.0.0.1:21590/api/sign", {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ thumbprint, hashAlgorithm: "SHA256", documentName: "contrato.pdf",
            signRequests: [{ id: "1", authenticatedAttributeBase64 }] })
        });
        """;

    partial void OnIsEnabledChanged(bool value) => _ = ApplyAsync();

    [RelayCommand]
    private Task ApplyAsync() => RunAsync(async () =>
    {
        Services.Settings.Current.AgentEnabled = IsEnabled;
        Services.Settings.Current.AgentPort = (int)Port;
        Services.Settings.Save();
        if (IsEnabled)
        {
            await _agent.StartAsync((int)Port);
        }
        else
        {
            await _agent.StopAsync();
        }
    });

    [RelayCommand]
    private void Forget(string origin)
    {
        _agent.Origins.Forget(origin);
        LoadOrigins();
    }

    private void LoadOrigins()
    {
        AllowedOrigins.Clear();
        foreach (string origin in Services.Settings.Current.AllowedOrigins)
        {
            AllowedOrigins.Add(origin);
        }
    }

    private void Refresh()
    {
        OnPropertyChanged(nameof(Status));
        OnPropertyChanged(nameof(IsRunning));
    }
}
