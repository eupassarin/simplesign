using System.Collections.ObjectModel;
using System.Globalization;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using SimpleSign.Brasil.IcpBrasil;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Signing;
using SimpleSign.Desktop.Services;

namespace SimpleSign.Desktop.ViewModels;

internal sealed partial class TimestampViewModel(AppServices services)
    : PageViewModel(services, "Carimbo do tempo", "Prova de que um arquivo existia em um instante (RFC 3161, .tst), sem assiná-lo.", "Icon.Timestamp"), IFileDropTarget
{
    System.Windows.Input.ICommand IFileDropTarget.DropPickCommand => PickFileCommand;

    private string? _path;

    public ObservableCollection<CheckItem> Checks { get; } = [];

    public ObservableCollection<DetailItem> Details { get; } = [];

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasFile))]
    [NotifyCanExecuteChangedFor(nameof(CreateCommand), nameof(VerifyCommand))]
    private string? _fileName;

    [ObservableProperty]
    private string? _tokenName;

    [ObservableProperty]
    private bool _requireIcpBrasil = true;

    [ObservableProperty]
    private string? _verdict;

    public bool HasFile => FileName is not null;

    public string TsaUrl => Services.Settings.Current.TsaUrl;

    public Task LoadFileAsync(string path)
    {
        _path = path;
        FileName = Path.GetFileName(path);
        TokenName = File.Exists(path + ".tst") ? Path.GetFileName(path + ".tst") : null;
        Checks.Clear();
        Details.Clear();
        Verdict = null;
        return Task.CompletedTask;
    }

    [RelayCommand]
    private async Task PickFileAsync()
    {
        if (await Services.Dialogs.OpenFileAsync("Arquivo", "*") is { } path)
        {
            await LoadFileAsync(path);
        }
    }

    [RelayCommand(CanExecute = nameof(HasFile))]
    private Task CreateAsync() => RunAsync(async () =>
    {
        byte[] token = await TimestampToken.CreateAsync(await File.ReadAllBytesAsync(_path!), new TimestampOptions(new Uri(TsaUrl)));
        if (await Services.Dialogs.SaveFileAsync("Salvar carimbo", FileName + ".tst") is { } target)
        {
            await File.WriteAllBytesAsync(target, token);
            TokenName = Path.GetFileName(target);
            Services.Log.Add(Title, $"Carimbo de {FileName} salvo em {target}");
            Show(TimestampToken.Verify(token, await File.ReadAllBytesAsync(_path!)));
        }
    }, "Carimbo criado.");

    [RelayCommand(CanExecute = nameof(HasFile))]
    private async Task VerifyAsync()
    {
        string? tokenPath = TokenName is not null && File.Exists(Path.Combine(Path.GetDirectoryName(_path!)!, TokenName))
            ? Path.Combine(Path.GetDirectoryName(_path!)!, TokenName)
            : await Services.Dialogs.OpenFileAsync("Carimbo (.tst)", "*.tst");
        if (tokenPath is null)
        {
            return;
        }

        await RunAsync(async () =>
        {
            byte[] token = await File.ReadAllBytesAsync(tokenPath);
            byte[] data = await File.ReadAllBytesAsync(_path!);
            TokenName = Path.GetFileName(tokenPath);
            Show(RequireIcpBrasil
                ? IcpBrasilTimestamp.Verify(token, data, Services.Settings.Current.IcpHomologation ? IcpBrasilEnvironment.Homologation : IcpBrasilEnvironment.Production)
                : TimestampToken.Verify(token, data));
        });
    }

    private void Show(TimestampTokenVerification result)
    {
        Checks.Clear();
        Details.Clear();
        Checks.Add(new("O carimbo cobre este arquivo", result.IsImprintValid ? CheckState.Ok : CheckState.Failed));
        Checks.Add(new("Assinatura da TSA", result.IsIntegrityValid ? CheckState.Ok : CheckState.Failed));
        Checks.Add(new("TSA confiável", result.IsTsaTrusted switch { true => CheckState.Ok, false => CheckState.Failed, null => CheckState.NotApplicable },
            result.IsTsaTrusted is null ? "não verificado" : null));
        if (result.Info is { } info)
        {
            Details.Add(new("Data e hora", info.GenerationTime.ToLocalTime().ToString("dd/MM/yyyy HH:mm:ss", CultureInfo.InvariantCulture)));
            Details.Add(new("TSA", info.TsaCertificate?.Subject ?? "-"));
            Details.Add(new("Política", info.PolicyOid ?? "-"));
            Details.Add(new("Número de série", info.SerialNumber ?? "-"));
            Details.Add(new("Resumo", info.HashAlgorithm.ToString()));
        }

        foreach (string error in result.Errors)
        {
            Details.Add(new("Erro", error));
        }

        Verdict = result.IsValid ? "Carimbo válido" : "Carimbo inválido";
    }
}
