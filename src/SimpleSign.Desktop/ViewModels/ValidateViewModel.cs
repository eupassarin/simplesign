using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using SimpleSign.Desktop.Services;

namespace SimpleSign.Desktop.ViewModels;

internal sealed partial class ValidateViewModel(AppServices services)
    : PageViewModel(services, "Validar", "Verifica integridade, cadeia, carimbos, LTV e a política ICP-Brasil de PDFs, .p7s/.p7m e XML.", "Icon.Validate"), IFileDropTarget
{
    System.Windows.Input.ICommand IFileDropTarget.DropPickCommand => PickFileCommand;

    private string? _path;

    public ObservableCollection<SignatureReport> Reports { get; } = [];

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasFile), nameof(NeedsData))]
    private string? _fileName;

    [ObservableProperty]
    private string? _dataFileName;

    [ObservableProperty]
    private string? _summary;

    private byte[]? _data;

    public bool HasFile => FileName is not null;

    public bool NeedsData => FileName?.EndsWith(".p7s", StringComparison.OrdinalIgnoreCase) == true;

    public async Task LoadFileAsync(string path)
    {
        _path = path;
        FileName = Path.GetFileName(path);
        _data = null;
        DataFileName = null;
        Reports.Clear();
        Summary = null;
        if (!NeedsData)
        {
            await ValidateAsync();
        }
        else if (File.Exists(path[..^4]))
        {
            _data = await File.ReadAllBytesAsync(path[..^4]);
            DataFileName = Path.GetFileName(path[..^4]);
            await ValidateAsync();
        }
    }

    [RelayCommand]
    private async Task PickFileAsync()
    {
        if (await Services.Dialogs.OpenFileAsync("Documento assinado", "*.pdf", "*.p7s", "*.p7m", "*.xml") is { } path)
        {
            await LoadFileAsync(path);
        }
    }

    [RelayCommand]
    private async Task PickDataAsync()
    {
        if (await Services.Dialogs.OpenFileAsync("Arquivo assinado pelo .p7s", "*") is { } path)
        {
            _data = await File.ReadAllBytesAsync(path);
            DataFileName = Path.GetFileName(path);
            await ValidateAsync();
        }
    }

    [RelayCommand]
    private Task ValidateAsync() => RunAsync(async () =>
    {
        if (_path is null)
        {
            return;
        }

        Reports.Clear();
        var reports = await Services.Documents.ValidateAsync(_path, await File.ReadAllBytesAsync(_path), _data, CancellationToken.None);
        foreach (var report in reports)
        {
            Reports.Add(report);
        }

        int valid = reports.Count(r => r.Verdict == CheckState.Ok);
        Summary = reports.Count == 0
            ? "Nenhuma assinatura encontrada."
            : $"{reports.Count} assinatura(s) · {valid} válida(s)";
        Services.Log.Add(Title, $"{FileName}: {Summary}");
    });
}
