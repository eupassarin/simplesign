using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using SimpleSign.Brasil.IcpBrasil;
using SimpleSign.Desktop.Services;

namespace SimpleSign.Desktop.ViewModels;

internal sealed partial class SignViewModel : PageViewModel, IFileDropTarget
{
    System.Windows.Input.ICommand IFileDropTarget.DropPickCommand => PickFileCommand;

    private byte[]? _input;
    private byte[]? _output;

    public SignViewModel(AppServices services)
        : base(services, "Assinar", "PDF, qualquer arquivo (CAdES) ou XML, com certificado A1, A3 ou do sistema.", "Icon.Sign")
    {
        _selectedFormat = Options.Formats[0];
        _selectedLevel = Options.Levels[0];
        _policies = [.. Options.Policies(SignatureFormat.Pades)];
        _selectedPolicy = Options.NoPolicy;
    }

    public IReadOnlyList<Option<SignatureFormat>> Formats => Options.Formats;

    public IReadOnlyList<Option<SignatureLevel>> Levels => Options.Levels;

    public ObservableCollection<CertificateEntry> Certificates { get; } = [];

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasFile))]
    [NotifyCanExecuteChangedFor(nameof(SignCommand))]
    private string? _fileName;

    [ObservableProperty]
    private string? _fileSize;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsPdf))]
    private Option<SignatureFormat> _selectedFormat;

    [ObservableProperty]
    private Option<SignatureLevel> _selectedLevel;

    [ObservableProperty]
    private ObservableCollection<Option<IcpBrasilPolicy?>> _policies;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(UsesPolicy))]
    private Option<IcpBrasilPolicy?> _selectedPolicy;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(SignCommand))]
    private CertificateEntry? _selectedCertificate;

    [ObservableProperty]
    private string? _reason;

    [ObservableProperty]
    private string? _location;

    [ObservableProperty]
    private bool _visibleStamp = true;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasOutput))]
    private string? _outputName;

    public bool HasFile => FileName is not null;

    public bool HasOutput => OutputName is not null;

    public bool IsPdf => SelectedFormat.Value == SignatureFormat.Pades;

    public bool UsesPolicy => SelectedPolicy.Value is not null;

    partial void OnSelectedFormatChanged(Option<SignatureFormat> value)
    {
        var previous = SelectedPolicy.Value;
        Policies = [.. Options.Policies(value.Value)];
        SelectedPolicy = Policies.FirstOrDefault(p => p.Value == previous) ?? Options.NoPolicy;
    }

    public override async Task OnShownAsync()
    {
        if (Certificates.Count == 0)
        {
            await RefreshCertificatesAsync();
        }
    }

    /// <summary>Loads a document dropped on the page or picked from disk.</summary>
    public async Task LoadFileAsync(string path)
    {
        _input = await File.ReadAllBytesAsync(path);
        FileName = Path.GetFileName(path);
        FileSize = $"{_input.Length / 1024.0:N1} KB";
        SelectedFormat = Options.Formats.First(f => f.Value == DocumentService.DefaultFormatFor(path));
        OutputName = null;
        _output = null;
    }

    [RelayCommand]
    private async Task PickFileAsync()
    {
        if (await Services.Dialogs.OpenFileAsync("Escolha o documento", "*") is { } path)
        {
            await RunAsync(() => LoadFileAsync(path));
        }
    }

    [RelayCommand]
    private Task RefreshCertificatesAsync() => RunAsync(async () =>
    {
        var files = Certificates.Where(c => c.Kind == CertificateSourceKind.File).ToList();
        var selected = SelectedCertificate?.Certificate.Thumbprint;
        Certificates.Clear();
        foreach (var entry in files.Concat(CertificateService.ListStore()))
        {
            Certificates.Add(entry);
        }

        var (tokens, _) = await CertificateService.ListTokensAsync(CancellationToken.None);
        foreach (var entry in tokens)
        {
            Certificates.Add(entry);
        }

        SelectedCertificate = Certificates.FirstOrDefault(c => c.Certificate.Thumbprint == selected)
            ?? Certificates.FirstOrDefault(c => !c.IsExpired);
    });

    [RelayCommand]
    private async Task LoadPfxAsync()
    {
        if (await Services.Dialogs.OpenFileAsync("Certificado A1 (PFX/P12)", "*.pfx", "*.p12") is not { } path)
        {
            return;
        }

        string? password = await Services.Dialogs.AskSecretAsync("Senha do certificado", $"Digite a senha de {Path.GetFileName(path)}.", "Abrir");
        if (password is null)
        {
            return;
        }

        await RunAsync(() =>
        {
            var entry = CertificateService.LoadFile(path, password);
            Certificates.Insert(0, entry);
            SelectedCertificate = entry;
            return Task.CompletedTask;
        });
    }

    private bool CanSign() => HasFile && SelectedCertificate is not null;

    [RelayCommand(CanExecute = nameof(CanSign))]
    private async Task SignAsync()
    {
        var entry = SelectedCertificate!;
        string? pin = null;
        if (entry.Kind == CertificateSourceKind.Token && !entry.Token!.HasPinPad)
        {
            pin = await Services.Dialogs.AskSecretAsync("PIN do token", $"Digite o PIN de {entry.Token.TokenLabel.Trim()} para assinar com {entry.Holder}.", "Assinar");
            if (pin is null)
            {
                return;
            }
        }

        await RunAsync(async () =>
        {
            using var credential = await Task.Run(() => CertificateService.Open(entry, pin));
            var request = new SignRequest(_input!, FileName!, SelectedFormat.Value, SelectedLevel.Value, SelectedPolicy.Value,
                Services.Settings.Current.TsaUrl, Reason, Location, VisibleStamp);
            _output = await Services.Documents.SignAsync(request, credential, CancellationToken.None);
            OutputName = DocumentService.OutputName(FileName!, SelectedFormat.Value);
            Services.Log.Add(Title, $"{FileName} assinado com {entry.Holder}");
        }, "Documento assinado. Salve o resultado.");
    }

    [RelayCommand]
    private async Task SaveAsync()
    {
        if (_output is null || await Services.Dialogs.SaveFileAsync("Salvar documento assinado", OutputName!) is not { } path)
        {
            return;
        }

        await RunAsync(() => File.WriteAllBytesAsync(path, _output), $"Salvo em {path}");
    }
}
