using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using SimpleSign.Desktop.Services;

namespace SimpleSign.Desktop.ViewModels;

internal sealed partial class SettingsViewModel : PageViewModel
{
    public SettingsViewModel(AppServices services)
        : base(services, "Ajustes", "Carimbo do tempo, cache de LCR, PIN e aparência.", "Icon.Settings")
    {
        var s = services.Settings.Current;
        _tsaUrl = s.TsaUrl;
        _crlCacheDirectory = s.CrlCacheDirectory;
        _pinCacheMinutes = s.PinCacheMinutes;
        _selectedTheme = Themes.FirstOrDefault(t => t.Value == s.Theme) ?? Themes[0];
    }

    public IReadOnlyList<Option<string>> Themes { get; } = [new("System", "Sistema"), new("Light", "Claro"), new("Dark", "Escuro")];

    [ObservableProperty]
    private string _tsaUrl;

    [ObservableProperty]
    private string _crlCacheDirectory;

    [ObservableProperty]
    private decimal _pinCacheMinutes;

    [ObservableProperty]
    private Option<string> _selectedTheme;

    public event EventHandler<string>? ThemeChanged;

    partial void OnSelectedThemeChanged(Option<string> value) => ThemeChanged?.Invoke(this, value.Value);

    [RelayCommand]
    private async Task PickCrlFolderAsync()
    {
        if (await Services.Dialogs.PickFolderAsync("Pasta do cache de LCR") is { } folder)
        {
            CrlCacheDirectory = folder;
        }
    }

    [RelayCommand]
    private void Save()
    {
        ErrorMessage = null;
        if (!Uri.TryCreate(TsaUrl, UriKind.Absolute, out var uri) || uri.Scheme is not ("http" or "https" or "tcp"))
        {
            ErrorMessage = "Informe uma URL http(s):// ou tcp:// para o carimbo do tempo.";
            return;
        }

        var s = Services.Settings.Current;
        s.TsaUrl = TsaUrl.Trim();
        s.CrlCacheDirectory = CrlCacheDirectory.Trim();
        s.PinCacheMinutes = (int)PinCacheMinutes;
        s.Theme = SelectedTheme.Value;
        Services.Settings.Save();
        StatusMessage = "Ajustes salvos.";
    }
}
