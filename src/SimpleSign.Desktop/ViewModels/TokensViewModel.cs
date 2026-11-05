using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.Input;
using SimpleSign.Desktop.Services;
using SimpleSign.Signers.Pkcs11;

namespace SimpleSign.Desktop.ViewModels;

internal sealed record DriverRow(string Vendor, string Product, string? Path, bool Installed, string? Error, IReadOnlyList<TokenRow> Tokens)
{
    public string Status => Error is not null ? "Erro ao carregar" : !Installed ? "Não instalado" : Tokens.Count == 0 ? "Nenhum token conectado" : $"{Tokens.Count} token(s)";
}

internal sealed record TokenRow(string Label, string Model, string Serial, string Pin, IReadOnlyList<CertificateEntry> Certificates);

internal sealed partial class TokensViewModel(AppServices services)
    : PageViewModel(services, "Tokens e certificados", "Drivers PKCS#11 detectados, tokens A3 conectados e certificados do sistema.", "Icon.Token")
{
    public ObservableCollection<DriverRow> Drivers { get; } = [];

    public ObservableCollection<DriverRow> MissingDrivers { get; } = [];

    public ObservableCollection<CertificateEntry> StoreCertificates { get; } = [];

    public override Task OnShownAsync() => Drivers.Count == 0 ? RefreshAsync() : Task.CompletedTask;

    [RelayCommand]
    private Task RefreshAsync() => RunAsync(async () =>
    {
        Drivers.Clear();
        MissingDrivers.Clear();
        StoreCertificates.Clear();
        var (certificates, found) = await CertificateService.ListTokensAsync(CancellationToken.None);
        foreach (var driver in found)
        {
            var tokens = driver.Tokens.Select(t => new TokenRow(t.Label.Trim(), $"{t.Manufacturer.Trim()} {t.Model.Trim()}", t.SerialNumber.Trim(),
                t.IsPinLocked ? "PIN bloqueado" : t.HasProtectedAuthenticationPath ? "PIN pad" : t.IsLoginRequired ? "Pede PIN" : "Sem PIN",
                [.. certificates.Where(c => c.Token!.TokenSerial == t.SerialNumber)])).ToList();
            Drivers.Add(new DriverRow(driver.Driver.Driver.Vendor, driver.Driver.Driver.Product, driver.Driver.LibraryPath, true, driver.Error, tokens));
        }

        foreach (var known in Pkcs11Drivers.Known.Where(k => found.All(f => f.Driver.Driver != k)))
        {
            MissingDrivers.Add(new DriverRow(known.Vendor, known.Product, null, false, null, []));
        }

        foreach (var entry in CertificateService.ListStore())
        {
            StoreCertificates.Add(entry);
        }
    });
}
