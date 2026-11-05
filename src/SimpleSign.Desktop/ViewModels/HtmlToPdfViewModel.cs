using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using SimpleSign.Desktop.Services;
using SimpleSign.HtmlToPdf;

namespace SimpleSign.Desktop.ViewModels;

internal sealed partial class HtmlToPdfViewModel(AppServices services)
    : PageViewModel(services, "HTML → PDF", "Gera um PDF a partir de HTML e CSS, pronto para assinar.", "Icon.Html")
{
    [ObservableProperty]
    private string _html = """
        <h1>Contrato de prestação de serviços</h1>
        <p>Pelo presente instrumento, as partes…</p>
        <table border="1" cellpadding="6">
          <tr><th>Item</th><th>Valor</th></tr>
          <tr><td>Serviço</td><td>R$ 1.000,00</td></tr>
        </table>
        """;

    [ObservableProperty]
    private string _title = "Documento";

    [RelayCommand]
    private Task ConvertAsync() => RunAsync(async () =>
    {
        byte[] pdf = await HtmlToPdfConverter.Html(Html).WithTitle(Title).ConvertAsync();
        if (await Services.Dialogs.SaveFileAsync("Salvar PDF", $"{Title}.pdf") is { } path)
        {
            await File.WriteAllBytesAsync(path, pdf);
            StatusMessage = $"PDF salvo em {path}";
        }
    });
}
