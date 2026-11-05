using System.Collections.ObjectModel;
using System.Globalization;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using SimpleSign.Desktop.Services;
using SimpleSign.PAdES.Inspection;

namespace SimpleSign.Desktop.ViewModels;

internal sealed record InspectedSignature(string Name, IReadOnlyList<DetailItem> Details, byte[] Cms);

internal sealed partial class InspectViewModel(AppServices services)
    : PageViewModel(services, "Inspecionar", "Estrutura do PDF, assinaturas, certificados, carimbos e DSS — sem validar.", "Icon.Inspect"), IFileDropTarget
{
    System.Windows.Input.ICommand IFileDropTarget.DropPickCommand => PickFileCommand;

    public ObservableCollection<DetailItem> Document { get; } = [];

    public ObservableCollection<InspectedSignature> Signatures { get; } = [];

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasFile))]
    private string? _fileName;

    public bool HasFile => FileName is not null;

    public Task LoadFileAsync(string path) => RunAsync(async () =>
    {
        FileName = Path.GetFileName(path);
        Document.Clear();
        Signatures.Clear();
        await using var stream = File.OpenRead(path);
        var result = await PdfSignatureInspector.InspectAsync(stream);
        var d = result.Document;
        Document.Add(new("Versão do PDF", d.PdfVersion.ToString()));
        Document.Add(new("PDF/A", d.PdfALevel.ToString()));
        Document.Add(new("Criptografado", d.IsEncrypted ? "Sim" : "Não"));
        Document.Add(new("Certificação (DocMDP)", d.IsDocMdpLocked ? $"Nível {d.DocMdpPermissionLevel}" : "Não"));
        Document.Add(new("Assinaturas", d.SignatureCount.ToString(CultureInfo.InvariantCulture)));
        Document.Add(new("DSS (dados LTV)", d.SecurityStore is null ? "Ausente" : "Presente"));
        foreach (var s in result.Signatures)
        {
            var details = new List<DetailItem>
            {
                new("Tipo", s.IsDocumentTimestamp ? "Carimbo do documento" : "Assinatura"),
                new("SubFilter", s.SubFilter ?? "-"),
                new("Signatário", s.Signer?.Subject ?? s.DeclaredSignerName ?? "-"),
                new("Emissor", s.Signer?.Issuer ?? "-"),
                new("Validade do certificado", s.Signer is { } c ? $"{c.NotBefore:dd/MM/yyyy} a {c.NotAfter:dd/MM/yyyy}" : "-"),
                new("Chave", s.Signer is { } k ? $"{k.KeyAlgorithm} {k.KeySizeBits}" : "-"),
                new("Resumo", s.DigestAlgorithm.ToString()),
                new("Algoritmo", s.SignatureAlgorithm.ToString()),
                new("Data declarada", s.SigningTime?.ToLocalTime().ToString("dd/MM/yyyy HH:mm:ss", CultureInfo.InvariantCulture) ?? "-"),
                new("Carimbo do tempo", s.Timestamp?.ToString() ?? "-"),
                new("Política", s.SignaturePolicyOid ?? "-"),
                new("Certificados embutidos", s.EmbeddedCertificates.Count.ToString(CultureInfo.InvariantCulture)),
            };
            if (!string.IsNullOrWhiteSpace(s.Reason))
            {
                details.Add(new("Motivo", s.Reason));
            }

            Signatures.Add(new InspectedSignature(s.FieldName, details, s.CmsRawData.ToArray()));
        }
    });

    [RelayCommand]
    private async Task PickFileAsync()
    {
        if (await Services.Dialogs.OpenFileAsync("PDF", "*.pdf") is { } path)
        {
            await LoadFileAsync(path);
        }
    }

    [RelayCommand]
    private async Task ExtractAsync(InspectedSignature signature)
    {
        if (await Services.Dialogs.SaveFileAsync("Salvar CMS", $"{signature.Name}.p7s") is { } path)
        {
            await RunAsync(() => File.WriteAllBytesAsync(path, signature.Cms), $"CMS salvo em {path}");
        }
    }
}
