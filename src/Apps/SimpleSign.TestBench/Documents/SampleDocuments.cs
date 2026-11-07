using System.Globalization;
using System.Text;
using SimpleSign.Core.Signing;
using SimpleSign.HtmlToPdf;
using SimpleSign.PAdES;
using SimpleSign.PAdES.Signing;
using SimpleSign.TestBench.Sandbox;

namespace SimpleSign.TestBench.Documents;

/// <summary>A sample PDF and what it demonstrates.</summary>
internal sealed record SampleDocument(string Id, string Title, string Description, string FileName, byte[] Content);

/// <summary>
/// The sample PDFs: plain, PDF/A, with an empty signature field, already signed and certified at
/// each DocMDP level. Generated at startup with the library itself (HtmlToPdf and the sandbox PKI).
/// </summary>
internal static class SampleDocuments
{
    public static async Task<IReadOnlyList<SampleDocument>> CreateAsync(SandboxEnvironment sandbox, CancellationToken cancellationToken = default)
    {
        byte[] contract = await HtmlToPdfConverter.Html(ContractHtml("Contrato de Prestação de Serviços", pages: 2))
            .WithTitle("Contrato de Prestação de Serviços")
            .WithAuthor("SimpleSign TestBench")
            .ConvertAsync(cancellationToken);

        byte[] font = LoadFont();
        byte[] pdfA2 = await HtmlToPdfConverter.Html(ContractHtml("Termo de Adesão (PDF/A-2b)", pages: 1))
            .WithFont("Liberation Sans", font)
            .WithStylesheet("body { font-family: 'Liberation Sans'; }")
            .WithTitle("Termo de Adesão")
            .WithLanguage("pt-BR")
            .WithPdfA()
            .ConvertAsync(cancellationToken);
        byte[] pdfA1 = ClaimPdfA1(pdfA2);

        var signer = sandbox.Pki.Signer("rsa-2048");
        async Task<byte[]> Sign(byte[] pdf, Func<PadesSignerBuilder, PadesSignerBuilder> configure) =>
            await configure(PadesSigner.Document(pdf)
                    .WithCertificate(signer.Certificate, sandbox.Pki.Chain)
                    .WithHttpClientProvider(sandbox.Network)
                    .WithLevel(AdesBaselineProfile.Basic()))
                .SignAsync(cancellationToken);

        byte[] signed = await Sign(contract, b => b.WithFieldName("Contratante").WithMetadata(new() { SignerName = "Maria da Silva", Reason = "Contratante" }));
        byte[] p1 = await Sign(contract, b => b.WithFieldName("Certificacao").AsCertification(CertificationLevel.NoChanges));
        byte[] p2 = await Sign(contract, b => b.WithFieldName("Certificacao").AsCertification(CertificationLevel.FormFilling));
        byte[] p3 = await Sign(contract, b => b.WithFieldName("Certificacao").AsCertification(CertificationLevel.FormFillingAndAnnotations));

        return
        [
            new("contract", "Contract (2 pages)", "A plain PDF 1.7 document with no signatures. Every option is available.", "contrato.pdf", contract),
            new("empty-field", "Form with an empty signature field", "Has an unsigned field 'Assinatura' with a visible rectangle, so you can sign into an existing field.", "formulario-campo-vazio.pdf", EmptyFieldPdf()),
            new("signed", "Already signed (B-B)", "Signed once by the sandbox signer. Adds a second signature in a new revision; certification is no longer possible.", "contrato-assinado.pdf", signed),
            new("certified-p1", "Certified, DocMDP P=1 (no changes)", "A certification signature that forbids any change: further signatures are refused (ISO 32000-1 §12.8.2.2).", "contrato-certificado-p1.pdf", p1),
            new("certified-p2", "Certified, DocMDP P=2 (form filling and signing)", "Certified with P=2: further approval signatures are allowed.", "contrato-certificado-p2.pdf", p2),
            new("certified-p3", "Certified, DocMDP P=3 (+ annotations)", "Certified with P=3: further signatures and annotations are allowed.", "contrato-certificado-p3.pdf", p3),
            new("pdfa-2b", "PDF/A-2b", "An archival PDF/A-2b document (fonts embedded). PDF/A preservation can check the signature keeps it conformant.", "termo-pdfa2b.pdf", pdfA2),
            new("pdfa-1b", "Declares PDF/A-1b", "The same document declaring PDF/A-1b in its XMP metadata. PDF/A-1 only allows adbe.pkcs7.detached signatures.", "termo-pdfa1b.pdf", pdfA1),
        ];
    }

    private const string Clause = "As partes acordam que o presente instrumento é celebrado de boa-fé, " +
        "observadas as disposições legais aplicáveis, e que as assinaturas eletrônicas apostas neste documento têm a validade " +
        "prevista na legislação aplicável.";

    private static string ContractHtml(string title, int pages)
    {
        var sb = new StringBuilder();
        sb.Append(CultureInfo.InvariantCulture, $$"""
            <html><head><style>
              body { font-family: Helvetica, Arial, sans-serif; color: #18181b; font-size: 11pt; line-height: 1.5; }
              h1 { font-size: 20pt; margin-bottom: 4pt; }
              .muted { color: #71717a; }
              .clause { margin-top: 12pt; }
              .page { page-break-after: always; }
              .sign { margin-top: 48pt; border-top: 1px solid #a1a1aa; width: 240pt; padding-top: 4pt; }
            </style></head><body>
            <h1>{{title}}</h1>
            <p class="muted">Documento de exemplo gerado pelo SimpleSign TestBench — sem valor jurídico.</p>
            """);
        for (int page = 1; page <= pages; page++)
        {
            sb.Append(page < pages ? "<div class=\"page\">" : "<div>");
            for (int clause = 1; clause <= 5; clause++)
            {
                int n = ((page - 1) * 5) + clause;
                sb.Append(CultureInfo.InvariantCulture, $"<p class=\"clause\"><b>Cláusula {n}.</b> {Clause}</p>");
            }

            if (page == pages)
            {
                sb.Append("<p class=\"sign\">Contratante</p><p class=\"sign\">Contratada</p>");
            }

            sb.Append("</div>");
        }

        sb.Append("</body></html>");
        return sb.ToString();
    }

    private static byte[] LoadFont()
    {
        var assembly = typeof(PadesSigner).Assembly;
        string name = assembly.GetManifestResourceNames().First(n => n.EndsWith(".ttf", StringComparison.OrdinalIgnoreCase));
        using var stream = assembly.GetManifestResourceStream(name)!;
        using var memory = new MemoryStream();
        stream.CopyTo(memory);
        return memory.ToArray();
    }

    /// <summary>Same bytes, but the XMP metadata declares PDF/A-1 (same length, so offsets stay valid).</summary>
    private static byte[] ClaimPdfA1(byte[] pdfA2)
    {
        byte[] copy = (byte[])pdfA2.Clone();
        byte[] from = Encoding.ASCII.GetBytes("<pdfaid:part>2</pdfaid:part>");
        int index = copy.AsSpan().IndexOf(from);
        if (index >= 0)
        {
            copy[index + "<pdfaid:part>".Length] = (byte)'1';
        }

        return copy;
    }

    /// <summary>A one-page form with a signature line and an unsigned signature field over it.</summary>
    private static byte[] EmptyFieldPdf()
    {
        const string content = """
            BT /F1 20 Tf 72 720 Td (Formulario de adesao) Tj ET
            BT /F1 11 Tf 72 690 Td (Documento de exemplo do SimpleSign TestBench. O campo abaixo esta vazio.) Tj ET
            BT /F1 11 Tf 72 670 Td (Assine no campo existente 'Assinatura' para preencher o retangulo.) Tj ET
            0.63 0.63 0.67 RG 0.5 w 72 300 220 70 re S
            BT /F1 9 Tf 72 290 Td (Assinatura do aderente) Tj ET
            """;
        var sb = new StringBuilder("%PDF-1.7\n%âãÏÓ\n");
        var offsets = new List<int>();
        void Obj(string body)
        {
            offsets.Add(Encoding.Latin1.GetByteCount(sb.ToString()));
            sb.Append(CultureInfo.InvariantCulture, $"{offsets.Count} 0 obj\n{body}\nendobj\n");
        }

        Obj("<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [4 0 R] /SigFlags 3 /DA (/Helv 0 Tf 0 g) >> >>");
        Obj("<< /Type /Pages /Kids [3 0 R] /Count 1 >>");
        Obj("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Contents 5 0 R /Resources << /Font << /F1 6 0 R >> >> /Annots [4 0 R] >>");
        Obj("<< /Type /Annot /Subtype /Widget /FT /Sig /T (Assinatura) /P 3 0 R /Rect [72 300 292 370] /F 4 >>");
        Obj($"<< /Length {Encoding.Latin1.GetByteCount(content)} >>\nstream\n{content}\nendstream");
        Obj("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>");
        int xref = Encoding.Latin1.GetByteCount(sb.ToString());
        sb.Append(CultureInfo.InvariantCulture, $"xref\n0 {offsets.Count + 1}\n0000000000 65535 f \n");
        foreach (int offset in offsets)
        {
            sb.Append(CultureInfo.InvariantCulture, $"{offset:D10} 00000 n \n");
        }

        sb.Append(CultureInfo.InvariantCulture, $"trailer\n<< /Size {offsets.Count + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n");
        return Encoding.Latin1.GetBytes(sb.ToString());
    }
}
