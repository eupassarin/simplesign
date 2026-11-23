using SimpleSign.TestHelpers;
using Xunit;

namespace SimpleSign.PAdES.Tests.Pdf.Parity;

/// <summary>
/// The documents the writers on the PDF object model are compared on with the writers before them (ADR 0032): every
/// committed PDF, the generated ones, documents signed by the current signer, and the cases a writer handles apart
/// (inline AcroForm, <c>/Annots</c> as a reference, an existing <c>/DSS</c>, CRLF).
/// </summary>
internal static class WriterCorpus
{
    /// <summary>The documents, by name: <c>fixture:</c>, <c>generated:</c>, <c>signed:</c>, or a variant's name.</summary>
    public static IReadOnlyDictionary<string, Func<Task<byte[]>>> Documents { get; } = BuildCorpus();

    /// <summary>Names as theory data.</summary>
    /// <param name="names">The names.</param>
    public static TheoryData<string> Names(IEnumerable<string> names)
    {
        var data = new TheoryData<string>();
        foreach (string name in names)
        {
            data.Add(name);
        }

        return data;
    }

    private static Dictionary<string, Func<Task<byte[]>>> BuildCorpus()
    {
        var corpus = new Dictionary<string, Func<Task<byte[]>>>(StringComparer.Ordinal);
        foreach (var (name, path) in ParityCorpus.Fixtures)
        {
            corpus["fixture:" + name] = () => Task.FromResult(File.ReadAllBytes(path));
        }

        foreach (var (name, build) in ParityCorpus.Generated)
        {
            corpus["generated:" + name] = () => Task.FromResult(build());
        }

        foreach (string name in new[] { "table", "stream", "objstm" })
        {
            corpus["signed:" + name] = async () =>
            {
                using var cert = TestCertificateFactory.CreateSelfSignedCert();
                return await PadesSigner.Document(ParityCorpus.Generated[name]()).WithCertificate(cert).WithFieldName("Sig1").SignAsync();
            };
        }

        corpus["minimal-with-page"] = () => Task.FromResult(TestPdfFactory.CreateMinimalPdfWithPage());
        corpus["three-pages"] = () => Task.FromResult(TestPdfFactory.CreateThreePagePdf());
        corpus["inline-acroform-fields"] = () => Task.FromResult(Catalog("/AcroForm << /Fields [5 0 R] /DA (/Helv 0 Tf 0 g) /SigFlags 1 >>", "/Annots [5 0 R]"));
        corpus["inline-acroform-empty"] = () => Task.FromResult(Catalog("/AcroForm << /Fields [] /NeedAppearances true >>", ""));
        corpus["inline-acroform-no-fields"] = () => Task.FromResult(Catalog("/AcroForm << /DR << /Font << /Helv 6 0 R >> >> >>", ""));
        corpus["indirect-acroform-extras"] = () => Task.FromResult(Catalog("/AcroForm 7 0 R", "/Annots [5 0 R]"));
        corpus["indirect-annots"] = () => Task.FromResult(Catalog("/AcroForm 7 0 R", "/Annots 8 0 R"));
        corpus["page-crlf"] = () => Task.FromResult(Catalog("/AcroForm 7 0 R", "", crlf: true));
        corpus["catalog-dss-same-line"] = () => Task.FromResult(Catalog("/DSS 9 0 R /AcroForm 7 0 R", ""));
        corpus["catalog-dss-own-line"] = () => Task.FromResult(Catalog("/AcroForm 7 0 R\n   /DSS 9 0 R\n", ""));
        corpus["catalog-crlf"] = () => Task.FromResult(Catalog("\r\n/AcroForm 7 0 R\r\n/Lang (pt-BR)\r\n", ""));
        return corpus;
    }

    /// <summary>A one-page document with a field, its catalog and page carrying the entries given.</summary>
    public static byte[] Catalog(string catalogExtra, string pageExtra, bool crlf = false)
    {
        string page = crlf
            ? $"<<\r\n/Type /Page\r\n/Parent 2 0 R\r\n/MediaBox [0 0 612 792]\r\n{pageExtra}\r\n>>"
            : $"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] {pageExtra} >>";
        return new PdfFileBuilder()
            .Object(1, $"<< /Type /Catalog /Pages 2 0 R {catalogExtra} >>")
            .Object(2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
            .Object(3, page)
            .Object(5, "<< /FT /Tx /T (Name) /Subtype /Widget /Rect [10 10 100 30] /P 3 0 R >>")
            .Object(6, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
            .Object(7, "<< /Type /AcroForm /Fields [5 0 R]\n/DA (/Helv 0 Tf 0 g)\n/DR << /Font << /Helv 6 0 R >> >> /SigFlags 1 >>")
            .Object(8, "[ 5 0 R ]")
            .Object(9, "<< /Type /DSS /Certs [8 0 R] >>")
            .EndRevision()
            .ToArray();
    }
}
