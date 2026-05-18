using BenchmarkDotNet.Attributes;
using SimpleSign.PAdES;
using SimpleSign.PAdES.Inspection;
using SimpleSign.Pdf;
using SimpleSign.TestHelpers;

namespace SimpleSign.Benchmarks;

/// <summary>
/// Isolates PDF parsing and signature extraction costs from signing.
/// Shows what fraction of total time is spent reading vs writing.
/// </summary>
[MemoryDiagnoser]
public class ParsingBenchmarks
{
    private byte[] _unsignedPdf = null!;
    private byte[] _signedPdf1 = null!;
    private byte[] _signedPdf5 = null!;

    [GlobalSetup]
    public async Task Setup()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert("CN=Bench Parsing");
        _unsignedPdf = PdfHelper.BuildMinimalPdf();

        _signedPdf1 = await SimpleSigner.Document(_unsignedPdf).WithCertificate(cert).SignAsync();

        byte[] multi = _unsignedPdf;
        for (int i = 0; i < 5; i++)
        {
            multi = await SimpleSigner.Document(multi).WithCertificate(cert).SignAsync();
        }

        _signedPdf5 = multi;
    }

    [Benchmark(Description = "ReadSignatureFields — unsigned PDF")]
    public async Task<int> ReadFields_Unsigned()
    {
        using var ms = new MemoryStream(_unsignedPdf);
        var fields = await PdfStructureReader.ReadSignatureFieldsAsync(ms);
        return fields.Count;
    }

    [Benchmark(Description = "ReadSignatureFields — 1 signature")]
    public async Task<int> ReadFields_1Sig()
    {
        using var ms = new MemoryStream(_signedPdf1);
        var fields = await PdfStructureReader.ReadSignatureFieldsAsync(ms);
        return fields.Count;
    }

    [Benchmark(Description = "ReadSignatureFields — 5 signatures")]
    public async Task<int> ReadFields_5Sigs()
    {
        using var ms = new MemoryStream(_signedPdf5);
        var fields = await PdfStructureReader.ReadSignatureFieldsAsync(ms);
        return fields.Count;
    }

    [Benchmark(Description = "PadesExtractor.ExtractAsync — 1 signature")]
    public async Task<int> Extract_1Sig()
    {
        using var ms = new MemoryStream(_signedPdf1);
        var sigs = await PadesExtractor.ExtractAsync(ms);
        return sigs.Count;
    }

    [Benchmark(Description = "PadesExtractor.ExtractAsync — 5 signatures")]
    public async Task<int> Extract_5Sigs()
    {
        using var ms = new MemoryStream(_signedPdf5);
        var sigs = await PadesExtractor.ExtractAsync(ms);
        return sigs.Count;
    }

    [Benchmark(Description = "IsEncryptedAsync check")]
    public async Task<bool> IsEncrypted_Check()
    {
        using var ms = new MemoryStream(_signedPdf1);
        return await PdfStructureReader.IsEncryptedAsync(ms);
    }
}
