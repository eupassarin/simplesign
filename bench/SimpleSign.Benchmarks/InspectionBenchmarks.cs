using BenchmarkDotNet.Attributes;
using SimpleSign.PAdES;
using SimpleSign.PAdES.Inspection;
using SimpleSign.TestHelpers;

namespace SimpleSign.Benchmarks;

[MemoryDiagnoser]
public class InspectionBenchmarks
{
    private byte[] _pdf1Sig = null!;
    private byte[] _pdf5Sigs = null!;
    private byte[] _pdf10Sigs = null!;

    [GlobalSetup]
    public async Task Setup()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert("CN=Bench Inspection");
        var template = PdfHelper.BuildMinimalPdf();

        _pdf1Sig = await PadesSigner.Document(template).WithCertificate(cert).SignAsync();

        byte[] multi = template;
        for (int i = 0; i < 5; i++)
        {
            multi = await PadesSigner.Document(multi).WithCertificate(cert).SignAsync();
        }
        _pdf5Sigs = multi;

        multi = template;
        for (int i = 0; i < 10; i++)
        {
            multi = await PadesSigner.Document(multi).WithCertificate(cert).SignAsync();
        }
        _pdf10Sigs = multi;
    }

    [Benchmark(Baseline = true, Description = "Inspect — 1 signature")]
    public async Task<int> Inspect_1Sig()
    {
        using var ms = new MemoryStream(_pdf1Sig);
        var result = await PdfSignatureInspector.InspectAsync(ms);
        return result.Signatures.Count;
    }

    [Benchmark(Description = "Inspect — 5 signatures")]
    public async Task<int> Inspect_5Sigs()
    {
        using var ms = new MemoryStream(_pdf5Sigs);
        var result = await PdfSignatureInspector.InspectAsync(ms);
        return result.Signatures.Count;
    }

    [Benchmark(Description = "Inspect — 10 signatures")]
    public async Task<int> Inspect_10Sigs()
    {
        using var ms = new MemoryStream(_pdf10Sigs);
        var result = await PdfSignatureInspector.InspectAsync(ms);
        return result.Signatures.Count;
    }
}
