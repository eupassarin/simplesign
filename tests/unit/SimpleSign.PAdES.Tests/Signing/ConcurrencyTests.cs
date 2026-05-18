using System.Runtime.CompilerServices;
using System.Text;
using Shouldly;
using SimpleSign.PAdES.Signing;
using SimpleSign.TestHelpers;
using Xunit;

namespace SimpleSign.PAdES.Tests.Signing;

[Trait("Category", "Concurrency")]
public sealed class ConcurrencyTests : IAsyncLifetime
{
    private static readonly byte[] MinimalPdf = Encoding.ASCII.GetBytes(
        "%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n3 0 obj<</Type/Page/MediaBox[0 0 612 792]/Parent 2 0 R>>endobj\nxref\n0 4\n0000000000 65535 f \n0000000009 00000 n \n0000000058 00000 n \n0000000107 00000 n \ntrailer<</Size 4/Root 1 0 R>>\nstartxref\n176\n%%EOF");

    private System.Security.Cryptography.X509Certificates.X509Certificate2 _cert = null!;

    public Task InitializeAsync()
    {
        _cert = TestCertificateFactory.CreateSelfSignedCert("CN=Concurrency Test");
        return Task.CompletedTask;
    }

    public Task DisposeAsync()
    {
        _cert.Dispose();
        return Task.CompletedTask;
    }

    [Fact(DisplayName = "BatchSigner parallel signing — all succeed")]
    public async Task BatchSigner_ParallelSigning_AllSucceed()
    {
        await using var signer = BatchSigner.Create(_cert).Build();

        var tasks = Enumerable.Range(0, 10)
            .Select(_ => signer.SignAsync(MinimalPdf))
            .ToArray();

        var results = await Task.WhenAll(tasks);

        results.Count().ShouldBe(10);
        foreach (var signed in results)
        {
            signed.ShouldNotBeNull();
            signed.ShouldNotBeEmpty();
            Encoding.ASCII.GetString(signed[..5]).ShouldBe("%PDF-");
        }
    }

    [Fact(DisplayName = "SimpleSigner parallel signing — thread safe")]
    public async Task SimpleSigner_ParallelSigning_ThreadSafe()
    {
        var tasks = Enumerable.Range(0, 5)
            .Select(_ => SimpleSigner.Document(MinimalPdf).WithCertificate(_cert).SignAsync())
            .ToArray();

        var results = await Task.WhenAll(tasks);

        results.Count().ShouldBe(5);
        foreach (var signed in results)
        {
            signed.ShouldNotBeNull();
            signed.ShouldNotBeEmpty();
            Encoding.ASCII.GetString(signed[..5]).ShouldBe("%PDF-");
        }
    }

    [Fact(DisplayName = "BatchSigner SignAllAsync parallel enumeration — no data corruption")]
    public async Task BatchSigner_SignAllAsync_ParallelEnumeration_NoDataCorruption()
    {
        await using var signer = BatchSigner.Create(_cert).Build();

        var results = new List<BatchSignResult>();
        await foreach (var result in signer.SignAllAsync(GenerateDocuments(20)))
        {
            results.Add(result);
        }

        results.Count().ShouldBe(20);
        foreach (var result in results)
        {
            result.Error.ShouldBeNull();
            result.SignedPdf.ShouldNotBeNull();
            result.SignedPdf.ShouldNotBeEmpty();
            Encoding.ASCII.GetString(result.SignedPdf![..5]).ShouldBe("%PDF-");
        }
    }

    private static async IAsyncEnumerable<(string Id, byte[] PdfBytes)> GenerateDocuments(
        int count,
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        for (var i = 0; i < count; i++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            await Task.Yield();
            yield return ($"doc-{i:D3}", MinimalPdf);
        }
    }
}
