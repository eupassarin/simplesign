using System.Security.Cryptography.X509Certificates;
using FluentAssertions;
using SimpleSign.PAdES.Signing;
using SimpleSign.TestHelpers;
using Xunit;

namespace SimpleSign.PAdES.Tests.Validation;

public sealed class DisposalEdgeCaseTests : IDisposable
{
    private readonly X509Certificate2 _cert = TestCertificateFactory.CreateSelfSignedCert();

    public void Dispose() => _cert.Dispose();

    private static byte[] CreateMinimalPdf()
    {
        var pdf = "%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n" +
                  "2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n" +
                  "3 0 obj<</Type/Page/MediaBox[0 0 612 792]/Parent 2 0 R>>endobj\n" +
                  "xref\n0 4\n0000000000 65535 f \n0000000009 00000 n \n0000000058 00000 n \n" +
                  "0000000107 00000 n \ntrailer<</Size 4/Root 1 0 R>>\nstartxref\n176\n%%EOF";
        return System.Text.Encoding.ASCII.GetBytes(pdf);
    }

    [Fact(DisplayName = "BatchSigner: Double DisposeAsync does not throw")]
    public async Task BatchSigner_DoubleDispose_DoesNotThrow()
    {
        var signer = BatchSigner.Create(_cert).Build();

        var act = async () =>
        {
            await signer.DisposeAsync();
            await signer.DisposeAsync();
        };

        await act.Should().NotThrowAsync();
    }

    [Fact(DisplayName = "BatchSigner: SignAsync after DisposeAsync still works (no owned resources)")]
    public async Task BatchSigner_UseAfterDispose_StillWorks()
    {
        // BatchSigner.DisposeAsync only disposes owned HttpClient;
        // signing remains functional since the cert and signer are not disposed
        var signer = BatchSigner.Create(_cert).Build();
        await signer.DisposeAsync();

        var result = await signer.SignAsync(CreateMinimalPdf());
        result.Should().NotBeEmpty();
    }
}
