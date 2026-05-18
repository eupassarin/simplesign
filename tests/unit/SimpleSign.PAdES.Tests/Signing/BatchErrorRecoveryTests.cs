using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Shouldly;
using SimpleSign.Core.Validation;
using SimpleSign.PAdES.Signing;
using SimpleSign.TestHelpers;
using Xunit;

namespace SimpleSign.PAdES.Tests.Signing;

public sealed class BatchErrorRecoveryTests
{
    private static byte[] CreateMinimalPdf()
    {
        const string pdf = "%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n" +
                           "2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n" +
                           "3 0 obj<</Type/Page/MediaBox[0 0 612 792]/Parent 2 0 R>>endobj\n" +
                           "xref\n0 4\n0000000000 65535 f \n0000000009 00000 n \n0000000058 00000 n \n" +
                           "0000000107 00000 n \ntrailer<</Size 4/Root 1 0 R>>\nstartxref\n176\n%%EOF";
        return Encoding.ASCII.GetBytes(pdf);
    }

    private static X509Certificate2 CreateExpiredCert()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=Expired", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-10), DateTimeOffset.UtcNow.AddDays(-1));
    }

    [Fact(DisplayName = "BatchSigner SignAllAsync with null PDF in middle continues with others")]
    [Trait("Category", "BatchError")]
    public async Task BatchSigner_SignAllAsync_InvalidPdfInMiddle_ContinuesWithOthers()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert("CN=BatchError Test");
        await using var signer = BatchSigner.Create(cert).Build();

        var results = new List<BatchSignResult>();
        await foreach (var result in signer.SignAllAsync(GenerateMixedInputs()))
        {
            results.Add(result);
        }

        results.Count().ShouldBe(3);

        var successResults = results.Where(r => r.IsSuccess).ToList();
        var errorResults = results.Where(r => !r.IsSuccess).ToList();

        successResults.Count().ShouldBe(2);
        successResults.ShouldAllBe(r => r.SignedPdf != null);

        errorResults.Count().ShouldBe(1);
        errorResults[0].Error.ShouldNotBeNull();
        errorResults[0].Id.ShouldBe("invalid-1");
    }

    [Fact(DisplayName = "BatchSigner SignAllAsync with expired cert returns all errors")]
    [Trait("Category", "BatchError")]
    public async Task BatchSigner_SignAllAsync_AllInvalid_ReturnsAllErrors()
    {
        using var cert = CreateExpiredCert();
        await using var signer = BatchSigner.Create(cert).Build();

        var results = new List<BatchSignResult>();
        await foreach (var result in signer.SignAllAsync(GenerateValidInputs(3)))
        {
            results.Add(result);
        }

        results.Count().ShouldBe(3);
        results.ShouldAllBe(r => !r.IsSuccess);
        results.ShouldAllBe(r => r.Error != null);
        results.ShouldAllBe(r => r.SignedPdf == null);
    }

    [Fact(DisplayName = "BatchSigner SignAsync with expired cert throws with meaningful message")]
    [Trait("Category", "BatchError")]
    public async Task BatchSigner_SignAsync_InvalidPdf_ThrowsWithMeaningfulMessage()
    {
        using var cert = CreateExpiredCert();
        await using var signer = BatchSigner.Create(cert).Build();

        var act = () => signer.SignAsync(CreateMinimalPdf());

        var exception = await Should.ThrowAsync<CertificateValidationException>(act);
        exception.Message.ShouldContain("expired");
    }

    private static async IAsyncEnumerable<(string Id, byte[] PdfBytes)> GenerateMixedInputs()
    {
        await Task.CompletedTask;
        yield return ("valid-0", CreateMinimalPdf());
        yield return ("invalid-1", null!);
        yield return ("valid-2", CreateMinimalPdf());
    }

    private static async IAsyncEnumerable<(string Id, byte[] PdfBytes)> GenerateValidInputs(int count)
    {
        for (var i = 0; i < count; i++)
        {
            await Task.CompletedTask;
            yield return ($"doc-{i}", CreateMinimalPdf());
        }
    }
}
