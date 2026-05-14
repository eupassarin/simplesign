using System.Security.Cryptography.X509Certificates;
using FluentAssertions;
using SimpleSign.PAdES.Signing;
using SimpleSign.PAdES.Validation;
using SimpleSign.TestHelpers;
using Xunit;

namespace SimpleSign.PAdES.Tests.Signing;

/// <summary>
/// Verifies that PAdES signing and validation APIs respect CancellationToken.
/// Uses a pre-canceled token to confirm methods throw OperationCanceledException.
/// </summary>
[Trait("Category", "Cancellation")]
public sealed class CancellationTokenTests : IDisposable
{
    private static readonly CancellationToken CanceledToken = new(canceled: true);

    private static readonly byte[] MinimalPdf =
        "%PDF-1.7\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\nxref\n0 3\n0000000000 65535 f \n0000000009 00000 n \n0000000058 00000 n \ntrailer\n<< /Size 3 /Root 1 0 R >>\nstartxref\n110\n%%EOF"u8.ToArray();

    private readonly X509Certificate2 _cert;

    public CancellationTokenTests()
    {
        _cert = TestCertificateFactory.CreateSelfSignedCert("CN=PAdES Cancel Test");
    }

    public void Dispose() => _cert.Dispose();

    // ── PAdES Signing ─────────────────────────────────────────────────────────

    [Fact(DisplayName = "SignerBuilder.SignAsync(canceledToken) throws OperationCanceledException")]
    public async Task SignerBuilder_SignAsync_Bytes_CanceledToken_Throws()
    {
        Func<Task> act = () => SimpleSigner
            .Document(MinimalPdf)
            .WithCertificate(_cert)
            .SignAsync(CanceledToken);

        await act.Should().ThrowAsync<OperationCanceledException>();
    }

    [Fact(DisplayName = "SignerBuilder.SignAsync(stream, canceledToken) throws OperationCanceledException")]
    public async Task SignerBuilder_SignAsync_Stream_CanceledToken_Throws()
    {
        using var output = new MemoryStream();

        Func<Task> act = () => SimpleSigner
            .Document(MinimalPdf)
            .WithCertificate(_cert)
            .SignAsync(output, CanceledToken);

        await act.Should().ThrowAsync<OperationCanceledException>();
    }

    [Fact(DisplayName = "BatchSigner.SignAsync(bytes, canceledToken) throws OperationCanceledException")]
    public async Task BatchSigner_SignAsync_Bytes_CanceledToken_Throws()
    {
        await using var signer = BatchSigner.Create(_cert).Build();

        Func<Task> act = () => signer.SignAsync(MinimalPdf, CanceledToken);

        await act.Should().ThrowAsync<OperationCanceledException>();
    }

    [Fact(DisplayName = "BatchSigner.SignAllAsync with canceled token throws OperationCanceledException")]
    public async Task BatchSigner_SignAllAsync_CanceledToken_Throws()
    {
        await using var signer = BatchSigner.Create(_cert).Build();

        Func<Task> act = async () =>
        {
            await foreach (var _ in signer.SignAllAsync(GetInputs(), CanceledToken))
            {
            }
        };

        await act.Should().ThrowAsync<OperationCanceledException>();

        static async IAsyncEnumerable<(string Id, byte[] PdfBytes)> GetInputs()
        {
            yield return ("doc1", MinimalPdf);
            await Task.CompletedTask;
        }
    }

    // ── PAdES Validation ──────────────────────────────────────────────────────

    [Fact(DisplayName = "PdfSignatureValidator.ValidateAsync(canceledToken) throws OperationCanceledException")]
    public async Task Validator_ValidateAsync_CanceledToken_Throws()
    {
        var validator = new PdfSignatureValidator();
        using var stream = new MemoryStream(MinimalPdf);

        Func<Task> act = () => validator.ValidateAsync(stream, cancellationToken: CanceledToken);

        await act.Should().ThrowAsync<OperationCanceledException>();
    }

    [Fact(DisplayName = "PdfSignatureValidator.ValidateFieldAsync(canceledToken) throws OperationCanceledException")]
    public async Task Validator_ValidateFieldAsync_CanceledToken_Throws()
    {
        var validator = new PdfSignatureValidator();
        using var stream = new MemoryStream(MinimalPdf);

        Func<Task> act = () => validator.ValidateFieldAsync(stream, "Signature1", CanceledToken);

        await act.Should().ThrowAsync<OperationCanceledException>();
    }
}
