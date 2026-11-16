using Shouldly;
using SimpleSign.Core.Revocation;
using SimpleSign.Core.Validation;
using SimpleSign.PAdES.Validation;
using SimpleSign.TestHelpers;
using Xunit;

namespace SimpleSign.PAdES.Tests.Validation;

/// <summary>A <see cref="PdfSignatureValidator"/> sharing revocation data with the rest of the application.</summary>
[Trait("Category", "Unit")]
public sealed class PdfSignatureValidatorSharedRevocationTests : IDisposable
{
    private readonly SyntheticPkiServer _server = new();

    public void Dispose() => _server.Dispose();

    private PdfSignatureValidator Validator(IRevocationCache? cache, IChainRevocationChecker? checker = null) => new(
        _server.Provider,
        new ValidationOptions { CheckRevocation = true, TrustSystemRoots = false },
        logger: null,
        trustAnchorProviders: [new InMemoryTrustAnchors(_server.Pki.RootCa)],
        chainValidationProviders: null,
        chainRevocationChecker: checker,
        revocationCache: cache);

    private async Task<byte[]> SignedAsync() => await PadesSigner.Document(TestPdfFactory.CreateMinimalPdf())
        .WithCertificate(_server.Pki.Leaf, _server.Pki.IntermediatesAndRoot())
        .WithHttpClientProvider(_server.Provider)
        .SignAsync();

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task ValidateAsync_TwoValidatorsSharingACache_DownloadTheCrlsOnce(bool shared)
    {
        byte[] signed = await SignedAsync();
        _server.ResetCount();
        var cache = new InMemoryRevocationCache(TimeSpan.FromHours(1));

        foreach (int _ in new[] { 1, 2 })
        {
            using var stream = new MemoryStream(signed);
            var result = (await Validator(shared ? cache : new InMemoryRevocationCache(TimeSpan.FromHours(1))).ValidateAsync(stream)).ShouldHaveSingleItem();
            result.IsCertificateChainValid.ShouldBeTrue(string.Join("; ", result.Errors));
            result.RevocationSource.ShouldBe(RevocationSource.OnlineCrl, string.Join("; ", result.Errors));
        }

        int perValidation = shared ? _server.CrlDownloads : _server.CrlDownloads / 2;
        perValidation.ShouldBeGreaterThan(0);
        _server.CrlDownloads.ShouldBe(shared ? perValidation : 2 * perValidation);
    }

    [Fact]
    public async Task ValidateAsync_CrlServerDownAfterAFirstValidation_StillChecksFromTheSharedCache()
    {
        byte[] signed = await SignedAsync();
        var cache = new InMemoryRevocationCache(TimeSpan.FromHours(1));
        using (var first = new MemoryStream(signed))
        {
            (await Validator(cache).ValidateAsync(first)).ShouldHaveSingleItem().RevocationSource.ShouldBe(RevocationSource.OnlineCrl);
        }

        _server.ResetCount();
        using var second = new MemoryStream(signed);
        var result = (await Validator(cache).ValidateAsync(second)).ShouldHaveSingleItem();

        result.RevocationSource.ShouldBe(RevocationSource.OnlineCrl, string.Join("; ", result.Errors));
        _server.CrlDownloads.ShouldBe(0);
    }
}
