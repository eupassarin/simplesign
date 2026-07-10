using System.Security.Cryptography.X509Certificates;
using SimpleSign.TestHelpers;
using Shouldly;
using Xunit;

namespace SimpleSign.CAdES.Tests;

public sealed class LtvDataCollectorTests : IDisposable
{
    private readonly SyntheticPki _pki;
    private readonly X509Certificate2 _selfSigned;

    public LtvDataCollectorTests()
    {
        _pki = new SyntheticPki("http://localhost/crl", "http://localhost/ocsp");
        _selfSigned = TestCertificateFactory.CreateSelfSignedCert();
    }

    public void Dispose()
    {
        _pki.Dispose();
        _selfSigned.Dispose();
    }

    [Fact]
    public void LtvCollectionResult_Parameters_AreStoredCorrectly()
    {
        var certs = new byte[][] { [1, 2, 3] };
        var ocsp = new byte[][] { [4, 5, 6] };
        var crls = new byte[][] { [7, 8, 9] };

        var result = new LtvCollectionResult(certs, ocsp, crls);

        result.CertificateRawData.ShouldHaveSingleItem();
        result.CertificateRawData[0].ShouldBe([1, 2, 3]);
        result.OcspResponses.ShouldHaveSingleItem();
        result.OcspResponses[0].ShouldBe([4, 5, 6]);
        result.Crls.ShouldHaveSingleItem();
        result.Crls[0].ShouldBe([7, 8, 9]);
    }

    [Fact]
    public async Task CollectAsync_WithCertWithoutRevocationUrls_ReturnsEmptyOcspAndCrls()
    {
        using var httpClient = new HttpClient(new MockHttpHandler(_ =>
            throw new HttpRequestException()));

        var result = await LtvDataCollector.CollectAsync(httpClient, _selfSigned, null, null);

        result.CertificateRawData.ShouldHaveSingleItem();
        result.CertificateRawData[0].ShouldBe(_selfSigned.RawData);
        result.OcspResponses.ShouldBeEmpty();
        result.Crls.ShouldBeEmpty();
    }

    [Fact]
    public async Task CollectAsync_WithRevocationUrls_FailingNetwork_ReturnsCertDataWithoutRevocation()
    {
        using var httpClient = MockHttpHandler.Failing();

        var result = await LtvDataCollector.CollectAsync(
            httpClient, _pki.Leaf, [_pki.IntermediateCa], null);

        result.CertificateRawData.ShouldNotBeEmpty();
        result.CertificateRawData.Count.ShouldBeGreaterThanOrEqualTo(2);
        result.OcspResponses.ShouldBeEmpty();
        result.Crls.ShouldBeEmpty();
    }

    [Fact]
    public async Task CollectAsync_NullSignerCert_ThrowsArgumentNullException()
    {
        using var httpClient = new HttpClient();

        var ex = await Should.ThrowAsync<ArgumentNullException>(
            () => LtvDataCollector.CollectAsync(httpClient, null!, null, null));

        ex.ParamName.ShouldBe("signerCert");
    }

    [Fact]
    public async Task CollectAsync_NullHttpClient_ThrowsArgumentNullException()
    {
        var ex = await Should.ThrowAsync<ArgumentNullException>(
            () => LtvDataCollector.CollectAsync(null!, _selfSigned, null, null));

        ex.ParamName.ShouldBe("httpClient");
    }

    [Fact]
    public async Task CollectAsync_WithChain_IncludesChainCertificates()
    {
        using var httpClient = MockHttpHandler.Failing();

        var result = await LtvDataCollector.CollectAsync(
            httpClient, _pki.Leaf, [_pki.IntermediateCa, _pki.RootCa], null);

        result.CertificateRawData.Count.ShouldBe(3);
        result.CertificateRawData.ShouldContain(b => b.SequenceEqual(_pki.Leaf.RawData));
        result.CertificateRawData.ShouldContain(b => b.SequenceEqual(_pki.IntermediateCa.RawData));
        result.CertificateRawData.ShouldContain(b => b.SequenceEqual(_pki.RootCa.RawData));
    }

    [Fact]
    public async Task CollectAsync_WithDuplicateCertInChain_RemovesDuplicates()
    {
        using var httpClient = MockHttpHandler.Failing();

        var result = await LtvDataCollector.CollectAsync(
            httpClient, _pki.Leaf, [_pki.Leaf, _pki.IntermediateCa], null);

        result.CertificateRawData.Count.ShouldBe(2);
        result.CertificateRawData.ShouldContain(b => b.SequenceEqual(_pki.Leaf.RawData));
        result.CertificateRawData.ShouldContain(b => b.SequenceEqual(_pki.IntermediateCa.RawData));
    }
}
