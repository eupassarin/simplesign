using System.Security.Cryptography.X509Certificates;
using System.Formats.Asn1;
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
        result.HasCompleteCoverage.ShouldBeFalse();
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
        result.HasCompleteCoverage.ShouldBeTrue();
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
        result.HasCompleteCoverage.ShouldBeFalse();
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

    [Fact]
    public async Task CollectAsync_WithPerCertificateCrls_RecordsCompleteEvidenceForEachPathCertificate()
    {
        using var pki = new SyntheticPki(
            crlDistributionPoint: "http://198.51.100.1/leaf.crl",
            intermediateCrlDistributionPoint: "http://198.51.100.1/intermediate.crl");
        byte[] leafCrl = pki.BuildLeafCrl();
        byte[] intermediateCrl = pki.BuildIntermediateCrl();
        var leafCrlReader = new AsnReader(leafCrl, AsnEncodingRules.DER).ReadSequence().ReadSequence();
        _ = leafCrlReader.ReadSequence();
        leafCrlReader.ReadEncodedValue().ToArray().ShouldBe(pki.IntermediateCa.SubjectName.RawData);
        LtvDataCollector.IsCrlIssuedFor(leafCrl, pki.Leaf, null).ShouldBeTrue();
        LtvDataCollector.IsCrlIssuedFor(intermediateCrl, pki.IntermediateCa, null).ShouldBeTrue();
        using var httpClient = new HttpClient(new MockHttpHandler(request =>
        {
            byte[]? response = request.RequestUri?.AbsolutePath switch
            {
                "/leaf.crl" => leafCrl,
                "/intermediate.crl" => intermediateCrl,
                _ => null,
            };
            return Task.FromResult(response is null
                ? new HttpResponseMessage(System.Net.HttpStatusCode.NotFound)
                : new HttpResponseMessage(System.Net.HttpStatusCode.OK)
                {
                    Content = new ByteArrayContent(response)
                });
        }));

        var result = await LtvDataCollector.CollectAsync(
            httpClient, pki.Leaf, pki.IntermediatesAndRoot(), null);

        result.HasCompleteCoverage.ShouldBeTrue();
        result.CertificateEvidence.ShouldNotBeNull();
        result.CertificateEvidence!.Count.ShouldBe(3);
        result.CertificateEvidence!.ShouldContain(e =>
            e.Thumbprint == pki.Leaf.Thumbprint && e.RevocationEvidenceKind == LtvRevocationEvidenceKind.Crl);
        result.CertificateEvidence!.ShouldContain(e =>
            e.Thumbprint == pki.IntermediateCa.Thumbprint && e.RevocationEvidenceKind == LtvRevocationEvidenceKind.Crl);
        result.CertificateEvidence!.ShouldContain(e =>
            e.Thumbprint == pki.RootCa.Thumbprint && e.RevocationEvidenceKind == LtvRevocationEvidenceKind.NotRequired);
    }

    [Fact]
    public async Task CollectAsync_MissingIssuerPublishedByAia_CompletesCertificatePath()
    {
        const string leafCrlUrl = "http://198.51.100.1/leaf.crl";
        const string intermediateCrlUrl = "http://198.51.100.1/intermediate.crl";
        const string rootCertificateUrl = "http://198.51.100.1/root.crt";
        using var pki = new SyntheticPki(
            crlDistributionPoint: leafCrlUrl,
            intermediateCrlDistributionPoint: intermediateCrlUrl,
            intermediateCaIssuersUrl: rootCertificateUrl);
        byte[] leafCrl = pki.BuildLeafCrl();
        byte[] intermediateCrl = pki.BuildIntermediateCrl();
        using var httpClient = new HttpClient(new MockHttpHandler(request =>
        {
            byte[]? response = request.RequestUri?.ToString() switch
            {
                leafCrlUrl => leafCrl,
                intermediateCrlUrl => intermediateCrl,
                rootCertificateUrl => pki.RootCa.RawData,
                _ => null,
            };
            return Task.FromResult(response is null
                ? new HttpResponseMessage(System.Net.HttpStatusCode.NotFound)
                : new HttpResponseMessage(System.Net.HttpStatusCode.OK)
                {
                    Content = new ByteArrayContent(response)
                });
        }));

        var result = await LtvDataCollector.CollectAsync(
            httpClient,
            pki.Leaf,
            [pki.IntermediateCa],
            logger: null);

        result.HasCompleteCoverage.ShouldBeTrue();
        result.CertificateRawData.ShouldContain(raw => raw.SequenceEqual(pki.RootCa.RawData));
        result.CertificateEvidence.ShouldNotBeNull();
        result.CertificateEvidence!.ShouldContain(item =>
            item.Thumbprint == pki.RootCa.Thumbprint &&
            item.RevocationEvidenceKind == LtvRevocationEvidenceKind.NotRequired);
    }

    [Fact]
    public async Task CollectAsync_WithIrrelevantCrl_DoesNotMarkCertificateComplete()
    {
        using var pki = new SyntheticPki(crlDistributionPoint: "http://198.51.100.1/leaf.crl");
        using var httpClient = new HttpClient(new MockHttpHandler(_ => Task.FromResult(
            new HttpResponseMessage(System.Net.HttpStatusCode.OK)
            {
                Content = new ByteArrayContent(pki.BuildIntermediateCrl())
            })));

        var result = await LtvDataCollector.CollectAsync(
            httpClient, pki.Leaf, [pki.IntermediateCa], null);

        result.HasCompleteCoverage.ShouldBeFalse();
        result.CertificateEvidence!.ShouldContain(e =>
            e.Thumbprint == pki.Leaf.Thumbprint && !e.IsComplete &&
            e.RevocationEvidenceKind == LtvRevocationEvidenceKind.None);
    }

    [Fact]
    public async Task CollectAsync_CancellationDuringOcsp_DoesNotFetchCrl()
    {
        using var pki = new SyntheticPki(
            crlDistributionPoint: "http://198.51.100.1/crl",
            ocspResponder: "http://198.51.100.1/ocsp");
        using var cts = new CancellationTokenSource();
        var requestedPaths = new List<string>();
        using var httpClient = new HttpClient(new MockHttpHandler(request =>
        {
            requestedPaths.Add(request.RequestUri!.AbsolutePath);
            cts.Cancel();
            return Task.FromCanceled<HttpResponseMessage>(cts.Token);
        }));

        await Should.ThrowAsync<OperationCanceledException>(() =>
            LtvDataCollector.CollectAsync(
                httpClient, pki.Leaf, pki.IntermediatesAndRoot(), null,
                cancellationToken: cts.Token));

        requestedPaths.ShouldHaveSingleItem().ShouldBe("/ocsp");
    }
}
