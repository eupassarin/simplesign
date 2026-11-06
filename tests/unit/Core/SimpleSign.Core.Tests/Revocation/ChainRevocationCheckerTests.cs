using System.Net;
using Shouldly;
using SimpleSign.Core.Extensions;
using SimpleSign.Core.Revocation;
using SimpleSign.TestHelpers;
using Xunit;

namespace SimpleSign.Core.Tests.Revocation;

[Trait("Category", "Unit")]
public sealed class ChainRevocationCheckerTests
{
    private const string LeafCrlUrl = "http://198.51.100.1/leaf.crl";
    private const string IntermediateCrlUrl = "http://198.51.100.1/intermediate.crl";

    [Fact]
    public async Task CheckAsync_OnlineCrlsGood_ReturnsGood()
    {
        using var pki = NewPki();
        using var http = CrlServer(pki.BuildLeafCrl(), pki.BuildIntermediateCrl());

        var result = await new ChainRevocationChecker(http).CheckAsync(pki.Chain(), DateTimeOffset.UtcNow, [], [], true, default);

        result.Status.ShouldBe(ChainRevocationStatus.Good);
        result.Messages.ShouldBeEmpty();
    }

    [Fact]
    public async Task CheckAsync_OnlineCrlRevokesLeaf_ReturnsRevoked()
    {
        using var pki = NewPki();
        using var http = CrlServer(pki.BuildRevokedLeafCrl(), pki.BuildIntermediateCrl());

        var result = await new ChainRevocationChecker(http).CheckAsync(pki.Chain(), DateTimeOffset.UtcNow, [], [], true, default);

        result.Status.ShouldBe(ChainRevocationStatus.Revoked);
        result.Messages.ShouldHaveSingleItem().ShouldContain("revoked");
    }

    [Fact]
    public async Task CheckAsync_CrlWithTamperedSignature_ReturnsUnknown()
    {
        using var pki = NewPki();
        byte[] tampered = pki.BuildLeafCrl();
        tampered[^1] ^= 0xFF;
        using var http = CrlServer(tampered, pki.BuildIntermediateCrl());

        var result = await new ChainRevocationChecker(http).CheckAsync(pki.Chain(), DateTimeOffset.UtcNow, [], [], true, default);

        result.Status.ShouldBe(ChainRevocationStatus.Unknown);
    }

    [Fact]
    public async Task CheckAsync_CrlSignedByWrongIssuer_ReturnsUnknown()
    {
        using var pki = NewPki();
        // The intermediate CRL is signed by the root: it does not apply to the leaf.
        using var http = CrlServer(pki.BuildIntermediateCrl(), pki.BuildIntermediateCrl());

        var result = await new ChainRevocationChecker(http).CheckAsync(pki.Chain(), DateTimeOffset.UtcNow, [], [], true, default);

        result.Status.ShouldBe(ChainRevocationStatus.Unknown);
    }

    [Fact]
    public async Task CheckAsync_NetworkFailure_ReturnsUnknown()
    {
        using var pki = NewPki();
        using var http = MockHttpHandler.Failing();

        var result = await new ChainRevocationChecker(http).CheckAsync(pki.Chain(), DateTimeOffset.UtcNow, [], [], true, default);

        result.Status.ShouldBe(ChainRevocationStatus.Unknown);
    }

    [Fact]
    public async Task CheckAsync_EmbeddedRevokedCrlOffline_ReturnsRevoked()
    {
        using var pki = NewPki();
        using var http = MockHttpHandler.Failing();

        var result = await new ChainRevocationChecker(http).CheckAsync(
            pki.Chain(), DateTimeOffset.UtcNow, [pki.BuildRevokedLeafCrl(), pki.BuildIntermediateCrl()], [], false, default);

        result.Status.ShouldBe(ChainRevocationStatus.Revoked);
    }

    [Fact]
    public async Task CheckAsync_NoEvidenceOffline_ReturnsUnknown()
    {
        using var pki = NewPki();
        using var http = MockHttpHandler.Failing();

        var result = await new ChainRevocationChecker(http).CheckAsync(pki.Chain(), DateTimeOffset.UtcNow, [], [], false, default);

        result.Status.ShouldBe(ChainRevocationStatus.Unknown);
        result.Messages.Count.ShouldBe(2);
    }

    [Fact]
    public async Task CheckAsync_SecondCheck_ServesCrlsFromCache()
    {
        using var pki = NewPki();
        int downloads = 0;
        byte[] leafCrl = pki.BuildLeafCrl();
        byte[] intermediateCrl = pki.BuildIntermediateCrl();
        using var http = new HttpClient(new MockHttpHandler(request =>
        {
            Interlocked.Increment(ref downloads);
            byte[] body = request.RequestUri!.AbsoluteUri == LeafCrlUrl ? leafCrl : intermediateCrl;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(body) });
        }));
        var checker = new ChainRevocationChecker(http);

        await checker.CheckAsync(pki.Chain(), DateTimeOffset.UtcNow, [], [], true, default);
        var second = await checker.CheckAsync(pki.Chain(), DateTimeOffset.UtcNow, [], [], true, default);

        second.Status.ShouldBe(ChainRevocationStatus.Good);
        downloads.ShouldBe(2);
    }

    private static SyntheticPki NewPki() =>
        new(crlDistributionPoint: LeafCrlUrl, intermediateCrlDistributionPoint: IntermediateCrlUrl);

    private static HttpClient CrlServer(byte[] leafCrl, byte[] intermediateCrl) =>
        new(new MockHttpHandler(request =>
        {
            byte[]? body = request.RequestUri!.AbsoluteUri switch
            {
                LeafCrlUrl => leafCrl,
                IntermediateCrlUrl => intermediateCrl,
                _ => null,
            };
            return Task.FromResult(body is null
                ? new HttpResponseMessage(HttpStatusCode.NotFound)
                : new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(body) });
        }));
}
