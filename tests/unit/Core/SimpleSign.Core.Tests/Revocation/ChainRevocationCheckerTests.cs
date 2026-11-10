using System.Net;
using Shouldly;
using SimpleSign.Core.Extensions;
using SimpleSign.Core.Revocation;
using SimpleSign.Core.Validation;
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
    public async Task CheckAsync_OnlineCrlsServedAsPem_ReadsThemAsDer()
    {
        using var pki = NewPki();
        using var http = CrlServer(Pem(pki.BuildLeafCrl()), Pem(pki.BuildIntermediateCrl()));

        var result = await new ChainRevocationChecker(http).CheckAsync(pki.Chain(), DateTimeOffset.UtcNow, [], [], true, default);

        result.Status.ShouldBe(ChainRevocationStatus.Good);
    }

    [Fact]
    public async Task CheckAsync_PemCrlRevokesLeaf_ReturnsRevoked()
    {
        using var pki = NewPki();
        using var http = CrlServer(Pem(pki.BuildRevokedLeafCrl()), Pem(pki.BuildIntermediateCrl()));

        var result = await new ChainRevocationChecker(http).CheckAsync(pki.Chain(), DateTimeOffset.UtcNow, [], [], true, default);

        result.Status.ShouldBe(ChainRevocationStatus.Revoked);
    }

    private static byte[] Pem(byte[] der) =>
        System.Text.Encoding.ASCII.GetBytes(new string(System.Security.Cryptography.PemEncoding.Write("X509 CRL", der)) + "\n");

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
    public async Task CheckAsync_EmbeddedCrl_ReportsItsThisUpdate()
    {
        using var pki = NewPki();
        using var http = MockHttpHandler.Failing();
        var issued = new DateTimeOffset(DateTimeOffset.UtcNow.AddDays(-2).Date, TimeSpan.Zero);

        var result = await new ChainRevocationChecker(http).CheckAsync(
            pki.Chain(), DateTimeOffset.UtcNow, [pki.BuildLeafCrl(issued, issued.AddDays(30)), pki.BuildIntermediateCrl()], [], false, default);

        result.Status.ShouldBe(ChainRevocationStatus.Good);
        result.IssuedAt.ShouldBe(issued);
    }

    [Theory]
    [InlineData(RevocationStrategy.CrlFirst, false, ChainRevocationStatus.Good)]
    [InlineData(RevocationStrategy.OcspFirst, true, ChainRevocationStatus.Good)]
    [InlineData(RevocationStrategy.OcspFirst, false, ChainRevocationStatus.Unknown)]
    public async Task CheckAsync_StrategyAndFallback_DecideWhichSourceAnswers(
        RevocationStrategy strategy, bool fallback, ChainRevocationStatus expected)
    {
        // The certificates name no OCSP responder: OCSP first without fallback gives no answer.
        using var pki = NewPki();
        using var http = CrlServer(pki.BuildLeafCrl(), pki.BuildIntermediateCrl());
        var checker = new ChainRevocationChecker(http) { Strategy = strategy, Fallback = fallback };

        var result = await checker.CheckAsync(pki.Chain(), DateTimeOffset.UtcNow, [], [], true, default);

        result.Status.ShouldBe(expected);
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

    [Fact]
    public async Task CheckCurrentAsync_RevokedAfterTheCrlWasCached_ReturnsRevoked()
    {
        // A stale CRL: the copy cached while the leaf was good must not decide before signing.
        using var pki = NewPki();
        byte[] leafCrl = pki.BuildLeafCrl();
        byte[] intermediateCrl = pki.BuildIntermediateCrl();
        using var http = new HttpClient(new MockHttpHandler(request =>
        {
            byte[] body = request.RequestUri!.AbsoluteUri == LeafCrlUrl ? Volatile.Read(ref leafCrl) : intermediateCrl;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(body) });
        }));
        var checker = new ChainRevocationChecker(http);
        (await checker.CheckAsync(pki.Chain(), DateTimeOffset.UtcNow, [], [], true, default)).Status.ShouldBe(ChainRevocationStatus.Good);

        Volatile.Write(ref leafCrl, pki.BuildRevokedLeafCrl());
        var cached = await checker.CheckAsync(pki.Chain(), DateTimeOffset.UtcNow, [], [], true, default);
        var current = await checker.CheckCurrentAsync(pki.Chain(), default);

        cached.Status.ShouldBe(ChainRevocationStatus.Good);
        current.Status.ShouldBe(ChainRevocationStatus.Revoked);
        current.Messages.ShouldHaveSingleItem().ShouldContain("revoked");
        // The fresh CRL replaced the cached one.
        (await checker.CheckAsync(pki.Chain(), DateTimeOffset.UtcNow, [], [], true, default)).Status.ShouldBe(ChainRevocationStatus.Revoked);
    }

    [Fact]
    public async Task CheckCurrentAsync_NoOcspAndCrlsGood_ReturnsGood()
    {
        using var pki = NewPki();
        using var http = CrlServer(pki.BuildLeafCrl(), pki.BuildIntermediateCrl());

        var result = await new ChainRevocationChecker(http).CheckCurrentAsync(pki.Chain(), default);

        result.Status.ShouldBe(ChainRevocationStatus.Good);
    }

    [Fact]
    public async Task CheckCurrentAsync_NetworkFailure_ReturnsUnknownForEachCertificate()
    {
        using var pki = NewPki();
        using var http = MockHttpHandler.Failing();

        var result = await new ChainRevocationChecker(http).CheckCurrentAsync(pki.Chain(), default);

        result.Status.ShouldBe(ChainRevocationStatus.Unknown);
        result.Messages.Count.ShouldBe(2);
    }

    [Fact]
    public async Task CheckCurrentAsync_DefaultImplementation_ChecksOnlineNow()
    {
        var checker = new RecordingChecker();
        IChainRevocationChecker asInterface = checker;

        await asInterface.CheckCurrentAsync([], default);

        checker.AllowOnline.ShouldBeTrue();
        checker.Time.ShouldBe(DateTimeOffset.UtcNow, TimeSpan.FromMinutes(1));
    }

    /// <summary>An implementation written before CheckCurrentAsync existed.</summary>
    private sealed class RecordingChecker : IChainRevocationChecker
    {
        public bool AllowOnline { get; private set; }

        public DateTimeOffset Time { get; private set; }

        public Task<ChainRevocationResult> CheckAsync(IReadOnlyList<System.Security.Cryptography.X509Certificates.X509Certificate2> chain, DateTimeOffset time,
            IReadOnlyList<byte[]> embeddedCrls, IReadOnlyList<byte[]> embeddedOcsps, bool allowOnline, CancellationToken cancellationToken)
        {
            AllowOnline = allowOnline;
            Time = time;
            return Task.FromResult(new ChainRevocationResult(ChainRevocationStatus.Good, []));
        }
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
