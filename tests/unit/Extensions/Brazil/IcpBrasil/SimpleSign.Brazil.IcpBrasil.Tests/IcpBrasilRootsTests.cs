using System.Net;
using System.Security.Cryptography;
using Shouldly;
using SimpleSign.Core.Extensions;
using SimpleSign.TestHelpers;

namespace SimpleSign.Brazil.IcpBrasil.Tests;

/// <summary>Bundled AC Raiz certificates, their expiry, and pinned additional roots.</summary>
[Trait("Category", "Unit")]
public sealed class IcpBrasilRootsTests
{
    // Fails a year before a bundled AC Raiz expires (v5: 2029-03-02): bundle the successor.
    [Fact]
    public void Bundled_NoRootExpiresWithinAYear() =>
        IcpBrasilRoots.ExpiringWithin(TimeSpan.FromDays(365)).Select(c => c.Subject).ShouldBeEmpty();

    [Fact]
    public void ExpiringWithin_FarAhead_ListsV5() =>
        IcpBrasilRoots.ExpiringWithin(TimeSpan.FromDays(365 * 4), new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero))
            .ShouldContain(c => c.Subject.Contains("v5", StringComparison.Ordinal));

    [Fact]
    public void FromPinnedBytes_MatchingFingerprint_ReturnsRoot()
    {
        var bundled = IcpBrasilRoots.Bundled[^1];
        string fingerprint = Convert.ToHexString(SHA256.HashData(bundled.RawData));

        using var root = IcpBrasilRoots.FromPinnedBytes(bundled.RawData, string.Join(':', fingerprint.Chunk(2).Select(c => new string(c))));

        root.Thumbprint.ShouldBe(bundled.Thumbprint);
    }

    [Fact]
    public void FromPinnedBytes_WrongFingerprint_Throws() =>
        Should.Throw<CryptographicException>(() => IcpBrasilRoots.FromPinnedBytes(IcpBrasilRoots.Bundled[0].RawData, new string('0', 64)));

    [Fact]
    public void FromPinnedBytes_NotAnIcpRoot_Throws()
    {
        using var cert = TestCertificateFactory.CreateSelfSignedCert();
        string fingerprint = Convert.ToHexString(SHA256.HashData(cert.RawData));

        Should.Throw<CryptographicException>(() => IcpBrasilRoots.FromPinnedBytes(cert.RawData, fingerprint));
    }

    [Fact]
    public async Task DownloadAsync_ChecksFingerprint()
    {
        var bundled = IcpBrasilRoots.Bundled[^1];
        Uri? requested = null;
        using var http = new HttpClient(new MockHttpHandler(r =>
        {
            requested = r.RequestUri;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(bundled.RawData) });
        }));

        using var root = await IcpBrasilRoots.DownloadAsync(http, 14, Convert.ToHexString(SHA256.HashData(bundled.RawData)));

        requested!.AbsoluteUri.ShouldBe("http://acraiz.icpbrasil.gov.br/ICP-Brasilv14.crt");
        root.IsSelfSigned().ShouldBeTrue();
    }

    [Fact]
    public async Task AdditionalTrustAnchors_AreTrusted()
    {
        using var pki = TestPki.Create(leafExpired: false);
        var validator = new IcpBrasilChainValidator(new HttpClient(new MockHttpHandler(_ =>
            Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound)))))
        {
            AdditionalTrustAnchors = [pki.Root],
        };

        var result = await validator.ValidateAsync(new ChainValidationContext
        {
            Certificate = pki.Leaf,
            Certificates = [pki.Ac],
            CheckRevocation = false,
        });

        result.IsChainValid.ShouldBeTrue(string.Join("; ", result.Errors));
    }
}
