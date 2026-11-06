using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Shouldly;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Extensions;
using SimpleSign.Core.Http;
using SimpleSign.Core.Signing;
using SimpleSign.Core.Validation;
using SimpleSign.PAdES;
using SimpleSign.PAdES.Validation;
using SimpleSign.TestHelpers;

namespace SimpleSign.Brazil.IcpBrasil.Tests;

/// <summary>
/// PAdES under ICP-Brasil AD-RB, AD-RT, AD-RC and AD-RA: the PBAD signature dictionary, the DSS,
/// the document timestamp and the AD-RA policy artifacts each PA mandates (2.16.76.1.8.1–3).
/// </summary>
[Trait("Category", "Unit")]
public sealed class IcpBrasilPadesPolicyTests : IDisposable
{
    private const string LeafCrlUrl = "http://198.51.100.1/leaf.crl";
    private const string IntermediateCrlUrl = "http://198.51.100.1/intermediate.crl";
    private readonly SyntheticPki _pki = new(crlDistributionPoint: LeafCrlUrl, intermediateCrlDistributionPoint: IntermediateCrlUrl);
    private readonly HttpClient _http;
    private readonly TimestampOptions _tsa;

    public IcpBrasilPadesPolicyTests()
    {
        byte[] leafCrl = _pki.BuildLeafCrl();
        byte[] intermediateCrl = _pki.BuildIntermediateCrl();
        _http = new HttpClient(new MockHttpHandler(async request =>
        {
            if (request.Method == HttpMethod.Post)
            {
                byte[] tsq = await request.Content!.ReadAsByteArrayAsync();
                var response = new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(TimestampTestResponseBuilder.CreateForRequest(tsq)) };
                response.Content.Headers.ContentType = new MediaTypeHeaderValue("application/timestamp-reply");
                return response;
            }

            byte[]? crl = request.RequestUri?.ToString() switch
            {
                LeafCrlUrl => leafCrl,
                IntermediateCrlUrl => intermediateCrl,
                _ => null,
            };
            return crl is null ? new HttpResponseMessage(HttpStatusCode.NotFound) : new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(crl) };
        }));
        _tsa = new TimestampOptions(new Uri("http://mock-tsa.example.com"), new SingleClientProvider(_http));
    }

    public void Dispose()
    {
        _http.Dispose();
        _pki.Dispose();
    }

    private static IcpBrasilPolicyArtifacts Artifacts() => new(
        IcpBrasilSignaturePolicies.Current(IcpBrasilPolicy.AdRa, IcpBrasilPolicyFormat.Pades),
        "PA bytes"u8.ToArray(), "LPA bytes"u8.ToArray(), "LPA signature bytes"u8.ToArray());

    private Task<byte[]> Sign(IcpBrasilPolicy policy) =>
        PadesSigner.Document(TestPdfFactory.CreateMinimalPdfWithPage())
            .WithCertificate(_pki.Leaf, _pki.IntermediatesAndRoot())
            .WithHttpClientProvider(new SingleClientProvider(_http))
            .WithIcpBrasilPolicy(policy, new IcpBrasilPadesOptions
            {
                Timestamp = policy == IcpBrasilPolicy.AdRb ? null : _tsa,
                LongTermValidation = new LongTermValidationOptions(new SingleClientProvider(_http)),
                Artifacts = policy == IcpBrasilPolicy.AdRa ? Artifacts() : null,
            })
            .SignAsync();

    // Validates the PDF and returns, for the first (non-timestamp) signature, its CMS and the PDF
    // facts the validator hands to chain validation providers.
    private async Task<(CmsSignedData Cms, PdfSignatureFacts Facts)> Inspect(byte[] signed)
    {
        var capture = new CapturingProvider();
        var validator = new PdfSignatureValidator(
            new ValidationOptions { CheckRevocation = false }, _http, logger: null, trustAnchorProviders: null, chainValidationProviders: [capture]);
        await using var stream = new MemoryStream(signed, writable: false);
        _ = await validator.ValidateAsync(stream);
        var context = capture.Contexts.First(c => c.Pdf is { SubFilter: not "ETSI.RFC3161" });
        return (context.Signature!, context.Pdf!);
    }

    [Theory]
    [InlineData(IcpBrasilPolicy.AdRb)]
    [InlineData(IcpBrasilPolicy.AdRt)]
    [InlineData(IcpBrasilPolicy.AdRc)]
    [InlineData(IcpBrasilPolicy.AdRa)]
    public async Task WithIcpBrasilPolicy_PdfHasEveryStructureThePolicyMandates(IcpBrasilPolicy policy)
    {
        byte[] signed = await Sign(policy);

        var (cms, facts) = await Inspect(signed);
        var check = IcpBrasilPolicyValidator.Validate(cms, DateTimeOffset.UtcNow, signerRoot: null, facts);

        check.Status.ShouldBe(IcpBrasilPolicyStatus.Valid, string.Join("; ", check.Errors));
        check.Policy!.Info.Policy.ShouldBe(policy);
        facts.Filter.ShouldBe("PBAD_PAdES");
        facts.SubFilter.ShouldBe("PBAD.PAdES");
    }

    [Theory]
    [InlineData(IcpBrasilPolicy.AdRc)]
    [InlineData(IcpBrasilPolicy.AdRa)]
    public async Task WithIcpBrasilPolicy_AdRcAdRa_EmbedDssVriAndDocumentTimestamp(IcpBrasilPolicy policy)
    {
        byte[] signed = await Sign(policy);

        var (_, facts) = await Inspect(signed);
        facts.HasDss.ShouldBeTrue();
        facts.DssKeys.ShouldContain("Certs");
        facts.HasVri.ShouldBeTrue();
        facts.HasLaterDocumentTimestamp.ShouldBeTrue();
        Encoding.Latin1.GetString(signed).ShouldContain("/Type /DocTimeStamp");
    }

    [Fact]
    public async Task WithIcpBrasilPolicy_AdRa_EmbedsPolicyArtifactsInDssAndVri()
    {
        byte[] signed = await Sign(IcpBrasilPolicy.AdRa);

        var (_, facts) = await Inspect(signed);
        facts.DssKeys.ShouldContain(IcpBrasilPolicyArtifacts.DssPolicyArtifacts);
        facts.DssKeys.ShouldContain(IcpBrasilPolicyArtifacts.DssLpaArtifacts);
        facts.DssKeys.ShouldContain(IcpBrasilPolicyArtifacts.DssLpaSignatures);
        facts.VriKeys.ShouldContain(IcpBrasilPolicyArtifacts.VriPolicyArtifact);
        facts.VriKeys.ShouldContain(IcpBrasilPolicyArtifacts.VriLpaArtifact);
        facts.VriKeys.ShouldContain(IcpBrasilPolicyArtifacts.VriLpaSignature);
    }

    [Fact]
    public async Task Validate_AdRcWithoutDssOrDocumentTimestamp_IsInvalid()
    {
        byte[] signed = await Sign(IcpBrasilPolicy.AdRc);
        var (cms, facts) = await Inspect(signed);

        var check = IcpBrasilPolicyValidator.Validate(cms, DateTimeOffset.UtcNow, signerRoot: null,
            facts with { HasDss = false, DssKeys = [], HasVri = false, VriKeys = [], HasLaterDocumentTimestamp = false });

        check.Status.ShouldBe(IcpBrasilPolicyStatus.Invalid);
        check.Errors.ShouldContain(e => e.Contains("DSS dictionary", StringComparison.Ordinal));
        check.Errors.ShouldContain(e => e.Contains("document timestamp", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Validate_AdRaWithoutArtifacts_IsInvalid()
    {
        byte[] signed = await Sign(IcpBrasilPolicy.AdRa);
        var (cms, facts) = await Inspect(signed);

        var check = IcpBrasilPolicyValidator.Validate(cms, DateTimeOffset.UtcNow, signerRoot: null,
            facts with { DssKeys = ["Type", "Certs", "CRLs", "VRI"], VriKeys = ["Type", "Cert", "CRL"] });

        check.Status.ShouldBe(IcpBrasilPolicyStatus.Invalid);
        check.Errors.Count(e => e.Contains("AD-RA requires PBAD_", StringComparison.Ordinal)).ShouldBe(6);
    }

    [Fact]
    public async Task Validate_EtsiSubFilter_IsInvalidForIcpPades()
    {
        byte[] signed = await Sign(IcpBrasilPolicy.AdRb);
        var (cms, facts) = await Inspect(signed);

        var check = IcpBrasilPolicyValidator.Validate(cms, DateTimeOffset.UtcNow, signerRoot: null,
            facts with { Filter = "Adobe.PPKLite", SubFilter = "ETSI.CAdES.detached" });

        check.Status.ShouldBe(IcpBrasilPolicyStatus.Invalid);
        check.Errors.ShouldContain(e => e.Contains("PBAD_PAdES", StringComparison.Ordinal));
    }

    [Fact]
    public void WithIcpBrasilPolicy_AdRaWithoutArtifacts_Throws()
    {
        var ex = Should.Throw<ArgumentException>(() => PadesSigner.Document(TestPdfFactory.CreateMinimalPdfWithPage())
            .WithCertificate(_pki.Leaf)
            .WithIcpBrasilPolicy(IcpBrasilPolicy.AdRa, new IcpBrasilPadesOptions { Timestamp = _tsa }));
        ex.Message.ShouldContain("Artifacts");
    }

    [Theory]
    [InlineData(IcpBrasilPolicy.AdRt)]
    [InlineData(IcpBrasilPolicy.AdRc)]
    public void WithIcpBrasilPolicy_TimestampedPolicyWithoutTsa_Throws(IcpBrasilPolicy policy) =>
        Should.Throw<ArgumentException>(() => PadesSigner.Document(TestPdfFactory.CreateMinimalPdfWithPage())
            .WithCertificate(_pki.Leaf)
            .WithIcpBrasilPolicy(policy, new IcpBrasilPadesOptions()));

    [Fact]
    public void WithIcpBrasilPolicy_ArtifactsForAnotherPolicy_Throws() =>
        Should.Throw<ArgumentException>(() => PadesSigner.Document(TestPdfFactory.CreateMinimalPdfWithPage())
            .WithCertificate(_pki.Leaf)
            .WithIcpBrasilPolicy(IcpBrasilPolicy.AdRc, new IcpBrasilPadesOptions { Timestamp = _tsa, Artifacts = Artifacts() }));

    [Fact]
    public void WithIcpBrasilPolicy_VersionOfAnotherPolicy_Throws() =>
        Should.Throw<ArgumentException>(() => PadesSigner.Document(TestPdfFactory.CreateMinimalPdfWithPage())
            .WithCertificate(_pki.Leaf)
            .WithIcpBrasilPolicy(IcpBrasilPolicy.AdRb, new IcpBrasilPadesOptions
            {
                Version = IcpBrasilSignaturePolicies.Current(IcpBrasilPolicy.AdRt, IcpBrasilPolicyFormat.Pades),
            }));

    [Fact]
    public void WithIcpBrasilPolicy_RevokedVersion_Throws()
    {
        var revoked = IcpBrasilSignaturePolicies.All.First(p => p.Oid == "2.16.76.1.7.1.11.1.2");

        Should.Throw<IcpBrasilPolicyException>(() => PadesSigner.Document(TestPdfFactory.CreateMinimalPdfWithPage())
            .WithCertificate(_pki.Leaf)
            .WithIcpBrasilPolicy(IcpBrasilPolicy.AdRb, new IcpBrasilPadesOptions { Version = revoked }));
    }

    [Fact]
    public async Task WithIcpBrasilPolicy_ExplicitVersion_IsWritten()
    {
        var version = IcpBrasilSignaturePolicies.All.First(p => p.Oid == "2.16.76.1.7.1.11.1.1");

        byte[] signed = await PadesSigner.Document(TestPdfFactory.CreateMinimalPdfWithPage())
            .WithCertificate(_pki.Leaf)
            .WithIcpBrasilPolicy(IcpBrasilPolicy.AdRb, new IcpBrasilPadesOptions { Version = version })
            .SignAsync();

        var (cms, _) = await Inspect(signed);
        CmsAttribute.ReadSignaturePolicy(cms.SignedAttrs!)!.Oid.ShouldBe(version.Oid);
    }

    [Fact]
    public void ToDssArtifacts_MapsEachArtifactToItsDssArrayAndVriEntry()
    {
        var artifacts = Artifacts().ToDssArtifacts();

        artifacts.Select(a => (a.DssKey, a.VriKey)).ShouldBe(
        [
            ("PBAD_PolicyArtifacts", "PBAD_PolicyArtifact"),
            ("PBAD_LpaArtifacts", "PBAD_LpaArtifact"),
            ("PBAD_LpaSignatures", "PBAD_LpaSignature"),
        ]);
    }

    private sealed class CapturingProvider : IChainValidationProvider
    {
        public List<ChainValidationContext> Contexts { get; } = [];

        public string RegionCode => "TEST";

        public bool CanValidate(X509Certificate2 certificate) => true;

        public Task<ChainValidationResult> ValidateAsync(X509Certificate2 certificate, IReadOnlyList<X509Certificate2>? chain = null) =>
            ValidateAsync(new ChainValidationContext { Certificate = certificate }, CancellationToken.None);

        public Task<ChainValidationResult> ValidateAsync(X509Certificate2 certificate, IReadOnlyList<X509Certificate2>? chain, CancellationToken cancellationToken) =>
            ValidateAsync(new ChainValidationContext { Certificate = certificate }, cancellationToken);

        public Task<ChainValidationResult> ValidateAsync(ChainValidationContext context, CancellationToken cancellationToken)
        {
            Contexts.Add(context);
            return Task.FromResult(new ChainValidationResult { IsTrusted = true, RegionCode = RegionCode });
        }
    }
}
