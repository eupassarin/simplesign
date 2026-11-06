using System.Net;
using System.Net.Http.Headers;
using Shouldly;
using SimpleSign.CAdES;
using SimpleSign.Core.Constants;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Http;
using SimpleSign.Core.Signing;
using SimpleSign.Core.Validation;
using SimpleSign.TestHelpers;

namespace SimpleSign.Brazil.IcpBrasil.Tests;

/// <summary>CAdES under ICP-Brasil AD-RT, AD-RV, AD-RC and AD-RA: the attributes each PA mandates.</summary>
[Trait("Category", "Unit")]
public sealed class IcpBrasilCadesPolicyTests : IDisposable
{
    private const string LeafCrlUrl = "http://198.51.100.1/leaf.crl";
    private const string IntermediateCrlUrl = "http://198.51.100.1/intermediate.crl";
    private readonly byte[] _data = "contrato"u8.ToArray();
    private readonly SyntheticPki _pki = new(crlDistributionPoint: LeafCrlUrl, intermediateCrlDistributionPoint: IntermediateCrlUrl);
    private readonly HttpClient _http;
    private readonly TimestampOptions _tsa;

    public IcpBrasilCadesPolicyTests()
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

    private Task<byte[]> Sign(IcpBrasilPolicy policy) =>
        CadesSigner.Document(_data)
            .WithCertificate(_pki.Leaf, _pki.IntermediatesAndRoot())
            .WithHttpClientProvider(new SingleClientProvider(_http))
            .WithIcpBrasilPolicy(policy, policy == IcpBrasilPolicy.AdRb ? null : _tsa)
            .SignAsync();

    [Theory]
    [InlineData(IcpBrasilPolicy.AdRb)]
    [InlineData(IcpBrasilPolicy.AdRt)]
    [InlineData(IcpBrasilPolicy.AdRv)]
    [InlineData(IcpBrasilPolicy.AdRc)]
    [InlineData(IcpBrasilPolicy.AdRa)]
    public async Task WithIcpBrasilPolicy_HasEveryAttributeThePolicyMandates(IcpBrasilPolicy policy)
    {
        byte[] p7s = await Sign(policy);

        var cms = CmsParser.ParseAll(p7s).Signers[0];
        var check = IcpBrasilPolicyValidator.Validate(cms, DateTimeOffset.UtcNow, IcpBrasilPolicyFormat.Cades, signerRoot: null);
        check.Status.ShouldBe(IcpBrasilPolicyStatus.Valid, string.Join("; ", check.Errors));
        check.Policy!.Info.Policy.ShouldBe(policy);
    }

    [Fact]
    public async Task AdRv_EscTimeStampCoversSignatureAndReferences()
    {
        byte[] p7s = await Sign(IcpBrasilPolicy.AdRv);

        var result = Validator().Validate(p7s, _data);

        result.IsSignatureValid.ShouldBeTrue(string.Join("; ", result.Errors));
        result.HasValidEscTimestamp.ShouldBe(true);
        var cms = CmsParser.Parse(p7s);
        cms.UnsignedAttributes!.Keys.ShouldContain(Oids.CertificateRefs);
        cms.UnsignedAttributes.Keys.ShouldContain(Oids.RevocationRefs);
        cms.UnsignedAttributes.Keys.ShouldNotContain(Oids.CertValues);
    }

    [Fact]
    public async Task AdRa_ArchiveTimeStampV2CoversTheContent()
    {
        byte[] p7s = await Sign(IcpBrasilPolicy.AdRa);

        var valid = Validator().Validate(p7s, _data);
        var tampered = Validator().Validate(p7s, "contrato alterado"u8.ToArray());

        valid.HasValidArchiveTimestamp.ShouldBe(true, string.Join("; ", valid.Errors.Concat(valid.Warnings)));
        tampered.IsIntegrityValid.ShouldBeFalse();
        tampered.HasValidArchiveTimestamp.ShouldBe(false);
        CmsParser.Parse(p7s).UnsignedAttributes!.Keys.ShouldContain(Oids.ArchiveTimeStamp);
    }

    [Fact]
    public async Task AdRc_ValuesCarryThePathAndItsLcrs()
    {
        byte[] p7s = await Sign(IcpBrasilPolicy.AdRc);

        var cms = CmsParser.Parse(p7s);
        cms.UnsignedAttributes!.Keys.ShouldContain(Oids.CertValues);
        cms.UnsignedAttributes.Keys.ShouldContain(Oids.RevocationValues);
        Validator().Validate(p7s, _data).HasValidEscTimestamp.ShouldBe(true);
    }

    [Fact]
    public void AboveAdRbWithoutTsa_Throws() =>
        Should.Throw<ArgumentException>(() => CadesSigner.Document(_data).WithCertificate(_pki.Leaf).WithIcpBrasilPolicy(IcpBrasilPolicy.AdRc));

    private static CadesSignatureValidator Validator() =>
        new(new ValidationOptions { CheckRevocation = false, TrustSystemRoots = false });
}
