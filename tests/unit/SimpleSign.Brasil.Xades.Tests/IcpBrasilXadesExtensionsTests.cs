using System.Net;
using System.Net.Http.Headers;
using Shouldly;
using SimpleSign.Brasil.IcpBrasil;
using SimpleSign.Core.Http;
using SimpleSign.Core.Signing;
using SimpleSign.Core.Validation;
using SimpleSign.TestHelpers;
using SimpleSign.XAdES;

namespace SimpleSign.Brasil.Xades.Tests;

/// <summary>XAdES under ICP-Brasil AD-RB…AD-RA: what each XML PA mandates is written and validates.</summary>
[Trait("Category", "Unit")]
public sealed class IcpBrasilXadesExtensionsTests : IDisposable
{
    private const string LeafCrlUrl = "http://198.51.100.1/leaf.crl";
    private const string IntermediateCrlUrl = "http://198.51.100.1/intermediate.crl";
    private readonly byte[] _xml = "<?xml version=\"1.0\"?><contrato><id>1</id></contrato>"u8.ToArray();
    private readonly SyntheticPki _pki = new(crlDistributionPoint: LeafCrlUrl, intermediateCrlDistributionPoint: IntermediateCrlUrl);
    private readonly HttpClient _http;
    private readonly TimestampOptions _tsa;

    public IcpBrasilXadesExtensionsTests()
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

    [Theory]
    [InlineData(IcpBrasilPolicy.AdRb)]
    [InlineData(IcpBrasilPolicy.AdRt)]
    [InlineData(IcpBrasilPolicy.AdRv)]
    [InlineData(IcpBrasilPolicy.AdRc)]
    [InlineData(IcpBrasilPolicy.AdRa)]
    public async Task WithIcpBrasilPolicy_HasEveryPropertyThePolicyMandates(IcpBrasilPolicy policy)
    {
        byte[] signed = await Sign(policy);

        var result = Validate(signed);
        result.IsSignatureValid.ShouldBeTrue(string.Join("; ", result.Errors));
        var check = IcpBrasilXadesPolicyValidator.Validate(signed, result);
        check.Status.ShouldBe(IcpBrasilPolicyStatus.Valid, string.Join("; ", check.Errors));
        check.Policy!.Info.Policy.ShouldBe(policy);
        check.Policy.Info.Format.ShouldBe(IcpBrasilPolicyFormat.Xades);
    }

    [Fact]
    public async Task WithIcpBrasilPolicy_WritesSigningCertificateV1AndThePaDigest()
    {
        byte[] signed = await Sign(IcpBrasilPolicy.AdRb);

        string xml = System.Text.Encoding.UTF8.GetString(signed);
        xml.ShouldContain("SigningCertificate>");
        xml.ShouldNotContain("SigningCertificateV2");
        var current = IcpBrasilSignaturePolicies.Current(IcpBrasilPolicy.AdRb, IcpBrasilPolicyFormat.Xades);
        Validate(signed).SignaturePolicy!.Hash.ToArray().ShouldBe(current.PolicyHash.ToArray());
    }

    [Fact]
    public async Task Validate_SigningCertificateV2_IsInvalid()
    {
        var current = IcpBrasilSignaturePolicies.Current(IcpBrasilPolicy.AdRb, IcpBrasilPolicyFormat.Xades);
        byte[] signed = await XadesSigner.Document(_xml).WithCertificate(_pki.Leaf, _pki.IntermediatesAndRoot())
            .WithSignaturePolicy(new Core.Crypto.SignaturePolicyReference(current.Oid, current.HashAlgorithmOid, current.PolicyHash, current.Uri))
            .SignAsync();

        var check = IcpBrasilXadesPolicyValidator.Validate(signed, Validate(signed));

        check.Status.ShouldBe(IcpBrasilPolicyStatus.Invalid);
        check.Errors.ShouldContain(e => e.Contains("SigningCertificateV2", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Validate_AdRcWithoutValues_IsInvalid()
    {
        // An AD-RC policy reference on a signature that only has AD-RV properties.
        var adRc = IcpBrasilSignaturePolicies.Current(IcpBrasilPolicy.AdRc, IcpBrasilPolicyFormat.Xades);
        byte[] signed = await XadesSigner.Document(_xml).WithCertificate(_pki.Leaf, _pki.IntermediatesAndRoot())
            .WithHttpClientProvider(new SingleClientProvider(_http))
            .WithIcpBrasilPolicy(IcpBrasilPolicy.AdRv, _tsa)
            .WithSignaturePolicy(new Core.Crypto.SignaturePolicyReference(adRc.Oid, adRc.HashAlgorithmOid, adRc.PolicyHash, adRc.Uri))
            .SignAsync();

        var check = IcpBrasilXadesPolicyValidator.Validate(signed, Validate(signed));

        check.Status.ShouldBe(IcpBrasilPolicyStatus.Invalid);
        check.Errors.ShouldContain(e => e.Contains("CertificateValues", StringComparison.Ordinal));
    }

    [Fact]
    public void AboveAdRbWithoutTsa_Throws() =>
        Should.Throw<ArgumentException>(() => XadesSigner.Document(_xml).WithCertificate(_pki.Leaf).WithIcpBrasilPolicy(IcpBrasilPolicy.AdRt));

    private Task<byte[]> Sign(IcpBrasilPolicy policy) =>
        XadesSigner.Document(_xml).WithCertificate(_pki.Leaf, _pki.IntermediatesAndRoot())
            .WithHttpClientProvider(new SingleClientProvider(_http))
            .WithIcpBrasilPolicy(policy, policy == IcpBrasilPolicy.AdRb ? null : _tsa)
            .SignAsync();

    private static XadesValidationResult Validate(byte[] signed) =>
        new XadesSignatureValidator(new ValidationOptions { CheckRevocation = false }).Validate(signed);
}
