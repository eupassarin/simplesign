using System.Net;
using System.Net.Http.Headers;
using Shouldly;
using SimpleSign.Core.Http;
using SimpleSign.Core.Signing;
using SimpleSign.Core.Validation;
using SimpleSign.TestHelpers;
using Xunit;

namespace SimpleSign.CAdES.Tests;

/// <summary>RFC 5126 extended forms (CAdES-X, X Long, A) on every timestamped baseline level.</summary>
public sealed class CadesExtendedFormTests : IDisposable
{
    private const string LeafCrlUrl = "http://198.51.100.1/leaf.crl";
    private const string IntermediateCrlUrl = "http://198.51.100.1/intermediate.crl";
    private readonly byte[] _data = "Contrato CAdES"u8.ToArray();
    private readonly SyntheticPki _pki = new(crlDistributionPoint: LeafCrlUrl, intermediateCrlDistributionPoint: IntermediateCrlUrl);
    private readonly HttpClient _http;

    public CadesExtendedFormTests()
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
    }

    public void Dispose()
    {
        _http.Dispose();
        _pki.Dispose();
    }

    [Theory]
    [InlineData(AdesBaselineLevel.Timestamped, CadesExtendedForm.CompleteReferences)]
    [InlineData(AdesBaselineLevel.Timestamped, CadesExtendedForm.ExtendedLong)]
    [InlineData(AdesBaselineLevel.Timestamped, CadesExtendedForm.Archive)]
    [InlineData(AdesBaselineLevel.LongTerm, CadesExtendedForm.CompleteReferences)]
    [InlineData(AdesBaselineLevel.LongTerm, CadesExtendedForm.ExtendedLong)]
    [InlineData(AdesBaselineLevel.LongTerm, CadesExtendedForm.Archive)]
    [InlineData(AdesBaselineLevel.Archive, CadesExtendedForm.CompleteReferences)]
    [InlineData(AdesBaselineLevel.Archive, CadesExtendedForm.ExtendedLong)]
    [InlineData(AdesBaselineLevel.Archive, CadesExtendedForm.Archive)]
    public async Task SignWithDetailsAsync_ExtendedFormOnLevel_ValidatesAndKeepsTheLevel(AdesBaselineLevel level, CadesExtendedForm form)
    {
        var result = await CadesSigner.Document(_data)
            .WithCertificate(_pki.Leaf, _pki.IntermediatesAndRoot())
            .WithHttpClientProvider(new SingleClientProvider(_http))
            .WithLevel(Profile(level))
            .WithExtendedValidationData(form)
            .SignWithDetailsAsync();

        result.AchievedLevel.ShouldBe(level);
        var validation = new CadesSignatureValidator(new ValidationOptions { CheckRevocation = false, TrustSystemRoots = false })
            .Validate(result.SignedArtifact, _data, [_pki.IntermediateCa, _pki.RootCa]);
        validation.Errors.ShouldBeEmpty();
        validation.IsValid.ShouldBeTrue();
        if (form == CadesExtendedForm.Archive)
        {
            validation.HasValidArchiveTimestamp.ShouldBe(true);
        }
    }

    private AdesBaselineProfile Profile(AdesBaselineLevel level)
    {
        var tsa = new TimestampOptions(new Uri("http://mock-tsa.example.com"), new SingleClientProvider(_http));
        var ltv = new LongTermValidationOptions(new SingleClientProvider(_http));
        return level switch
        {
            AdesBaselineLevel.Timestamped => AdesBaselineProfile.Timestamped(tsa),
            AdesBaselineLevel.LongTerm => AdesBaselineProfile.LongTerm(tsa, ltv),
            _ => AdesBaselineProfile.Archive(tsa, ltv),
        };
    }
}
