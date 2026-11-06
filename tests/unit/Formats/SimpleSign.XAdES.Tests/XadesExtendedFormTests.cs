using System.Net;
using System.Net.Http.Headers;
using System.Xml;
using Shouldly;
using SimpleSign.Core.Constants;
using SimpleSign.Core.Http;
using SimpleSign.Core.Signing;
using SimpleSign.Core.Validation;
using SimpleSign.TestHelpers;
using SimpleSign.XAdES.Constants;
using Xunit;

namespace SimpleSign.XAdES.Tests;

/// <summary>XAdES-C, XAdES-X, XAdES-X-L and XAdES-A (ETSI TS 101 903 v1.3.2), as ICP-Brasil's AD-RV, AD-RC and AD-RA need.</summary>
[Trait("Category", "Unit")]
public sealed class XadesExtendedFormTests : IDisposable
{
    private const string LeafCrlUrl = "http://198.51.100.1/leaf.crl";
    private const string IntermediateCrlUrl = "http://198.51.100.1/intermediate.crl";
    private readonly byte[] _xml = "<?xml version=\"1.0\"?><contrato><id>1</id></contrato>"u8.ToArray();
    private readonly SyntheticPki _pki = new(crlDistributionPoint: LeafCrlUrl, intermediateCrlDistributionPoint: IntermediateCrlUrl);
    private readonly HttpClient _http;

    public XadesExtendedFormTests()
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

    [Fact]
    public async Task CompleteReferences_WritesRefsAndValidSigAndRefsTimeStamp()
    {
        byte[] signed = await Sign(XadesExtendedForm.CompleteReferences);

        var names = UnsignedPropertyNames(signed);
        names.ShouldBe(["SignatureTimeStamp", "CompleteCertificateRefs", "CompleteRevocationRefs", "SigAndRefsTimeStamp"]);
        var result = Validate(signed);
        result.IsSignatureValid.ShouldBeTrue(string.Join("; ", result.Errors));
        result.HasValidSigAndRefsTimeStamp.ShouldBe(true, string.Join("; ", result.Warnings));
        result.HasValidCompleteReferences.ShouldBe(true, string.Join("; ", result.Warnings));
    }

    [Fact]
    public async Task CompleteReferences_ReferencesTheCaCertificatesAndTheirCrls()
    {
        byte[] signed = await Sign(XadesExtendedForm.CompleteReferences);

        var (doc, ns) = Load(signed);
        doc.SelectNodes("//xades:CompleteCertificateRefs/xades:CertRefs/xades:Cert", ns)!.Count.ShouldBe(2);
        doc.SelectNodes("//xades:CompleteRevocationRefs/xades:CRLRefs/xades:CRLRef", ns)!.Count.ShouldBe(2);
        doc.SelectSingleNode("//xades:CRLRef/xades:CRLIdentifier/xades:IssueTime", ns).ShouldNotBeNull();
    }

    [Fact]
    public async Task ExtendedLong_AddsValuesAfterTheTimeStamp()
    {
        byte[] signed = await Sign(XadesExtendedForm.ExtendedLong);

        UnsignedPropertyNames(signed).ShouldBe(
            ["SignatureTimeStamp", "CompleteCertificateRefs", "CompleteRevocationRefs", "SigAndRefsTimeStamp", "CertificateValues", "RevocationValues"]);
        var result = Validate(signed);
        result.HasValidCompleteReferences.ShouldBe(true, string.Join("; ", result.Warnings));
        result.HasValidSigAndRefsTimeStamp.ShouldBe(true);
    }

    [Fact]
    public async Task Archive_AddsRefsValuesAndArchiveTimeStamp()
    {
        byte[] signed = await Sign(XadesExtendedForm.Archive);

        var names = UnsignedPropertyNames(signed);
        names.ShouldContain("CompleteCertificateRefs");
        names.ShouldContain("CertificateValues");
        names.ShouldNotContain("SigAndRefsTimeStamp");
        names[^1].ShouldBe("ArchiveTimeStamp");
        Validate(signed).HasValidArchiveTimeStamp.ShouldBe(true);
    }

    [Fact]
    public async Task TamperedReference_SigAndRefsTimeStampInvalid()
    {
        byte[] signed = await Sign(XadesExtendedForm.CompleteReferences);
        var (doc, ns) = Load(signed);
        var serial = (XmlElement)doc.SelectSingleNode("//xades:CompleteCertificateRefs//ds:X509SerialNumber", ns)!;
        serial.InnerText = "1";
        using var ms = new MemoryStream();
        doc.Save(ms);

        var result = Validate(ms.ToArray());

        result.HasValidSigAndRefsTimeStamp.ShouldBe(false);
    }

    [Fact]
    public async Task ExtendedLong_TamperedCrlValue_ReferencesInvalid()
    {
        byte[] signed = await Sign(XadesExtendedForm.ExtendedLong);
        var (doc, ns) = Load(signed);
        var crl = (XmlElement)doc.SelectSingleNode("//xades:RevocationValues/xades:CRLValues/xades:EncapsulatedCRLValue", ns)!;
        crl.InnerText = Convert.ToBase64String("not a crl"u8);
        using var ms = new MemoryStream();
        doc.Save(ms);

        Validate(ms.ToArray()).HasValidCompleteReferences.ShouldBe(false);
    }

    [Fact]
    public async Task WithoutTimestampedProfile_Throws()
    {
        var builder = XadesSigner.Document(_xml).WithCertificate(_pki.Leaf, _pki.IntermediatesAndRoot())
            .WithExtendedValidationData(XadesExtendedForm.CompleteReferences);

        var ex = await Should.ThrowAsync<SigningException>(() => builder.SignAsync());
        ex.Reason.ShouldBe(SigningErrorReason.LevelNotAchievable);
    }

    [Fact]
    public async Task NoForm_NoReferences()
    {
        byte[] signed = await XadesSigner.Document(_xml).WithCertificate(_pki.Leaf, _pki.IntermediatesAndRoot())
            .WithHttpClientProvider(new SingleClientProvider(_http))
            .WithLevel(AdesBaselineProfile.Timestamped(Tsa()))
            .SignAsync();

        var result = Validate(signed);
        result.HasValidCompleteReferences.ShouldBeNull();
        result.HasValidSigAndRefsTimeStamp.ShouldBeNull();
    }

    private Task<byte[]> Sign(XadesExtendedForm form) =>
        XadesSigner.Document(_xml).WithCertificate(_pki.Leaf, _pki.IntermediatesAndRoot())
            .WithHttpClientProvider(new SingleClientProvider(_http))
            .WithLevel(AdesBaselineProfile.Timestamped(Tsa()))
            .WithExtendedValidationData(form)
            .SignAsync();

    private TimestampOptions Tsa() => new(new Uri("http://mock-tsa.example.com"), new SingleClientProvider(_http));

    private static XadesValidationResult Validate(byte[] signed) =>
        new XadesSignatureValidator(new ValidationOptions { CheckRevocation = false }).Validate(signed);

    private static List<string> UnsignedPropertyNames(byte[] signed)
    {
        var (doc, ns) = Load(signed);
        return [.. doc.SelectNodes("//xades:UnsignedSignatureProperties/*", ns)!.OfType<XmlElement>().Select(e => e.LocalName)];
    }

    private static (XmlDocument Doc, XmlNamespaceManager Ns) Load(byte[] xml)
    {
        var doc = new XmlDocument { PreserveWhitespace = true, XmlResolver = null };
        using var stream = new MemoryStream(xml);
        using var reader = XmlReader.Create(stream, new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit });
        doc.Load(reader);
        var ns = new XmlNamespaceManager(doc.NameTable);
        ns.AddNamespace("ds", XmlDSigUrls.DsNamespace);
        ns.AddNamespace("xades", XadesUris.XadesNamespace);
        ns.AddNamespace("xades141", XadesUris.Xades141Namespace);
        return (doc, ns);
    }
}
