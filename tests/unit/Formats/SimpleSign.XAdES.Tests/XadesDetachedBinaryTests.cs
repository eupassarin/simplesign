using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Xml;
using Shouldly;
using SimpleSign.Core.Constants;
using SimpleSign.Core.Http;
using SimpleSign.Core.Signing;
using SimpleSign.TestHelpers;
using SimpleSign.XAdES.Constants;
using Xunit;

namespace SimpleSign.XAdES.Tests;

/// <summary>
/// A detached XAdES signature over a file that is not XML (<see cref="XadesSignerBuilder.WithDetachedBinary"/>): the
/// reference has no transforms and digests the octets, at every level and through every way of signing.
/// </summary>
[Trait("Category", "Unit")]
public sealed class XadesDetachedBinaryTests : IDisposable
{
    private const string TsaUrl = "http://198.51.100.7/tsa";
    private const string LeafCrlUrl = "http://198.51.100.7/leaf.crl";
    private const string IntermediateCrlUrl = "http://198.51.100.7/intermediate.crl";
    private const string DataUri = "contrato.pdf";
    private static readonly byte[] s_key = RandomNumberGenerator.GetBytes(32);

    // Not XML: a PDF header followed by binary bytes, which XmlDocument.Load refuses.
    private static readonly byte[] s_pdf = [.. "%PDF-1.7\n%âã\n"u8.ToArray(), 0x00, 0xFF, 0x10, 0x80, .. "1 0 obj\n<<>>\nendobj\n%%EOF\n"u8.ToArray()];

    private readonly SyntheticPki _pki = new(crlDistributionPoint: LeafCrlUrl, intermediateCrlDistributionPoint: IntermediateCrlUrl);
    private readonly HttpClient _http;

    public XadesDetachedBinaryTests()
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

    private SingleClientProvider Http => new(_http);

    private static AdesBaselineProfile Profile(AdesBaselineLevel level)
    {
        var tsa = new TimestampOptions(new Uri(TsaUrl));
        var ltv = new LongTermValidationOptions { RevocationPreference = RevocationPreference.CrlFirst };
        return level switch
        {
            AdesBaselineLevel.Basic => AdesBaselineProfile.Basic(),
            AdesBaselineLevel.Timestamped => AdesBaselineProfile.Timestamped(tsa),
            AdesBaselineLevel.LongTerm => AdesBaselineProfile.LongTerm(tsa, ltv),
            _ => AdesBaselineProfile.Archive(tsa, ltv),
        };
    }

    private XadesValidationResult Validate(byte[] signed, byte[] data) =>
        new XadesSignatureValidator().Validate(signed, [_pki.IntermediateCa, _pki.RootCa], data);

    [Theory]
    [InlineData(AdesBaselineLevel.Basic)]
    [InlineData(AdesBaselineLevel.Timestamped)]
    [InlineData(AdesBaselineLevel.LongTerm)]
    [InlineData(AdesBaselineLevel.Archive)]
    public async Task SignWithDetailsAsync_BinaryFile_ReachesTheLevelAndValidates(AdesBaselineLevel level)
    {
        XadesSigningResult result = await XadesSigner.Document(s_pdf)
            .WithCertificate(_pki.Leaf, _pki.IntermediatesAndRoot())
            .WithDetachedBinary("application/pdf")
            .WithDataUri(DataUri)
            .WithHttpClientProvider(Http)
            .WithLevel(Profile(level))
            .SignWithDetailsAsync();

        result.AchievedLevel.ShouldBe(level);
        XadesValidationResult validated = Validate(result.SignedArtifact, s_pdf);
        validated.IsSignatureValid.ShouldBeTrue(string.Join("; ", validated.Errors));
        validated.IsIntegrityValid.ShouldBeTrue();
        if (level == AdesBaselineLevel.Archive)
        {
            validated.HasValidArchiveTimeStamp.ShouldBe(true);
        }
    }

    [Fact]
    public async Task SignAsync_BinaryFile_ReferenceHasNoTransformsAndDigestsTheOctets()
    {
        byte[] signed = await XadesSigner.Document(s_pdf)
            .WithCertificate(_pki.Leaf)
            .WithDetachedBinary("application/pdf")
            .WithDataUri(DataUri)
            .SignAsync();

        var document = new XmlDocument { PreserveWhitespace = true };
        document.Load(new MemoryStream(signed));
        var ns = new XmlNamespaceManager(document.NameTable);
        ns.AddNamespace("ds", XmlDSigUrls.DsNamespace);
        ns.AddNamespace("xades", XadesUris.XadesNamespace);
        var reference = (XmlElement)document.SelectSingleNode($"//ds:SignedInfo/ds:Reference[@URI='{DataUri}']", ns).ShouldNotBeNull();
        reference.SelectSingleNode("ds:Transforms", ns).ShouldBeNull();
        reference.SelectSingleNode("ds:DigestValue", ns)!.InnerText.ShouldBe(Convert.ToBase64String(SHA256.HashData(s_pdf)));
        document.SelectSingleNode("//xades:DataObjectFormat/xades:MimeType", ns)!.InnerText.ShouldBe("application/pdf");
    }

    [Fact]
    public async Task Validate_FileChangedAfterSigning_IsInvalid()
    {
        byte[] signed = await XadesSigner.Document(s_pdf).WithCertificate(_pki.Leaf).WithDetachedBinary().WithDataUri(DataUri).SignAsync();
        byte[] changed = (byte[])s_pdf.Clone();
        changed[12] ^= 0x01;

        Validate(signed, changed).IsValid.ShouldBeFalse();
    }

    [Fact]
    public async Task SignAsync_BinaryFileWithAnExternalKey_Validates()
    {
        byte[] signed = await XadesSigner.Document(s_pdf)
            .WithExternalSigner(_pki.Leaf, new DelegatingExternalSigner(data =>
            {
                using RSA rsa = _pki.Leaf.GetRSAPrivateKey()!;
                return Task.FromResult(rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
            }), _pki.IntermediatesAndRoot())
            .WithSignatureAlgorithm("1.2.840.113549.1.1.11")
            .WithDetachedBinary()
            .WithDataUri(DataUri)
            .SignAsync();

        XadesValidationResult validated = Validate(signed, s_pdf);
        validated.IsSignatureValid.ShouldBeTrue(string.Join("; ", validated.Errors));
    }

    [Fact]
    public async Task SignAsync_BinaryFileWithADataObjectsTimeStamp_TimestampsTheOctets()
    {
        byte[] signed = await XadesSigner.Document(s_pdf)
            .WithCertificate(_pki.Leaf, _pki.IntermediatesAndRoot())
            .WithDetachedBinary()
            .WithDataUri(DataUri)
            .WithHttpClientProvider(Http)
            .WithDataObjectsTimestamp(new TimestampOptions(new Uri(TsaUrl)))
            .SignAsync();

        XadesValidationResult validated = Validate(signed, s_pdf);
        validated.IsSignatureValid.ShouldBeTrue(string.Join("; ", validated.Errors));
        Encoding.UTF8.GetString(signed).ShouldContain("AllDataObjectsTimeStamp");
    }

    [Fact]
    public async Task CompleteAsync_DeferredBinaryFile_Validates()
    {
        using X509Certificate2 publicCertificate = RemoteKey.PublicOnly(_pki.Leaf);
        XadesDeferredPrepareResult prepared = await XadesDeferredSigner.Document(s_pdf)
            .WithCertificate(publicCertificate, _pki.IntermediatesAndRoot())
            .WithSessionIntegrityKey(s_key)
            .WithDetachedBinary("application/pdf")
            .WithDataUri(DataUri)
            .WithLevel(Profile(AdesBaselineLevel.Archive))
            .PrepareAsync();

        XadesSigningResult result = await XadesDeferredSigner.Resume(prepared.SessionData, s_key)
            .WithHttpClientProvider(Http)
            .CompleteWithDetailsAsync(RemoteKey.Sign(_pki.Leaf, prepared.ToSigningRequest()));

        result.AchievedLevel.ShouldBe(AdesBaselineLevel.Archive);
        XadesValidationResult validated = Validate(result.SignedArtifact, s_pdf);
        validated.IsSignatureValid.ShouldBeTrue(string.Join("; ", validated.Errors));
        validated.HasValidArchiveTimeStamp.ShouldBe(true);
    }

    [Fact]
    public async Task AugmentAsync_BinaryFileSignature_ReachesArchiveAndValidates()
    {
        byte[] signed = await XadesSigner.Document(s_pdf)
            .WithCertificate(_pki.Leaf, _pki.IntermediatesAndRoot())
            .WithDetachedBinary()
            .WithDataUri(DataUri)
            .SignAsync();

        var result = await XadesAugmenter.Document(signed, s_pdf)
            .WithTimestamp(new TimestampOptions(new Uri(TsaUrl)))
            .WithHttpClientProvider(Http)
            .ToLevel(AdesBaselineLevel.Archive)
            .AugmentAsync();

        result.Level.ShouldBe(AdesBaselineLevel.Archive);
        XadesValidationResult validated = Validate(result.Document, s_pdf);
        validated.IsSignatureValid.ShouldBeTrue(string.Join("; ", validated.Errors));
        validated.HasValidArchiveTimeStamp.ShouldBe(true);
    }

    [Fact]
    public async Task SignAsync_DetachedBinaryThenAnotherForm_IsRefused()
    {
        var builder = XadesSigner.Document(s_pdf).WithCertificate(_pki.Leaf).WithDetachedBinary().WithForm(XadesForm.Enveloped);

        await Should.ThrowAsync<SigningException>(() => builder.SignAsync());
    }

    [Fact]
    public async Task SignAsync_BinaryFileWithoutTheOption_IsRefusedAsNotXml()
    {
        var builder = XadesSigner.Document(s_pdf).WithCertificate(_pki.Leaf).WithForm(XadesForm.Detached).WithDataUri(DataUri);

        await Should.ThrowAsync<ArgumentException>(() => builder.SignAsync());
    }
}
