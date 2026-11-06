using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Shouldly;
using SimpleSign.Core.Http;
using SimpleSign.Core.Signing;
using SimpleSign.Core.Validation;
using SimpleSign.PAdES.Signing;
using SimpleSign.PAdES.Validation;
using SimpleSign.PAdES.Pdf;
using SimpleSign.TestHelpers;
using Xunit;

namespace SimpleSign.PAdES.Tests.Signing;

/// <summary>
/// Options that used to be ignored or wrongly refused: DocMDP P=2/P=3 documents taking more
/// signatures, the appearance of an existing field, archive TSA credentials, DSS artifacts and the
/// TSA credentials of a resumed deferred session.
/// </summary>
[Trait("Category", "Unit")]
public sealed class PadesOptionFixesTests : IDisposable
{
    private const string LeafCrlUrl = "http://198.51.100.1/leaf.crl";
    private const string IntermediateCrlUrl = "http://198.51.100.1/intermediate.crl";
    private static readonly Uri TsaUri = new("http://tsa.example.test/");
    private static readonly Uri ArchiveTsaUri = new("http://archive-tsa.example.test/");
    private static readonly byte[] SessionIntegrityKey = [.. Enumerable.Repeat((byte)0x5A, 32)];

    private readonly SyntheticPki _pki = new(crlDistributionPoint: LeafCrlUrl, intermediateCrlDistributionPoint: IntermediateCrlUrl);
    private readonly ConcurrentQueue<(Uri Uri, string? Authorization)> _tsaRequests = new();
    private readonly HttpClient _http;

    public PadesOptionFixesTests()
    {
        byte[] leafCrl = _pki.BuildLeafCrl();
        byte[] intermediateCrl = _pki.BuildIntermediateCrl();
        _http = new HttpClient(new MockHttpHandler(async request =>
        {
            if (request.Method == HttpMethod.Post)
            {
                _tsaRequests.Enqueue((request.RequestUri!, request.Headers.Authorization?.ToString()));
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

    private LongTermValidationOptions Ltv() => new(new SingleClientProvider(_http));

    private PadesSignerBuilder Signer(byte[] pdf) =>
        PadesSigner.Document(pdf).WithCertificate(_pki.Leaf, _pki.IntermediatesAndRoot());

    // ── DocMDP ───────────────────────────────────────────────────────────

    [Theory(DisplayName = "§12.8.2.2.2: a P=2 or P=3 certified document takes another signature")]
    [InlineData(CertificationLevel.FormFilling)]
    [InlineData(CertificationLevel.FormFillingAndAnnotations)]
    public async Task SignAsync_CertifiedP2OrP3_AllowsSecondSignature(CertificationLevel level)
    {
        byte[] certified = await Signer(TestPdfFactory.CreateMinimalPdfWithPage()).AsCertification(level).SignAsync();

        byte[] twice = await Signer(certified).WithFieldName("Approval").SignAsync();

        await using var stream = new MemoryStream(twice, writable: false);
        var fields = await PdfStructureReader.ReadSignatureFieldsAsync(stream);
        fields.Count(f => f.IsSigned).ShouldBe(2);
    }

    [Fact(DisplayName = "§12.8.2.2.2: a P=1 certified document refuses another signature")]
    public async Task SignAsync_CertifiedP1_Refuses()
    {
        byte[] certified = await Signer(TestPdfFactory.CreateMinimalPdfWithPage()).AsCertification(CertificationLevel.NoChanges).SignAsync();

        var ex = await Should.ThrowAsync<SigningException>(() => Signer(certified).WithFieldName("Approval").SignAsync());
        ex.Reason.ShouldBe(SigningErrorReason.DocumentNotSignable);
    }

    [Fact(DisplayName = "Certifying a document that is already signed is refused")]
    public async Task AsCertification_AlreadySigned_Throws()
    {
        byte[] signed = await Signer(TestPdfFactory.CreateMinimalPdfWithPage()).SignAsync();

        var ex = await Should.ThrowAsync<SigningException>(() =>
            Signer(signed).WithFieldName("Second").AsCertification().SignAsync());
        ex.Reason.ShouldBe(SigningErrorReason.DocumentNotSignable);
        ex.Message.ShouldContain("Only the first signature");
    }

    // ── Existing field appearance ────────────────────────────────────────

    [Fact(DisplayName = "Signing an existing field draws the appearance in its rectangle")]
    public async Task WithExistingField_WithAppearance_DrawsAppearanceInFieldRect()
    {
        byte[] pdf = PdfWithEmptyField("[100 100 300 160]");

        byte[] signed = await Signer(pdf)
            .WithExistingField("Existing")
            .WithAppearance(new SignatureAppearance { ShowDate = true })
            .SignAsync();

        string update = Encoding.Latin1.GetString(signed, pdf.Length, signed.Length - pdf.Length);
        update.ShouldContain("/AP << /N ");
        update.ShouldContain("/Subtype /Form");
        update.ShouldContain("/BBox [0 0 200.00 60.00]");

        var validator = new PdfSignatureValidator(new ValidationOptions { CheckRevocation = false, TrustedRoots = [_pki.RootCa] });
        await using var stream = new MemoryStream(signed, writable: false);
        var result = (await validator.ValidateAsync(stream)).ShouldHaveSingleItem();
        result.IsIntegrityValid.ShouldBeTrue(string.Join("; ", result.Errors));
    }

    [Fact(DisplayName = "An appearance on an existing invisible field is refused")]
    public async Task WithExistingField_ZeroRectWithAppearance_Throws()
    {
        byte[] pdf = PdfWithEmptyField("[0 0 0 0]");

        var ex = await Should.ThrowAsync<ArgumentException>(() => Signer(pdf)
            .WithExistingField("Existing")
            .WithAppearance(new SignatureAppearance())
            .SignAsync());
        ex.Message.ShouldContain("no visible rectangle");
    }

    [Theory(DisplayName = "ReadRectSize reads a widget's width and height")]
    [InlineData("<< /Rect [100 100 300 160] >>", 200f, 60f)]
    [InlineData("<< /Rect [300.5 160 100.5 100] >>", 200f, 60f)]
    public void ReadRectSize_ReadsSize(string dict, float width, float height)
    {
        var size = PdfSignatureWriter.ReadRectSize(dict);

        size.ShouldNotBeNull();
        size.Value.Width.ShouldBe(width, 0.01f);
        size.Value.Height.ShouldBe(height, 0.01f);
    }

    // ── Archive TSA credentials ──────────────────────────────────────────

    [Fact(DisplayName = "B-LTA without an archive endpoint sends the signature TSA's credentials twice")]
    public async Task Archive_WithoutArchiveEndpoint_InheritsSignatureTsaAuthorization()
    {
        var tsa = new TimestampOptions(TsaUri, new SingleClientProvider(_http))
        {
            Authorization = new AuthenticationHeaderValue("Bearer", "signature-tsa"),
        };

        var result = await Signer(TestPdfFactory.CreateMinimalPdfWithPage())
            .WithHttpClientProvider(new SingleClientProvider(_http))
            .WithLevel(AdesBaselineProfile.Archive(tsa, Ltv()))
            .SignWithDetailsAsync();

        result.HasArchiveTimestamp.ShouldBeTrue();
        _tsaRequests.Count.ShouldBe(2);
        _tsaRequests.ShouldAllBe(r => r.Uri == TsaUri && r.Authorization == "Bearer signature-tsa");
    }

    [Fact(DisplayName = "B-LTA with its own archive endpoint sends the archive credentials there")]
    public async Task Archive_WithArchiveEndpoint_UsesArchiveAuthorization()
    {
        var tsa = new TimestampOptions(TsaUri, new SingleClientProvider(_http))
        {
            Authorization = new AuthenticationHeaderValue("Bearer", "signature-tsa"),
        };
        var archive = new ArchiveTimestampOptions(ArchiveTsaUri, new SingleClientProvider(_http))
        {
            Authorization = new AuthenticationHeaderValue("Basic", "YXJjaGl2ZTpzZWNyZXQ="),
        };

        var result = await Signer(TestPdfFactory.CreateMinimalPdfWithPage())
            .WithHttpClientProvider(new SingleClientProvider(_http))
            .WithLevel(AdesBaselineProfile.Archive(tsa, Ltv(), archive))
            .SignWithDetailsAsync();

        result.HasArchiveTimestamp.ShouldBeTrue();
        _tsaRequests.ShouldContain((TsaUri, "Bearer signature-tsa"));
        _tsaRequests.ShouldContain((ArchiveTsaUri, "Basic YXJjaGl2ZTpzZWNyZXQ="));
    }

    [Fact(DisplayName = "ArchiveTimestampOptions.Resolve without endpoint returns the signature TSA")]
    public void Resolve_NoEndpoint_ReturnsSignatureTimestamp()
    {
        var tsa = new TimestampOptions(TsaUri) { Authorization = new AuthenticationHeaderValue("Bearer", "x") };

        new ArchiveTimestampOptions().Resolve(tsa).ShouldBeSameAs(tsa);
    }

    [Fact(DisplayName = "ArchiveTimestampOptions.Resolve with endpoint does not leak the signature TSA's credentials")]
    public void Resolve_WithEndpoint_DoesNotInheritCredentials()
    {
        var tsa = new TimestampOptions(TsaUri) { Authorization = new AuthenticationHeaderValue("Bearer", "x") };

        var resolved = new ArchiveTimestampOptions(ArchiveTsaUri).Resolve(tsa);

        resolved.Endpoint.ShouldBe(ArchiveTsaUri);
        resolved.Authorization.ShouldBeNull();
    }

    // ── DSS artifacts ────────────────────────────────────────────────────

    [Fact(DisplayName = "DSS artifacts below B-LT are refused")]
    public async Task WithDssArtifacts_BelowLongTerm_Throws()
    {
        var ex = await Should.ThrowAsync<SigningException>(() => Signer(TestPdfFactory.CreateMinimalPdfWithPage())
            .WithDssArtifacts([new PdfDssArtifact("X_Artifacts", "X_Artifact", "data"u8.ToArray())])
            .SignAsync());
        ex.Reason.ShouldBe(SigningErrorReason.LevelNotAchievable);
    }

    [Theory(DisplayName = "DSS artifacts with reserved or malformed keys are refused")]
    [InlineData("Certs", "X_Artifact")]
    [InlineData("X_Artifacts", "OCSP")]
    [InlineData("X Artifacts", "X_Artifact")]
    [InlineData("", "X_Artifact")]
    public void WithDssArtifacts_BadKey_Throws(string dssKey, string vriKey) =>
        Should.Throw<ArgumentException>(() => Signer(TestPdfFactory.CreateMinimalPdfWithPage())
            .WithDssArtifacts([new PdfDssArtifact(dssKey, vriKey, "data"u8.ToArray())]));

    [Fact(DisplayName = "DSS artifacts are written to the DSS array and the signature's VRI entry")]
    public async Task WithDssArtifacts_LongTerm_WritesDssAndVriEntries()
    {
        var tsa = new TimestampOptions(TsaUri, new SingleClientProvider(_http));

        byte[] signed = await Signer(TestPdfFactory.CreateMinimalPdfWithPage())
            .WithHttpClientProvider(new SingleClientProvider(_http))
            .WithLevel(AdesBaselineProfile.LongTerm(tsa, Ltv()))
            .WithDssArtifacts([new PdfDssArtifact("X_Artifacts", "X_Artifact", "artifact"u8.ToArray())])
            .SignAsync();

        var dss = DssExtractor.ParseExistingDss(signed);
        dss.ExtraArrays.Keys.ShouldContain("X_Artifacts");
        var data = await DssExtractor.TryReadFullDssDataAsync(new MemoryStream(signed), CancellationToken.None);
        data.Keys.ShouldContain("X_Artifacts");
        data.VriEntries.Values.ShouldContain(v => v.Keys.Contains("X_Artifact"));
    }

    [Fact(DisplayName = "Custom DSS arrays survive a later signature that rewrites the DSS")]
    public async Task WithDssArtifacts_SecondLtvSignature_PreservesArray()
    {
        var tsa = new TimestampOptions(TsaUri, new SingleClientProvider(_http));
        byte[] first = await Signer(TestPdfFactory.CreateMinimalPdfWithPage())
            .WithHttpClientProvider(new SingleClientProvider(_http))
            .WithLevel(AdesBaselineProfile.LongTerm(tsa, Ltv()))
            .WithDssArtifacts([new PdfDssArtifact("X_Artifacts", "X_Artifact", "artifact"u8.ToArray())])
            .SignAsync();

        byte[] second = await Signer(first)
            .WithFieldName("Second")
            .WithHttpClientProvider(new SingleClientProvider(_http))
            .WithLevel(AdesBaselineProfile.LongTerm(tsa, Ltv()))
            .SignAsync();

        var data = await DssExtractor.TryReadFullDssDataAsync(new MemoryStream(second), CancellationToken.None);
        data.Keys.ShouldContain("X_Artifacts");
    }

    // ── DSS key parsing ──────────────────────────────────────────────────

    [Fact(DisplayName = "TopLevelKeys skips nested dictionaries, arrays, strings and references")]
    public void TopLevelKeys_ReadsOnlyTopLevelKeys()
    {
        byte[] dict = "<< /Type /DSS /VRI << /ABC 5 0 R >> /Certs [1 0 R 2 0 R] /Note (a /Fake (nested) key) /Ref 7 0 R /Hex <2F41> /PBAD_LpaArtifacts [9 0 R] >>"u8.ToArray();

        DssExtractor.TopLevelKeys(dict).ShouldBe(["Type", "VRI", "Certs", "Note", "Ref", "Hex", "PBAD_LpaArtifacts"]);
    }

    // ── Deferred resume ──────────────────────────────────────────────────

    [Fact(DisplayName = "WithTimestampOptions supplies the TSA credentials a resumed session cannot store")]
    public async Task Resume_WithTimestampOptions_SendsAuthorization()
    {
        using var certificate = TestCertificateFactory.CreateSelfSignedCert();
        var prepared = await DeferredSigner.Document(TestPdfFactory.CreateMinimalPdfWithPage())
            .WithCertificate(certificate)
            .WithSessionIntegrityKey(SessionIntegrityKey)
            .WithLevel(AdesBaselineProfile.Timestamped(new TimestampOptions(TsaUri)))
            .PrepareAsync();
        using RSA key = certificate.GetRSAPrivateKey()!;
        byte[] signature = key.SignData(prepared.HashToSign, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        byte[] signed = await DeferredSigner.Resume(prepared.SessionData, SessionIntegrityKey)
            .WithTimestampOptions(new TimestampOptions(TsaUri, new SingleClientProvider(_http))
            {
                Authorization = new AuthenticationHeaderValue("Bearer", "resumed"),
            })
            .CompleteAsync(signature);

        signed.ShouldNotBeEmpty();
        _tsaRequests.ShouldContain((TsaUri, "Bearer resumed"));
    }

    [Fact(DisplayName = "WithTimestampOptions refuses a TSA other than the session's")]
    public async Task Resume_WithTimestampOptions_OtherEndpoint_Throws()
    {
        using var certificate = TestCertificateFactory.CreateSelfSignedCert();
        var prepared = await DeferredSigner.Document(TestPdfFactory.CreateMinimalPdfWithPage())
            .WithCertificate(certificate)
            .WithSessionIntegrityKey(SessionIntegrityKey)
            .WithLevel(AdesBaselineProfile.Timestamped(new TimestampOptions(TsaUri)))
            .PrepareAsync();

        Should.Throw<ArgumentException>(() => DeferredSigner.Resume(prepared.SessionData, SessionIntegrityKey)
            .WithTimestampOptions(new TimestampOptions(ArchiveTsaUri)));
    }

    [Fact(DisplayName = "WithTimestampOptions is only for resumed sessions")]
    public void WithTimestampOptions_NotResumed_Throws() =>
        Should.Throw<InvalidOperationException>(() => DeferredSigner.Document(TestPdfFactory.CreateMinimalPdfWithPage())
            .WithTimestampOptions(new TimestampOptions(TsaUri)));

    [Fact(DisplayName = "WithTimestampOptions on a B-B session is refused")]
    public async Task Resume_BasicSession_WithTimestampOptions_Throws()
    {
        using var certificate = TestCertificateFactory.CreateSelfSignedCert();
        var prepared = await DeferredSigner.Document(TestPdfFactory.CreateMinimalPdfWithPage())
            .WithCertificate(certificate)
            .WithSessionIntegrityKey(SessionIntegrityKey)
            .WithLevel(AdesBaselineProfile.Basic())
            .PrepareAsync();

        Should.Throw<InvalidOperationException>(() => DeferredSigner.Resume(prepared.SessionData, SessionIntegrityKey)
            .WithTimestampOptions(new TimestampOptions(TsaUri)));
    }

    private static byte[] PdfWithEmptyField(string rect)
    {
        var sb = new StringBuilder("%PDF-1.7\n");
        var offsets = new List<int>();
        void Obj(string body)
        {
            offsets.Add(sb.Length);
            sb.Append($"{offsets.Count} 0 obj\n{body}\nendobj\n");
        }

        Obj("<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [4 0 R] /SigFlags 3 >> >>");
        Obj("<< /Type /Pages /Kids [3 0 R] /Count 1 >>");
        Obj("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Annots [4 0 R] >>");
        Obj($"<< /Type /Annot /Subtype /Widget /FT /Sig /T (Existing) /P 3 0 R /Rect {rect} /F 4 >>");
        int xref = sb.Length;
        sb.Append($"xref\n0 {offsets.Count + 1}\n0000000000 65535 f \n");
        foreach (int o in offsets)
        {
            sb.Append($"{o:D10} 00000 n \n");
        }

        sb.Append($"trailer\n<< /Size {offsets.Count + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n");
        return Encoding.Latin1.GetBytes(sb.ToString());
    }
}
