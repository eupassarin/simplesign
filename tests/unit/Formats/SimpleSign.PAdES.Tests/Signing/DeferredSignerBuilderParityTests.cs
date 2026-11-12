using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Shouldly;
using SimpleSign.Core.Constants;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Extensions;
using SimpleSign.Core.Http;
using SimpleSign.Core.Signing;
using SimpleSign.Core.Validation;
using SimpleSign.PAdES.Inspection;
using SimpleSign.PAdES.Signing;
using SimpleSign.PAdES.Validation;
using SimpleSign.TestHelpers;
using Xunit;

namespace SimpleSign.PAdES.Tests.Signing;

/// <summary>
/// The options <see cref="DeferredSignerBuilder"/> shares with <see cref="PadesSignerBuilder"/>: each one has
/// its effect in a two-phase signature, and what is decided in phase one reaches the signed PDF through the
/// session.
/// </summary>
[Trait("Category", "Unit")]
public sealed class DeferredSignerBuilderParityTests : IDisposable
{
    private const string TsaUrl = "http://198.51.100.1/tsa";
    private const string LeafCrlUrl = "http://198.51.100.1/leaf.crl";
    private const string IntermediateCrlUrl = "http://198.51.100.1/intermediate.crl";
    private static readonly byte[] s_key = DeferredSigningEngineTestAdapter.SessionIntegrityKey;

    private readonly X509Certificate2 _signer = TestCertificateFactory.CreateSelfSignedCert("CN=Deferred Parity, O=Tests");
    private readonly X509Certificate2 _publicCertificate;
    private readonly SyntheticPki _pki = new(crlDistributionPoint: LeafCrlUrl, intermediateCrlDistributionPoint: IntermediateCrlUrl);
    private readonly HttpClient _http;

    public DeferredSignerBuilderParityTests()
    {
        _publicCertificate = RemoteKey.PublicOnly(_signer);
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
        _publicCertificate.Dispose();
        _signer.Dispose();
    }

    private DeferredSignerBuilder Prepare(byte[]? pdf = null) =>
        DeferredSigner.Document(pdf ?? TestPdfFactory.CreateMinimalPdfWithPage())
            .WithCertificate(_publicCertificate)
            .WithSessionIntegrityKey(s_key);

    /// <summary>Signs the prepared data with the key and completes a builder resumed from the session bytes.</summary>
    private async Task<byte[]> Complete(DeferredSigningPrepareResult prepared, Func<DeferredSignerBuilder, DeferredSignerBuilder>? configure = null)
    {
        byte[] signature = RemoteKey.Sign(_signer, prepared.ToSigningRequest());
        DeferredSignerBuilder resumed = DeferredSigner.Resume([.. prepared.SessionData], s_key);
        return await (configure?.Invoke(resumed) ?? resumed).CompleteAsync(signature);
    }

    private static async Task<SignatureFieldInfo> InspectSignature(byte[] signedPdf)
    {
        using var stream = new MemoryStream(signedPdf);
        PdfInspectionResult inspection = await PdfSignatureInspector.InspectAsync(stream);
        return inspection.Signatures.Last(s => !s.IsDocumentTimestamp);
    }

    private async Task ShouldBeValid(byte[] signedPdf, params X509Certificate2[] trusted)
    {
        using var stream = new MemoryStream(signedPdf);
        var results = await new PdfSignatureValidator(new ValidationOptions { CheckRevocation = false, TrustedRoots = [.. trusted.Length == 0 ? [_signer] : trusted] })
            .ValidateAsync(stream);
        results.ShouldNotBeEmpty();
        results[0].IsSignatureValid.ShouldBeTrue(string.Join("; ", results[0].Errors));
        results[0].IsIntegrityValid.ShouldBeTrue();
    }

    // ── WithOperationId ───────────────────────────────────────────────────

    [Fact]
    public async Task WithOperationId_IsInTheSigningRequestTheSessionAndTheAuditOfPhaseTwo()
    {
        var audit = new RecordingAuditSink();
        DeferredSigningPrepareResult prepared = await Prepare().WithOperationId("op-pades-1").PrepareAsync();

        prepared.ToSigningRequest().OperationId.ShouldBe("op-pades-1");
        prepared.DataToSign.ShouldBe(prepared.HashToSign);
        DeferredSigningSession.Deserialize(prepared.SessionData, s_key).OperationId.ShouldBe("op-pades-1");
        byte[] signed = await Complete(prepared, b => b.WithAuditSink(audit));

        SignatureAuditEvent completed = audit.Events.ShouldHaveSingleItem();
        completed.Signed.ShouldBeTrue();
        completed.OperationId.ShouldBe("op-pades-1");
        completed.OutputSha256.ShouldBe(Convert.ToHexString(SHA256.HashData(signed)));
    }

    [Fact]
    public async Task WithOperationId_OnTheResumedBuilder_ReplacesTheOneOfTheSession()
    {
        var audit = new RecordingAuditSink();
        DeferredSigningPrepareResult prepared = await Prepare().WithOperationId("phase-one").PrepareAsync();

        await Complete(prepared, b => b.WithAuditSink(audit).WithOperationId("phase-two"));

        audit.Events.ShouldHaveSingleItem().OperationId.ShouldBe("phase-two");
    }

    [Fact]
    public async Task WithOperationId_RefusalWhilePreparing_IsAuditedWithTheId()
    {
        using X509Certificate2 publicLeaf = RemoteKey.PublicOnly(_pki.Leaf);
        var audit = new RecordingAuditSink();

        // The policy asks for a chain to a given anchor, and none was given.
        var ex = await Should.ThrowAsync<SigningException>(() => DeferredSigner.Document(TestPdfFactory.CreateMinimalPdfWithPage())
            .WithCertificate(publicLeaf, [_pki.IntermediateCa])
            .WithSessionIntegrityKey(s_key)
            .WithSigningPolicy(TestPolicies.SigningWithTrustAnchor)
            .WithAuditSink(audit)
            .WithOperationId("op-refused")
            .PrepareAsync());

        SignatureAuditEvent refused = audit.Events.ShouldHaveSingleItem();
        refused.Signed.ShouldBeFalse();
        refused.Reason.ShouldBe(ex.Reason);
        refused.OperationId.ShouldBe("op-refused");
    }

    // ── WithCountryExtension ──────────────────────────────────────────────

    [Fact]
    public async Task WithCountryExtension_AnchorsOfTheExtension_SatisfyTheTrustCheckOfPhaseOne()
    {
        using X509Certificate2 publicLeaf = RemoteKey.PublicOnly(_pki.Leaf);
        DeferredSignerBuilder builder = DeferredSigner.Document(TestPdfFactory.CreateMinimalPdfWithPage())
            .WithCertificate(publicLeaf, [_pki.IntermediateCa])
            .WithSessionIntegrityKey(s_key)
            .WithSigningPolicy(TestPolicies.SigningWithTrustAnchor);
        var extension = new AnchorExtension(_pki.RootCa);

        await Should.ThrowAsync<SigningException>(() => builder.PrepareAsync());
        DeferredSignerBuilder withExtension = builder.WithCountryExtension(extension);
        DeferredSigningPrepareResult prepared = await withExtension.PrepareAsync();

        withExtension.CountryExtensions.ShouldBe([extension]);
        builder.CountryExtensions.ShouldBeEmpty();
        prepared.HashToSign.ShouldNotBeEmpty();
        builder.WithCountryExtension<EmptyExtension>().CountryExtensions.ShouldHaveSingleItem().ShouldBeOfType<EmptyExtension>();
    }

    [Fact]
    public async Task WithCountryExtension_OnTheResumedBuilder_GivesTheAnchorsThatCheckTheTsa()
    {
        using X509Certificate2 tsaCertificate = _pki.IssueTimestampingCertificate();
        using var tsa = new HttpClient(new MockHttpHandler(async request =>
        {
            byte[] tsq = await request.Content!.ReadAsByteArrayAsync();
            var options = new TimestampTokenOptions { TsaCertificate = tsaCertificate, ExtraCertificates = [_pki.IntermediateCa] };
            var response = new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(TimestampTestResponseBuilder.CreateForRequest(tsq, options)) };
            response.Content.Headers.ContentType = new MediaTypeHeaderValue("application/timestamp-reply");
            return response;
        }));
        var policy = SimpleSign.Core.Policies.SigningPolicy.Default
            .With("Timestamp/ProspectiveCertificateChain", new SimpleSign.Core.Policies.PolicyConstraint(SimpleSign.Core.Policies.ConstraintLevel.Fail));
        DeferredSigningPrepareResult prepared = await Prepare()
            .WithLevel(AdesBaselineProfile.Timestamped(new TimestampOptions(new Uri(TsaUrl))))
            .PrepareAsync();
        Func<DeferredSignerBuilder, DeferredSignerBuilder> resume = b => b
            .WithHttpClientProvider(new SingleClientProvider(tsa))
            .WithSigningPolicy(policy);

        // A session does not carry extensions: without the anchors the TSA is not trusted.
        var ex = await Should.ThrowAsync<SigningException>(() => Complete(prepared, resume));
        byte[] signed = await Complete(prepared, b => resume(b).WithCountryExtension(new AnchorExtension(_pki.RootCa)));

        ex.Reason.ShouldBe(SigningErrorReason.TimestampUntrusted);
        (await InspectSignature(signed)).Timestamp.ShouldNotBeNull();
    }

    // ── WithPdfAPreservation ──────────────────────────────────────────────

    [Fact]
    public async Task WithPdfAPreservation_OptionsThatBreakThePdfALevel_AreRefusedWhilePreparing()
    {
        byte[] pdfA1 = PdfA1(TestPdfFactory.CreateMinimalPdfWithPage());
        var audit = new RecordingAuditSink();

        // PDF/A-1 takes the adbe.pkcs7.detached SubFilter only; the default is ETSI.CAdES.detached.
        var ex = await Should.ThrowAsync<SigningException>(() => Prepare(pdfA1).WithPdfAPreservation().WithAuditSink(audit).PrepareAsync());
        DeferredSigningPrepareResult unchecked_ = await Prepare(pdfA1).PrepareAsync();
        DeferredSigningPrepareResult compatible = await Prepare(pdfA1)
            .WithPdfAPreservation()
            .WithSubFilter(PdfSignatureSubFilter.AdbePkcs7Detached)
            .PrepareAsync();

        ex.Reason.ShouldBe(SigningErrorReason.DocumentNotSignable);
        ex.Message.ShouldContain("PDF/A");
        audit.Events.ShouldHaveSingleItem().Reason.ShouldBe(SigningErrorReason.DocumentNotSignable);
        unchecked_.HashToSign.ShouldNotBeEmpty();
        byte[] signed = await Complete(compatible);
        (await InspectSignature(signed)).SubFilter.ShouldBe("adbe.pkcs7.detached");
        await ShouldBeValid(signed);
    }

    [Fact]
    public async Task WithPdfAPreservation_DocumentThatIsNotPdfA_Prepares()
    {
        DeferredSigningPrepareResult prepared = await Prepare().WithPdfAPreservation().PrepareAsync();

        await ShouldBeValid(await Complete(prepared));
    }

    // ── WithSignaturePolicy, WithMetadata ─────────────────────────────────

    [Fact]
    public async Task WithSignaturePolicy_IsASignedAttributeOfTheCompletedSignature()
    {
        byte[] policyDocument = "a signature policy document"u8.ToArray();
        var policy = new SignaturePolicyReference("2.16.76.1.7.1.11.1.1", Oids.Sha256, SHA256.HashData(policyDocument), "https://example.com/policy.der");

        DeferredSigningPrepareResult prepared = await Prepare().WithSignaturePolicy(policy).PrepareAsync();
        byte[] signed = await Complete(prepared);

        SignatureFieldInfo signature = await InspectSignature(signed);
        signature.SignaturePolicyOid.ShouldBe(policy.Oid);
        SignaturePolicyReference embedded = CmsAttribute.ReadSignaturePolicy(CmsParser.Parse(signature.CmsRawData.ToArray()).SignedAttrs!).ShouldNotBeNull();
        embedded.Hash.ToArray().ShouldBe(policy.Hash.ToArray());
        CmsParser.Parse(signature.CmsRawData.ToArray()).SignedAttrs.ShouldBe(prepared.HashToSign);
        await ShouldBeValid(signed);
    }

    [Fact]
    public async Task WithMetadata_SetsTheFieldAndTheSignedAttributes()
    {
        var metadata = new SignatureMetadata
        {
            SignerName = "Ana Quispe",
            Reason = "Approval of the contract",
            Location = "Lima",
            Email = "ana@example.com",
            CommitmentType = CommitmentType.ProofOfApproval,
            PolicyOid = "1.2.3.4.5.6",
        };

        DeferredSigningPrepareResult prepared = await Prepare().WithMetadata(metadata).PrepareAsync();
        byte[] signed = await Complete(prepared);

        SignatureFieldInfo signature = await InspectSignature(signed);
        signature.DeclaredSignerName.ShouldBe("Ana Quispe");
        signature.Reason.ShouldBe("Approval of the contract");
        signature.Location.ShouldBe("Lima");
        signature.ContactInfo.ShouldBe("Email: ana@example.com");
        signature.CommitmentTypeOid.ShouldNotBeNull();
        signature.SignaturePolicyOid.ShouldBe("1.2.3.4.5.6");
        await ShouldBeValid(signed);
    }

    // ── WithSigningTime, WithDocumentInfo ─────────────────────────────────

    [Fact]
    public async Task WithSigningTime_IsTheTimeOfTheSignatureDictionaryAndOfTheSession()
    {
        var signingTime = DateTimeOffset.FromUnixTimeSeconds(DateTimeOffset.UtcNow.ToUnixTimeSeconds() - 3600);

        DeferredSigningPrepareResult prepared = await Prepare().WithSigningTime(signingTime).PrepareAsync();
        byte[] signed = await Complete(prepared);

        DeferredSigningSession.Deserialize(prepared.SessionData, s_key).SigningTime.ShouldBe(signingTime);
        (await InspectSignature(signed)).PdfDeclaredSigningTime.ShouldBe(signingTime);
        await ShouldBeValid(signed);
    }

    [Fact]
    public async Task WithDocumentInfo_EntryIsWrittenInTheSigningRevisionAndCoveredByTheSignature()
    {
        DeferredSigningPrepareResult prepared = await Prepare()
            .WithDocumentInfo("Title", "Contract42")
            .WithDocumentInfo("Subject", "first")
            .WithDocumentInfo("Subject", "Deferred")
            .PrepareAsync();
        byte[] signed = await Complete(prepared);

        string pdf = Encoding.Latin1.GetString(signed);
        pdf.ShouldContain("Contract42");
        pdf.ShouldContain("Deferred");
        pdf.ShouldNotContain("(first)");
        SignatureFieldInfo signature = await InspectSignature(signed);
        int entry = pdf.IndexOf("Contract42", StringComparison.Ordinal);
        bool covered = entry < signature.ByteRange.Length1
            || (entry >= signature.ByteRange.Offset2 && entry < signature.ByteRange.Offset2 + signature.ByteRange.Length2);
        covered.ShouldBeTrue("the entry is inside the byte range the signature covers");
        await ShouldBeValid(signed);
        Should.Throw<ArgumentException>(() => Prepare().WithDocumentInfo("Bad Key", "value"));
    }

    // ── WithDssArtifacts ──────────────────────────────────────────────────

    [Fact]
    public async Task WithDssArtifacts_TravelInTheSessionAndAreWrittenWithTheLongTermData()
    {
        using X509Certificate2 publicLeaf = RemoteKey.PublicOnly(_pki.Leaf);
        byte[] artifactContent = "policy artifact kept in the DSS"u8.ToArray();
        var profile = AdesBaselineProfile.LongTerm(
            new TimestampOptions(new Uri(TsaUrl)), new LongTermValidationOptions { RevocationPreference = RevocationPreference.CrlFirst });

        DeferredSigningPrepareResult prepared = await DeferredSigner.Document(TestPdfFactory.CreateMinimalPdfWithPage())
            .WithCertificate(publicLeaf, _pki.IntermediatesAndRoot())
            .WithSessionIntegrityKey(s_key)
            .WithLevel(profile)
            .WithDssArtifacts([new PdfDssArtifact("TestPolicyArtifacts", "TestPolicyArtifact", artifactContent)])
            .PrepareAsync();

        PdfDssArtifact inSession = DeferredSigningSession.Deserialize(prepared.SessionData, s_key).DssArtifacts.ShouldNotBeNull().ShouldHaveSingleItem();
        inSession.DssKey.ShouldBe("TestPolicyArtifacts");
        inSession.Content.ToArray().ShouldBe(artifactContent);
        byte[] signed = await DeferredSigner.Resume(prepared.SessionData, s_key)
            .WithHttpClientProvider(new SingleClientProvider(_http))
            .CompleteAsync(RemoteKey.Sign(_pki.Leaf, prepared.ToSigningRequest()));

        string pdf = Encoding.Latin1.GetString(signed);
        pdf.ShouldContain("/TestPolicyArtifacts");
        pdf.ShouldContain("/TestPolicyArtifact ");
        await ShouldBeValid(signed, _pki.RootCa);
    }

    [Fact]
    public async Task WithDssArtifacts_WithoutALongTermLevel_IsRefusedWhilePreparing()
    {
        var ex = await Should.ThrowAsync<SigningException>(() => Prepare()
            .WithDssArtifacts([new PdfDssArtifact("TestPolicyArtifacts", "TestPolicyArtifact", new byte[] { 1, 2, 3 })])
            .PrepareAsync());

        ex.Reason.ShouldBe(SigningErrorReason.LevelNotAchievable);
        Should.Throw<ArgumentException>(() => Prepare().WithDssArtifacts([new PdfDssArtifact("Certs", "Cert", new byte[] { 1 })]));
    }

    // ── The field shortcuts ───────────────────────────────────────────────

    [Fact]
    public async Task FieldShortcuts_ChangeOnePartOfTheFieldAndKeepTheRest()
    {
        DeferredSigningPrepareResult prepared = await Prepare()
            .WithFieldOptions(new SignatureFieldOptions { FieldName = "Original", Reason = "Kept reason" })
            .WithFieldName("Approval")
            .WithSubFilter(PdfSignatureSubFilter.AdbePkcs7Detached)
            .WithAppearance(new SignatureAppearance { Page = 1, X = 40, Y = 40, Width = 180, Height = 50 })
            .PrepareAsync();
        byte[] signed = await Complete(prepared);

        SignatureFieldInfo signature = await InspectSignature(signed);
        signature.FieldName.ShouldBe("Approval");
        signature.Reason.ShouldBe("Kept reason");
        signature.SubFilter.ShouldBe("adbe.pkcs7.detached");
        Encoding.Latin1.GetString(signed).ShouldContain("/AP");
        await ShouldBeValid(signed);
    }

    [Fact]
    public async Task AsCertification_OnlyTheFirstSignatureOfTheDocumentCertifies()
    {
        DeferredSigningPrepareResult first = await Prepare().AsCertification(CertificationLevel.FormFilling).PrepareAsync();
        byte[] certified = await Complete(first);
        byte[] signedOnce = await Complete(await Prepare().PrepareAsync());

        var ex = await Should.ThrowAsync<SigningException>(() => Prepare(signedOnce).AsCertification().PrepareAsync());

        Encoding.Latin1.GetString(certified).ShouldContain("/DocMDP");
        ex.Reason.ShouldBe(SigningErrorReason.DocumentNotSignable);
    }

    // ── CompleteWithDetailsAsync ──────────────────────────────────────────

    [Theory]
    [InlineData(AdesBaselineLevel.Basic)]
    [InlineData(AdesBaselineLevel.Timestamped)]
    [InlineData(AdesBaselineLevel.LongTerm)]
    [InlineData(AdesBaselineLevel.Archive)]
    public async Task CompleteWithDetailsAsync_EachLevel_ReportsWhatThePdfHolds(AdesBaselineLevel level)
    {
        using X509Certificate2 publicLeaf = RemoteKey.PublicOnly(_pki.Leaf);
        var tsa = new TimestampOptions(new Uri(TsaUrl));
        var validation = new LongTermValidationOptions { RevocationPreference = RevocationPreference.CrlFirst };
        AdesBaselineProfile profile = level switch
        {
            AdesBaselineLevel.Basic => AdesBaselineProfile.Basic(),
            AdesBaselineLevel.Timestamped => AdesBaselineProfile.Timestamped(tsa),
            AdesBaselineLevel.LongTerm => AdesBaselineProfile.LongTerm(tsa, validation),
            _ => AdesBaselineProfile.Archive(tsa, validation),
        };
        DeferredSigningPrepareResult prepared = await DeferredSigner.Document(TestPdfFactory.CreateMinimalPdfWithPage())
            .WithCertificate(publicLeaf, _pki.IntermediatesAndRoot())
            .WithSessionIntegrityKey(s_key)
            .WithLevel(profile)
            .PrepareAsync();

        PadesSigningResult result = await DeferredSigner.Resume(prepared.SessionData, s_key)
            .WithHttpClientProvider(new SingleClientProvider(_http))
            .CompleteWithDetailsAsync(RemoteKey.Sign(_pki.Leaf, prepared.ToSigningRequest()));

        result.RequestedLevel.ShouldBe(level);
        result.AchievedLevel.ShouldBe(level);
        result.HasSignatureTimestamp.ShouldBe(level >= AdesBaselineLevel.Timestamped);
        result.HasLongTermValidationMaterial.ShouldBe(level >= AdesBaselineLevel.LongTerm);
        result.HasArchiveTimestamp.ShouldBe(level == AdesBaselineLevel.Archive);
        result.Warnings.ShouldBeEmpty();
        await ShouldBeValid(result.SignedArtifact, _pki.RootCa);
    }

    [Fact]
    public async Task CompleteWithDetailsAsync_ProfileThatMayReturnALowerLevel_ReportsTheLevelReached()
    {
        using HttpClient failing = MockHttpHandler.Failing();
        var audit = new RecordingAuditSink();
        DeferredSigningPrepareResult prepared = await Prepare()
            .WithLevel(AdesBaselineProfile.Timestamped(new TimestampOptions(new Uri(TsaUrl)), SigningLevelFailureBehavior.ReturnLowerLevel))
            .PrepareAsync();
        byte[] signature = RemoteKey.Sign(_signer, prepared.ToSigningRequest());
        DeferredSignerBuilder resumed = DeferredSigner.Resume(prepared.SessionData, s_key)
            .WithHttpClientProvider(new SingleClientProvider(failing))
            .WithAuditSink(audit);

        var ex = await Should.ThrowAsync<SigningException>(() => resumed.CompleteAsync(signature));
        PadesSigningResult result = await resumed.CompleteWithDetailsAsync(signature);

        ex.Reason.ShouldBe(SigningErrorReason.DowngradeRequiresDetailedResult);
        result.RequestedLevel.ShouldBe(AdesBaselineLevel.Timestamped);
        result.AchievedLevel.ShouldBe(AdesBaselineLevel.Basic);
        result.HasSignatureTimestamp.ShouldBeFalse();
        result.Warnings.ShouldContain(w => w.Code == SigningWarningCode.LevelDowngraded);
        audit.Events.ShouldHaveSingleItem().AchievedLevel.ShouldBe(AdesBaselineLevel.Basic);
        await ShouldBeValid(result.SignedArtifact);
    }

    [Fact]
    public async Task CompleteAsync_StrictProfileAndTsaThatDoesNotAnswer_Throws()
    {
        using HttpClient failing = MockHttpHandler.Failing();
        DeferredSigningPrepareResult prepared = await Prepare()
            .WithLevel(AdesBaselineProfile.Timestamped(new TimestampOptions(new Uri(TsaUrl))))
            .PrepareAsync();

        var ex = await Should.ThrowAsync<SigningException>(() => DeferredSigner.Resume(prepared.SessionData, s_key)
            .WithHttpClientProvider(new SingleClientProvider(failing))
            .CompleteAsync(RemoteKey.Sign(_signer, prepared.ToSigningRequest())));

        ex.Reason.ShouldBe(SigningErrorReason.NetworkFailure);
    }

    // ── Phase one fixes what is signed ────────────────────────────────────

    [Fact]
    public async Task PhaseOneOptions_OnAResumedBuilder_Throw()
    {
        DeferredSigningPrepareResult prepared = await Prepare().PrepareAsync();
        DeferredSignerBuilder resumed = DeferredSigner.Resume(prepared.SessionData, s_key);

        Should.Throw<InvalidOperationException>(() => resumed.WithSigningTime(DateTimeOffset.UtcNow));
        Should.Throw<InvalidOperationException>(() => resumed.WithSignaturePolicy(new SignaturePolicyReference("1.2.3", Oids.Sha256, new byte[32], null)));
        Should.Throw<InvalidOperationException>(() => resumed.WithMetadata(new SignatureMetadata { SignerName = "x" }));
        Should.Throw<InvalidOperationException>(() => resumed.WithDocumentInfo("Title", "x"));
        Should.Throw<InvalidOperationException>(() => resumed.WithPdfAPreservation());
        Should.Throw<InvalidOperationException>(() => resumed.WithDssArtifacts([]));
        Should.Throw<InvalidOperationException>(() => resumed.WithFieldName("x"));
        Should.Throw<InvalidOperationException>(() => resumed.WithExistingField("x"));
        Should.Throw<InvalidOperationException>(() => resumed.AsCertification());
        Should.Throw<InvalidOperationException>(() => resumed.WithSubFilter(PdfSignatureSubFilter.AdbePkcs7Detached));
        Should.Throw<InvalidOperationException>(() => resumed.WithAppearance(new SignatureAppearance()));
    }

    // ── Sessions of earlier versions ──────────────────────────────────────

    [Fact]
    public async Task Resume_SessionPreparedBeforeTheNewFields_VerifiesAndCompletes()
    {
        // Captured from version 0.10.1, before the session gained OperationId, DssArtifacts and the clock skew.
        string fixtures = RepositoryPaths.Get("tests", "unit", "Formats", "SimpleSign.PAdES.Tests", "Signing", "Fixtures");
        byte[] session = await File.ReadAllBytesAsync(Path.Combine(fixtures, "deferred-session-0.10.json"));
        byte[] signature = Convert.FromBase64String(await File.ReadAllTextAsync(Path.Combine(fixtures, "deferred-session-0.10.signature.txt")));

        DeferredSigningSession deserialized = DeferredSigningSession.Deserialize(session, s_key);
        byte[] signed = await DeferredSigner.Resume(session, s_key).CompleteAsync(signature);

        deserialized.OperationId.ShouldBeNull();
        deserialized.DssArtifacts.ShouldBeNull();
        SignatureFieldInfo info = await InspectSignature(signed);
        info.FieldName.ShouldBe("Legacy");
        info.Reason.ShouldBe("Captured before the session gained fields");
        using var stream = new MemoryStream(signed);
        var results = await new PdfSignatureValidator(new ValidationOptions { CheckRevocation = false, TrustSystemRoots = false }).ValidateAsync(stream);
        results[0].IsSignatureValid.ShouldBeTrue(string.Join("; ", results[0].Errors));
        results[0].IsIntegrityValid.ShouldBeTrue();
    }

    [Fact]
    public async Task SessionData_NewFieldsAtTheirDefault_AreNotWritten()
    {
        DeferredSigningPrepareResult prepared = await Prepare().PrepareAsync();

        // An instance of an earlier version re-serializes the session to check its HMAC: a field it does
        // not know must not be there unless the option that needs it was used.
        string json = Encoding.UTF8.GetString(prepared.SessionData);
        foreach (string added in new[] { "OperationId", "DssArtifacts", "LongTermClockSkewSeconds" })
        {
            json.ShouldNotContain($"\"{added}\"");
        }
    }

    [Fact]
    public async Task SessionData_ClockSkewTolerance_IsRestoredInPhaseTwo()
    {
        var validation = new LongTermValidationOptions { ClockSkewTolerance = TimeSpan.FromSeconds(90) };
        DeferredSigningPrepareResult prepared = await Prepare()
            .WithLevel(AdesBaselineProfile.LongTerm(new TimestampOptions(new Uri(TsaUrl)), validation))
            .PrepareAsync();

        DeferredSigningSession.Deserialize(prepared.SessionData, s_key).LongTermClockSkewSeconds.ShouldBe(90);
    }

    /// <summary>The same PDF declared as PDF/A-1b: the identification the detector reads, after the last %%EOF.</summary>
    private static byte[] PdfA1(byte[] pdf) =>
        [.. pdf, .. "\n%<pdfaid:part>1</pdfaid:part><pdfaid:conformance>B</pdfaid:conformance>\n"u8];

    private sealed class AnchorExtension(X509Certificate2 anchor) : ICountryExtension
    {
        public string RegionCode => "TEST";

        public string DisplayName => "Test anchors";

        public IReadOnlyList<ITrustAnchorProvider> TrustAnchorProviders { get; } = [new InMemoryTrustAnchors(anchor)];

        public IReadOnlyList<IChainValidationProvider> ChainValidationProviders => [];
    }

    private sealed class EmptyExtension : ICountryExtension
    {
        public string RegionCode => "NONE";

        public string DisplayName => "No anchors";

        public IReadOnlyList<ITrustAnchorProvider> TrustAnchorProviders => [];

        public IReadOnlyList<IChainValidationProvider> ChainValidationProviders => [];
    }
}
