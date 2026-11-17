using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Shouldly;
using SimpleSign.CAdES;
using SimpleSign.Core.Validation;
using SimpleSign.PAdES;
using SimpleSign.Peru.Iofe.Tests;
using SimpleSign.TestHelpers;
using SimpleSign.XAdES;

namespace SimpleSign.Peru.Iofe.Accredited.Tests;

[Trait("Category", "Unit")]
public sealed class IofeVerificationAgentTests : IDisposable
{
    private static readonly IofeSender Sender = new("20123456789", "mesa@entidad.example");

    private readonly IofeTestPki _pki = new();
    private readonly RecordingVerificationAuditSink _audit = new();
    private readonly RecordingNotifier _notifier = new();

    public void Dispose() => _pki.Dispose();

    private Task<IofeVerificationAgent> AgentAsync(IofeContingency? contingency = null, IofeTrust? trust = null, TimeProvider? clock = null) =>
        IofeVerificationAgent.CreateAsync(new IofeVerificationAgentOptions
        {
            Audit = _audit,
            Notifier = _notifier,
            Trust = trust ?? IofeTrust.InstalledRoots([_pki.Pki.RootCa]),
            HttpClientProvider = _pki.Provider,
            Contingency = contingency,
            TimeProvider = clock ?? TimeProvider.System,
        });

    /// <summary>The checks that decided a verification, for the message of a failed assertion.</summary>
    private static string Describe(IofeVerification verification) =>
        string.Join("; ", verification.Reasons.Concat(verification.Signatures.SelectMany(s => s.Constraints)
            .Where(c => c.Status is ConstraintStatus.Failed or ConstraintStatus.Indeterminate)
            .Select(c => $"{c.Id}={c.Status}/{c.SubIndication}")));

    private Task<byte[]> SignedPdfAsync(byte[]? pdf = null) =>
        PadesSigner.Document(pdf ?? TestPdfFactory.CreateMinimalPdf())
            .WithCertificate(_pki.Pki.Leaf, _pki.Pki.IntermediatesAndRoot())
            .SignAsync();

    [Fact]
    [Trait("AnnexB", "V-5")]
    [Trait("AnnexB", "V-15")]
    public async Task VerifyAsync_ValidPdf_IsAcceptedAndRecorded()
    {
        await using var agent = await AgentAsync();

        var result = await agent.VerifyAsync(await SignedPdfAsync(), Sender, new IofeVerificationRequest { Reference = "MP-2026-001" });

        result.Accepted.ShouldBeTrue(string.Join("; ", result.Reasons));
        result.Format.ShouldBe(IofeDocumentFormat.Pdf);
        result.Signatures.Count.ShouldBe(1);
        result.Notice.ShouldBeNull();
        result.EtsiReportXml.ShouldContain("TOTAL-PASSED");
        _notifier.Notices.ShouldBeEmpty();
        var record = _audit.Events.ShouldHaveSingleItem();
        record.Accepted.ShouldBeTrue();
        record.SenderId.ShouldBe(Sender.Id);
        record.Reference.ShouldBe("MP-2026-001");
        record.DocumentSha256.ShouldBe(result.DocumentSha256);
        record.NoticeDelivered.ShouldBeNull();
        record.PolicyName.ShouldBe(IofePolicies.AgentValidation.Name);
    }

    [Fact]
    public async Task VerifyAsync_CmsAndXml_AreAccepted()
    {
        await using var agent = await AgentAsync();
        byte[] cms = await CadesSigner.Document("contenido"u8.ToArray())
            .WithCertificate(_pki.Pki.Leaf, _pki.Pki.IntermediatesAndRoot())
            .WithContentType(CadesContentType.Enveloped)
            .SignAsync();
        byte[] xml = await XadesSigner.Document("<documento><dato>1</dato></documento>"u8.ToArray())
            .WithCertificate(_pki.Pki.Leaf, _pki.Pki.IntermediatesAndRoot())
            .SignAsync();

        var cmsResult = await agent.VerifyAsync(cms, Sender);
        var xmlResult = await agent.VerifyAsync(xml, Sender);

        cmsResult.Format.ShouldBe(IofeDocumentFormat.Cms);
        cmsResult.Accepted.ShouldBeTrue(string.Join("; ", cmsResult.Reasons));
        xmlResult.Format.ShouldBe(IofeDocumentFormat.Xml);
        xmlResult.Accepted.ShouldBeTrue(string.Join("; ", xmlResult.Reasons));
    }

    [Fact]
    [Trait("AnnexB", "V-5")]
    [Trait("AnnexB", "V-8")]
    [Trait("AnnexB", "V-15")]
    public async Task VerifyAsync_RevokedSigner_IsRejectedWithANoticeToTheSender()
    {
        await using var agent = await AgentAsync();
        byte[] signed = await SignedPdfAsync();
        _pki.LeafRevoked = true;

        var result = await agent.VerifyAsync(signed, Sender, new IofeVerificationRequest { Reference = "MP-2026-002" });

        result.Accepted.ShouldBeFalse();
        result.Signatures[0].Indication.ShouldNotBe(SignatureIndication.Valid);
        var notice = _notifier.Notices.ShouldHaveSingleItem();
        notice.ShouldBe(result.Notice);
        notice.Sender.ShouldBe(Sender);
        notice.Reference.ShouldBe("MP-2026-002");
        notice.Text.ShouldContain("COMUNICADO DE RECHAZO");
        notice.Text.ShouldContain(result.DocumentSha256);
        notice.Text.ShouldContain("Firma 1");
        var record = _audit.Events.ShouldHaveSingleItem();
        record.Accepted.ShouldBeFalse();
        record.NoticeDelivered.ShouldBe(true);
        record.Reasons.ShouldNotBeEmpty();
    }

    [Fact]
    [Trait("AnnexB", "V-30")]
    public async Task VerifyAsync_DocumentChangedAfterSigning_IsRejected()
    {
        await using var agent = await AgentAsync();
        byte[] signed = await SignedPdfAsync();
        // A byte of the signed content (the PDF header's version digit), not of the signature.
        signed[7] = (byte)'9';

        var result = await agent.VerifyAsync(signed, Sender);

        result.Accepted.ShouldBeFalse();
        _notifier.Notices.Count.ShouldBe(1);
    }

    [Fact]
    public async Task VerifyAsync_DocumentWithoutSignatures_IsRejected()
    {
        await using var agent = await AgentAsync();

        var result = await agent.VerifyAsync(TestPdfFactory.CreateMinimalPdf(), Sender);

        result.Accepted.ShouldBeFalse();
        result.Reasons.ShouldContain(r => r.Contains("no contiene firmas", StringComparison.Ordinal));
        result.EtsiReportXml.ShouldBeEmpty();
        _notifier.Notices.Count.ShouldBe(1);
    }

    [Fact]
    public async Task VerifyAsync_UnreadableDocument_IsRejectedNotThrown()
    {
        await using var agent = await AgentAsync();

        var result = await agent.VerifyAsync([0x30, 0x03, 0x02, 0x01, 0x05], Sender);

        result.Accepted.ShouldBeFalse();
        result.Format.ShouldBe(IofeDocumentFormat.Cms);
        _notifier.Notices.Count.ShouldBe(1);
        _audit.Events.ShouldHaveSingleItem().Accepted.ShouldBeFalse();
    }

    [Fact]
    [Trait("AnnexB", "V-12")]
    public async Task VerifyAsync_SignerWithoutNonRepudiation_IsRejected()
    {
        await using var agent = await AgentAsync();
        using var key = RSA.Create(2048);
        using var certificate = _pki.IssueSigner("CN=Solo firma digital, O=SimpleSign Tests", key, X509KeyUsageFlags.DigitalSignature);
        using var withKey = certificate.CopyWithPrivateKey(key);
        byte[] signed = await PadesSigner.Document(TestPdfFactory.CreateMinimalPdf())
            .WithCertificate(withKey, _pki.Pki.IntermediatesAndRoot())
            .SignAsync();

        var result = await agent.VerifyAsync(signed, Sender);

        result.Accepted.ShouldBeFalse("an automated agent accepts only signatures with nonRepudiation (Req. 23)");
    }

    [Fact]
    public async Task VerifyAsync_NotifierFails_ThrowsAndRecordsTheNoticeAsNotDelivered()
    {
        await using var agent = await AgentAsync();
        _notifier.Fails = true;

        var ex = await Should.ThrowAsync<IofeAccreditationException>(() => agent.VerifyAsync(TestPdfFactory.CreateMinimalPdf(), Sender));

        ex.Refusal.ShouldBe(IofeRefusal.NoticeNotDelivered);
        ex.InnerException.ShouldBeOfType<IOException>();
        var record = _audit.Events.ShouldHaveSingleItem();
        record.Accepted.ShouldBeFalse();
        record.NoticeDelivered.ShouldBe(false);
    }

    [Fact]
    [Trait("AnnexB", "V-14")]
    public async Task VerifyAsync_RevocationUnavailable_IsRejectedUnlessAContingencyIsInForce()
    {
        byte[] signed = await SignedPdfAsync();
        _pki.CrlsDown = true;
        var now = DateTimeOffset.UtcNow;
        var contingency = new IofeContingency("PROC-AAC-07", now.AddHours(-1), now.AddHours(1));

        await using var strict = await AgentAsync();
        var refused = await strict.VerifyAsync(signed, Sender);
        await using var relaxed = await AgentAsync(contingency);
        var accepted = await relaxed.VerifyAsync(signed, Sender);

        refused.Accepted.ShouldBeFalse("the checks stay on while no contingency is declared (Req. 24)");
        accepted.Accepted.ShouldBeTrue(Describe(accepted));
        _audit.Events[0].Contingency.ShouldBeNull();
        _audit.Events[1].Contingency.ShouldBe("PROC-AAC-07");
    }

    [Fact]
    [Trait("AnnexB", "V-14")]
    public async Task VerifyAsync_RevokedSignerUnderAContingency_IsStillRejected()
    {
        var now = DateTimeOffset.UtcNow;
        await using var agent = await AgentAsync(new IofeContingency("PROC-AAC-07", now.AddHours(-1), now.AddHours(1)));
        byte[] signed = await SignedPdfAsync();
        _pki.LeafRevoked = true;

        var result = await agent.VerifyAsync(signed, Sender);

        result.Accepted.ShouldBeFalse("a contingency tolerates a status that cannot be obtained, not a revoked certificate");
        result.Signatures[0].Constraints.ShouldContain(
            c => c.Id.EndsWith("/NotRevoked", StringComparison.Ordinal) && c.Status == ConstraintStatus.Failed, Describe(result));
        _audit.Events.ShouldHaveSingleItem().Contingency.ShouldBe("PROC-AAC-07");
    }

    [Fact]
    public async Task VerifyAsync_ContingencyOutsideItsValidity_IsRefused()
    {
        var now = DateTimeOffset.UtcNow;
        var clock = new ManualClock(now);
        await using var agent = await AgentAsync(new IofeContingency("PROC-AAC-07", now.AddHours(-1), now.AddHours(1)), clock: clock);
        byte[] signed = await SignedPdfAsync();
        _pki.CrlsDown = true;

        var inForce = await agent.VerifyAsync(signed, Sender);
        clock.Now = now.AddHours(2);
        var ex = await Should.ThrowAsync<IofeAccreditationException>(() => agent.VerifyAsync(signed, Sender));

        inForce.Accepted.ShouldBeTrue(Describe(inForce));
        ex.Refusal.ShouldBe(IofeRefusal.ContingencyExpired);
    }

    [Fact]
    [Trait("AnnexB", "V-1")]
    [Trait("AnnexB", "V-3")]
    public async Task VerifyAsync_TrustedList_AcceptsAListedRootAndRejectsAnUnlistedOne()
    {
        using var list = new IofeListBuilder();
        using var unlisted = new SyntheticPki();
        byte[] listedOnly = list.List(1, [("EC de pruebas", IofeListBuilder.CaQc, IofeListBuilder.UnderSupervision, _pki.Pki.RootCa)]);
        byte[] otherOnly = list.List(1, [("Otra EC", IofeListBuilder.CaQc, IofeListBuilder.UnderSupervision, unlisted.RootCa)]);
        byte[] signed = await SignedPdfAsync();

        await using var trusting = await AgentAsync(trust: IofeTrust.List(IofeExtension.Load(listedOnly, [list.Operator])));
        var accepted = await trusting.VerifyAsync(signed, Sender);
        await using var notTrusting = await AgentAsync(trust: IofeTrust.List(IofeExtension.Load(otherOnly, [list.Operator])));
        var rejected = await notTrusting.VerifyAsync(signed, Sender);

        accepted.Accepted.ShouldBeTrue(string.Join("; ", accepted.Reasons));
        rejected.Accepted.ShouldBeFalse();
    }

    [Fact]
    public async Task CreateAsync_WithoutAuditOrNotifier_IsRefused()
    {
        var noAudit = await Should.ThrowAsync<IofeAccreditationException>(() => IofeVerificationAgent.CreateAsync(
            new IofeVerificationAgentOptions { Audit = null!, Notifier = _notifier, Trust = IofeTrust.InstalledRoots([_pki.Pki.RootCa]) }));
        var noNotifier = await Should.ThrowAsync<IofeAccreditationException>(() => IofeVerificationAgent.CreateAsync(
            new IofeVerificationAgentOptions { Audit = _audit, Notifier = null!, Trust = IofeTrust.InstalledRoots([_pki.Pki.RootCa]) }));

        noAudit.Refusal.ShouldBe(IofeRefusal.AuditMissing);
        noNotifier.Refusal.ShouldBe(IofeRefusal.OptionsIncomplete);
    }

    [Fact]
    [Trait("AnnexB", "V-30")]
    public async Task Viewer_SignedPdf_ShowsIntegrityTimePublicKeyAndCertificateInSpanish()
    {
        await using var agent = await AgentAsync();

        string page = await agent.Viewer.RenderAsync(await SignedPdfAsync());

        page.ShouldContain("lang=\"es\"");
        page.ShouldContain("SimpleSign Synthetic Signer");
        page.ShouldContain("BEGIN PUBLIC KEY");
        page.ShouldContain(_pki.Pki.Leaf.SerialNumber, Case.Insensitive);
    }
}
