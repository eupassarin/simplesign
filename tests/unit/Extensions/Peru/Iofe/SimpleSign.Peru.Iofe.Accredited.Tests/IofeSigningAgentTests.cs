using Shouldly;
using SimpleSign.Core.Signing;
using SimpleSign.Peru.Iofe.Tests;
using SimpleSign.TestHelpers;

namespace SimpleSign.Peru.Iofe.Accredited.Tests;

/// <summary>
/// The signing agent of section 4.2 against a real PKCS#11 module (SoftHSM2), with the time-stamp checks of section
/// 4.4. Skipped unless <c>SOFTHSM2_MODULE</c> is set; <c>scripts/tests/pkcs11.sh</c> runs them in Docker.
/// </summary>
[Trait("Category", "Pkcs11")]
[Collection(IofeTokenCollection.Name)]
public sealed class IofeSigningAgentTests : IDisposable
{
    private static readonly IofeTransaction Invoice = new("factura", "F001-123");

    private readonly IofeTokenFixture _hsm;
    private readonly RecordingAuditSink _audit = new();

    public IofeSigningAgentTests(IofeTokenFixture hsm)
    {
        _hsm = hsm;
        _hsm.TestPki?.Reset();
    }

    public void Dispose() => _hsm.TestPki?.Reset();

    private IofeTestPki Pki => _hsm.TestPki;

    private IofeSigningAgentOptions Options(string key = IofeTokenFixture.AgentKey) => new()
    {
        Module = _hsm.Module(key),
        ModuleDeclaration = IofeTokenFixture.Declaration,
        Audit = _audit,
        Transactions = ["factura", "constancia"],
        Trust = IofeTrust.InstalledRoots([Pki.Pki.RootCa]),
        HttpClientProvider = Pki.Provider,
    };

    private IofeTimestampAuthority Authority => new(new Uri(IofeTestPki.TsaUrl), Pki.Tsa);

    private async Task<IofeVerification> VerifyAsync(IofeSignedDocument signed, byte[]? detachedContent = null)
    {
        await using var verifier = await IofeVerificationAgent.CreateAsync(new IofeVerificationAgentOptions
        {
            Audit = new RecordingVerificationAuditSink(),
            Notifier = new RecordingNotifier(),
            Trust = IofeTrust.InstalledRoots([Pki.Pki.RootCa]),
            HttpClientProvider = Pki.Provider,
        });
        return await verifier.VerifyAsync(signed.Document, new IofeSender("20123456789"), new IofeVerificationRequest { DetachedContent = detachedContent });
    }

    [SkippableFact]
    [Trait("AnnexB", "F-15")]
    [Trait("AnnexB", "F-17")]
    [Trait("AnnexB", "F-18")]
    public async Task SignPdfAsync_AllowedTransaction_SignsInTheModuleAndRecordsIt()
    {
        Skip.If(_hsm.SkipReason is not null, _hsm.SkipReason);
        await using var agent = await IofeSigningAgent.OpenAsync(Options());

        var signed = await agent.SignPdfAsync(TestPdfFactory.CreateMinimalPdf(), Invoice);

        signed.Format.ShouldBe(IofeDocumentFormat.Pdf);
        signed.Level.ShouldBe(AdesBaselineLevel.Basic);
        signed.Timestamped.ShouldBeFalse();
        signed.OperationId.ShouldBe("factura/F001-123");
        signed.PolicyName.ShouldBe(IofePolicies.AgentSigning.Name);
        signed.UnderContingency.ShouldBeFalse();
        signed.KeySource.ShouldBe(IofeKeySourceKind.Module);
        agent.RemoteService.ShouldBeNull();
        var module = agent.Module.ShouldNotBeNull();
        module.KeyProtection.IsConfinedToToken.ShouldBeTrue();
        module.Declaration.ShouldBe(IofeTokenFixture.Declaration);
        var record = _audit.Events.ShouldHaveSingleItem();
        record.Signed.ShouldBeTrue();
        record.OperationId.ShouldBe("factura/F001-123");
        record.PolicyName.ShouldBe(IofePolicies.AgentSigning.Name);
        record.CertificateSha256.ShouldBe(signed.SignerCertificateSha256);
        var verification = await VerifyAsync(signed);
        verification.Accepted.ShouldBeTrue(string.Join("; ", verification.Reasons));
    }

    [SkippableFact]
    public async Task SignCmsAsyncAndSignXmlAsync_AllowedTransaction_ProduceSignaturesTheVerifierAccepts()
    {
        Skip.If(_hsm.SkipReason is not null, _hsm.SkipReason);
        await using var agent = await IofeSigningAgent.OpenAsync(Options());
        byte[] data = "constancia de pago"u8.ToArray();

        var attached = await agent.SignCmsAsync(data, new IofeTransaction("constancia", "C-1"));
        var detached = await agent.SignCmsAsync(data, new IofeTransaction("constancia", "C-2"), detached: true);
        var xml = await agent.SignXmlAsync("<factura><total>10</total></factura>"u8.ToArray(), Invoice);

        (await VerifyAsync(attached)).Accepted.ShouldBeTrue();
        (await VerifyAsync(detached, data)).Accepted.ShouldBeTrue();
        var xmlVerification = await VerifyAsync(xml);
        xmlVerification.Format.ShouldBe(IofeDocumentFormat.Xml);
        xmlVerification.Accepted.ShouldBeTrue(string.Join("; ", xmlVerification.Reasons));
        _audit.Events.Select(e => e.OperationId).ShouldBe(["constancia/C-1", "constancia/C-2", "factura/F001-123"]);
    }

    [SkippableFact]
    public async Task SignPdfAsync_TransactionOutsideTheAgents_IsRefusedAndRecorded()
    {
        Skip.If(_hsm.SkipReason is not null, _hsm.SkipReason);
        await using var agent = await IofeSigningAgent.OpenAsync(Options());

        var ex = await Should.ThrowAsync<IofeAccreditationException>(
            () => agent.SignPdfAsync(TestPdfFactory.CreateMinimalPdf(), new IofeTransaction("contrato", "X-9")));

        ex.Refusal.ShouldBe(IofeRefusal.TransactionNotAllowed);
        var record = _audit.Events.ShouldHaveSingleItem();
        record.Signed.ShouldBeFalse();
        record.OperationId.ShouldBe("contrato/X-9");
        record.Message.ShouldNotBeNull().ShouldContain(nameof(IofeRefusal.TransactionNotAllowed));
    }

    [SkippableFact]
    [Trait("AnnexB", "F-18")]
    public async Task OpenAsync_ExtractableKey_IsRefusedAndRecorded()
    {
        Skip.If(_hsm.SkipReason is not null, _hsm.SkipReason);

        var ex = await Should.ThrowAsync<IofeAccreditationException>(() => IofeSigningAgent.OpenAsync(Options(IofeTokenFixture.ExtractableKey)));

        ex.Refusal.ShouldBe(IofeRefusal.KeyNotInModule);
        ex.Message.ShouldContain("CKA_EXTRACTABLE=true");
        _audit.Events.ShouldHaveSingleItem().Signed.ShouldBeFalse();
    }

    [SkippableFact]
    [Trait("AnnexB", "F-19")]
    public async Task OpenAsync_TokenThatIsNotTheDeclaredModule_IsRefused()
    {
        Skip.If(_hsm.SkipReason is not null, _hsm.SkipReason);
        var options = Options() with { ModuleDeclaration = new IofeModuleDeclaration("Thales", "Luna K7", "FIPS 140-2 Level 3", "4090") };

        var ex = await Should.ThrowAsync<IofeAccreditationException>(() => IofeSigningAgent.OpenAsync(options));

        ex.Refusal.ShouldBe(IofeRefusal.ModuleMismatch);
        _audit.Events.ShouldHaveSingleItem().Signed.ShouldBeFalse();
    }

    [SkippableFact]
    public async Task OpenAsync_IncompleteOptions_IsRefused()
    {
        Skip.If(_hsm.SkipReason is not null, _hsm.SkipReason);

        var noAudit = await Should.ThrowAsync<IofeAccreditationException>(() => IofeSigningAgent.OpenAsync(Options() with { Audit = null! }));
        var noTransactions = await Should.ThrowAsync<IofeAccreditationException>(() => IofeSigningAgent.OpenAsync(Options() with { Transactions = [] }));
        var noDeclaration = await Should.ThrowAsync<IofeAccreditationException>(() => IofeSigningAgent.OpenAsync(Options() with { ModuleDeclaration = null! }));

        noAudit.Refusal.ShouldBe(IofeRefusal.AuditMissing);
        noTransactions.Refusal.ShouldBe(IofeRefusal.OptionsIncomplete);
        noDeclaration.Refusal.ShouldBe(IofeRefusal.OptionsIncomplete);
    }

    [SkippableFact]
    public async Task SignPdfAsync_RevokedCertificate_IsRefusedAndRecorded()
    {
        Skip.If(_hsm.SkipReason is not null, _hsm.SkipReason);
        await using var agent = await IofeSigningAgent.OpenAsync(Options());
        Pki.LeafRevoked = true;

        var ex = await Should.ThrowAsync<SigningException>(() => agent.SignPdfAsync(TestPdfFactory.CreateMinimalPdf(), Invoice));

        ex.Reason.ShouldBe(SigningErrorReason.CertificateRevoked);
        var record = _audit.Events.ShouldHaveSingleItem();
        record.Signed.ShouldBeFalse();
        record.Reason.ShouldBe(SigningErrorReason.CertificateRevoked);
    }

    [SkippableFact]
    public async Task SignPdfAsync_CertificateWithoutNonRepudiation_IsRefused()
    {
        Skip.If(_hsm.SkipReason is not null, _hsm.SkipReason);
        await using var agent = await IofeSigningAgent.OpenAsync(Options(IofeTokenFixture.DigitalSignatureOnlyKey));

        var ex = await Should.ThrowAsync<SigningException>(() => agent.SignPdfAsync(TestPdfFactory.CreateMinimalPdf(), Invoice));

        ex.Reason.ShouldBe(SigningErrorReason.KeyUsageNotPermitted);
    }

    [SkippableFact]
    [Trait("AnnexB", "F-3")]
    public async Task SignPdfAsync_RootNotTrusted_IsRefused()
    {
        Skip.If(_hsm.SkipReason is not null, _hsm.SkipReason);
        using var other = new SyntheticPki();
        await using var agent = await IofeSigningAgent.OpenAsync(Options() with { Trust = IofeTrust.InstalledRoots([other.RootCa]) });

        var ex = await Should.ThrowAsync<SigningException>(() => agent.SignPdfAsync(TestPdfFactory.CreateMinimalPdf(), Invoice));

        ex.Reason.ShouldBe(SigningErrorReason.UntrustedRoot);
    }

    [SkippableFact]
    public async Task SignPdfAsync_RevocationUnavailable_IsRefusedUnlessAContingencyIsInForce()
    {
        Skip.If(_hsm.SkipReason is not null, _hsm.SkipReason);
        var now = DateTimeOffset.UtcNow;
        var clock = new ManualClock(now);
        var contingency = new IofeContingency("PROC-AAC-07", now.AddHours(-1), now.AddHours(1));
        Pki.CrlsDown = true;

        SigningException refused;
        await using (var strict = await IofeSigningAgent.OpenAsync(Options()))
        {
            refused = await Should.ThrowAsync<SigningException>(() => strict.SignPdfAsync(TestPdfFactory.CreateMinimalPdf(), Invoice));
        }

        await using var relaxed = await IofeSigningAgent.OpenAsync(Options() with { Contingency = contingency, TimeProvider = clock });
        var signed = await relaxed.SignPdfAsync(TestPdfFactory.CreateMinimalPdf(), Invoice);
        clock.Now = now.AddHours(2);
        var expired = await Should.ThrowAsync<IofeAccreditationException>(() => relaxed.SignPdfAsync(TestPdfFactory.CreateMinimalPdf(), Invoice));

        refused.Reason.ShouldBe(SigningErrorReason.RevocationStatusUnknown);
        signed.UnderContingency.ShouldBeTrue();
        signed.PolicyName.ShouldContain("PROC-AAC-07");
        expired.Refusal.ShouldBe(IofeRefusal.ContingencyExpired);
        _audit.Events.Count.ShouldBe(3);
        _audit.Events[1].Signed.ShouldBeTrue();
        _audit.Events[1].PolicyName.ShouldNotBeNull().ShouldContain("contingencia: PROC-AAC-07");
        _audit.Events[2].Signed.ShouldBeFalse();
    }

    [SkippableFact]
    [Trait("AnnexB", "F-14")]
    public async Task SignPdfAsync_RevokedCertificateUnderAContingency_IsStillRefused()
    {
        Skip.If(_hsm.SkipReason is not null, _hsm.SkipReason);
        var now = DateTimeOffset.UtcNow;
        await using var agent = await IofeSigningAgent.OpenAsync(
            Options() with { Contingency = new IofeContingency("PROC-AAC-07", now.AddHours(-1), now.AddHours(1)) });
        Pki.LeafRevoked = true;

        var ex = await Should.ThrowAsync<SigningException>(() => agent.SignPdfAsync(TestPdfFactory.CreateMinimalPdf(), Invoice));

        ex.Reason.ShouldBe(SigningErrorReason.CertificateRevoked);
    }

    // Section 4.4: the checks of each time-stamp asked for.

    [SkippableFact]
    public async Task SignPdfAsync_WithTheTimestampAuthority_ReachesLongTermAndIsAccepted()
    {
        Skip.If(_hsm.SkipReason is not null, _hsm.SkipReason);
        await using var agent = await IofeSigningAgent.OpenAsync(Options() with { Timestamp = Authority });

        var signed = await agent.SignPdfAsync(TestPdfFactory.CreateMinimalPdf(), Invoice);

        signed.Level.ShouldBe(AdesBaselineLevel.LongTerm);
        signed.Timestamped.ShouldBeTrue();
        var verification = await VerifyAsync(signed);
        verification.Accepted.ShouldBeTrue(string.Join("; ", verification.Reasons));
    }

    [SkippableFact]
    public async Task SignPdfAsync_TokenOfAnotherAuthority_IsRefused()
    {
        Skip.If(_hsm.SkipReason is not null, _hsm.SkipReason);
        await using var agent = await IofeSigningAgent.OpenAsync(Options() with { Timestamp = Authority });
        Pki.TsaImpostor = true;

        var ex = await Should.ThrowAsync<SigningException>(() => agent.SignPdfAsync(TestPdfFactory.CreateMinimalPdf(), Invoice));

        ex.Reason.ShouldBe(SigningErrorReason.TimestampUntrusted);
        _audit.Events.ShouldHaveSingleItem().Signed.ShouldBeFalse();
    }

    [SkippableFact]
    public async Task SignPdfAsync_TokenWithABrokenSignature_IsRefused()
    {
        Skip.If(_hsm.SkipReason is not null, _hsm.SkipReason);
        await using var agent = await IofeSigningAgent.OpenAsync(Options() with { Timestamp = Authority });
        Pki.TsaTampered = true;

        await Should.ThrowAsync<SigningException>(() => agent.SignPdfAsync(TestPdfFactory.CreateMinimalPdf(), Invoice));

        _audit.Events.ShouldHaveSingleItem().Signed.ShouldBeFalse();
    }

    [SkippableFact]
    public async Task SignPdfAsync_RevokedTimestampAuthority_IsRefused()
    {
        Skip.If(_hsm.SkipReason is not null, _hsm.SkipReason);
        await using var agent = await IofeSigningAgent.OpenAsync(Options() with { Timestamp = Authority });
        Pki.TsaRevoked = true;

        var ex = await Should.ThrowAsync<SigningException>(() => agent.SignPdfAsync(TestPdfFactory.CreateMinimalPdf(), Invoice));

        ex.Reason.ShouldBe(SigningErrorReason.TimestampCertificateRevoked);
    }

    [SkippableFact]
    [Trait("AnnexB", "F-30")]
    public async Task Viewer_SignedPdf_ShowsTheSignerInSpanish()
    {
        Skip.If(_hsm.SkipReason is not null, _hsm.SkipReason);
        await using var agent = await IofeSigningAgent.OpenAsync(Options());
        var signed = await agent.SignPdfAsync(TestPdfFactory.CreateMinimalPdf(), Invoice);

        string page = await agent.Viewer.RenderAsync(signed.Document);

        page.ShouldContain("lang=\"es\"");
        page.ShouldContain(agent.SignerSubject.Split(',')[0]);
        page.ShouldContain("BEGIN PUBLIC KEY");
    }
}
