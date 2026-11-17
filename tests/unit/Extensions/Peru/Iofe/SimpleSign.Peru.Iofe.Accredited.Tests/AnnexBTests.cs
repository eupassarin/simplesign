using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Shouldly;
using SimpleSign.Core.Signing;
using SimpleSign.PAdES;
using SimpleSign.Peru.Iofe.Tests;
using SimpleSign.TestHelpers;

namespace SimpleSign.Peru.Iofe.Accredited.Tests;

/// <summary>
/// Items of annex B of INDECOPI's guide shown by the accredited agents themselves, beyond those the other test
/// classes of this project already show (each test names its item in the <c>AnnexB</c> trait;
/// <see cref="AnnexBCoverageTests"/> checks that none is left out). The signing key is in a remote signing service in
/// memory, so these run everywhere.
/// </summary>
[Trait("Category", "Unit")]
public sealed class AnnexBTests : IClassFixture<IofeRemoteServiceFixture>, IDisposable
{
    private static readonly IofeTransaction Invoice = new("factura", "F001-123");
    private static readonly IofeSender Sender = new("20123456789");

    private readonly IofeTestPki _pki;
    private readonly FakeRemoteSigningService _service;
    private readonly RecordingAuditSink _audit = new();

    public AnnexBTests(IofeRemoteServiceFixture fixture)
    {
        _pki = fixture.Pki;
        _service = fixture.Service;
        Reset();
    }

    public void Dispose() => Reset();

    private void Reset()
    {
        _pki.Reset();
        _service.Reset();
    }

    private IofeSigningAgentOptions Options(string credential = FakeRemoteSigningService.AgentCredential, IofeTrust? trust = null) => new()
    {
        RemoteService = FakeRemoteSigningService.Service(credential),
        RemoteServiceDeclaration = FakeRemoteSigningService.Declaration,
        Audit = _audit,
        Transactions = ["factura"],
        Trust = trust ?? IofeTrust.InstalledRoots([_pki.Pki.RootCa]),
        HttpClientProvider = _pki.Provider,
    };

    private Task<IofeVerificationAgent> VerifierAsync(IofeTrust? trust = null) =>
        IofeVerificationAgent.CreateAsync(new IofeVerificationAgentOptions
        {
            Audit = new RecordingVerificationAuditSink(),
            Notifier = new RecordingNotifier(),
            Trust = trust ?? IofeTrust.InstalledRoots([_pki.Pki.RootCa]),
            HttpClientProvider = _pki.Provider,
        });

    /// <summary>A document as a third party sends it, signed with the test PKI's signer.</summary>
    private Task<byte[]> ReceivedPdfAsync() =>
        PadesSigner.Document(TestPdfFactory.CreateMinimalPdf()).WithCertificate(_pki.Pki.Leaf, _pki.Pki.IntermediatesAndRoot()).SignAsync();

    /// <summary>
    /// The signature is refused and none is returned or recorded as made. A refusal of the certificate comes before
    /// the key is used; one of the time-stamp comes after (the token is over the signature), and the signature is
    /// thrown away.
    /// </summary>
    private async Task<SigningException> RefusedAsync(IofeSigningAgentOptions options, bool beforeTheKeyIsUsed = true)
    {
        await using var agent = await IofeSigningAgent.OpenAsync(options);
        var ex = await Should.ThrowAsync<SigningException>(() => agent.SignPdfAsync(TestPdfFactory.CreateMinimalPdf(), Invoice));
        if (beforeTheKeyIsUsed)
        {
            _service.HashesSigned.ShouldBe(0, "nothing reaches the key when the policy refuses the certificate");
        }

        _audit.Events.ShouldNotContain(e => e.Signed);
        return ex;
    }

    // ── The trusted list (items 1 to 3) ─────────────────────────────────

    [Fact]
    [Trait("AnnexB", "F-1")]
    [Trait("AnnexB", "F-3")]
    public async Task Sign_ListSignedByItsOperatorWithTheRootListed_Signs()
    {
        using var list = new IofeListBuilder();
        byte[] xml = list.List(1, [("EC de pruebas", IofeListBuilder.CaQc, IofeListBuilder.UnderSupervision, _pki.Pki.RootCa)]);
        await using var agent = await IofeSigningAgent.OpenAsync(Options(trust: IofeTrust.List(IofeExtension.Load(xml, [list.Operator]))));

        var signed = await agent.SignPdfAsync(TestPdfFactory.CreateMinimalPdf(), Invoice);

        signed.Document.ShouldNotBeEmpty();
        _audit.Events.ShouldHaveSingleItem().Signed.ShouldBeTrue();
    }

    [Fact]
    [Trait("AnnexB", "F-1")]
    [Trait("AnnexB", "V-1")]
    public void TrustedList_SignedByAnotherCertificateOrChanged_IsNotRead()
    {
        using var list = new IofeListBuilder();
        using var impostor = new IofeListBuilder("CN=Otro firmante, O=Nadie, C=PE");
        byte[] xml = list.List(1, [("EC de pruebas", IofeListBuilder.CaQc, IofeListBuilder.UnderSupervision, _pki.Pki.RootCa)]);
        byte[] changed = System.Text.Encoding.UTF8.GetBytes(System.Text.Encoding.UTF8.GetString(xml).Replace("EC de pruebas", "EC de otros", StringComparison.Ordinal));

        Should.Throw<Exception>(() => IofeExtension.Load(xml, [impostor.Operator]));
        Should.Throw<Exception>(() => IofeExtension.Load(changed, [list.Operator]));
    }

    [Fact]
    [Trait("AnnexB", "F-2")]
    [Trait("AnnexB", "V-2")]
    public void TrustedList_Expired_IsNotRead()
    {
        using var list = new IofeListBuilder();
        byte[] expired = list.List(
            1, [("EC de pruebas", IofeListBuilder.CaQc, IofeListBuilder.UnderSupervision, _pki.Pki.RootCa)], nextUpdate: DateTimeOffset.UtcNow.AddDays(-1));

        Should.Throw<Exception>(() => IofeExtension.Load(expired, [list.Operator]));
    }

    [Fact]
    [Trait("AnnexB", "F-3")]
    public async Task Sign_RootNotInTheList_IsRefused()
    {
        using var list = new IofeListBuilder();
        using var other = new SyntheticPki();
        byte[] xml = list.List(1, [("Otra EC", IofeListBuilder.CaQc, IofeListBuilder.UnderSupervision, other.RootCa)]);

        var ex = await RefusedAsync(Options(trust: IofeTrust.List(IofeExtension.Load(xml, [list.Operator]))));

        ex.Reason.ShouldBe(SigningErrorReason.UntrustedRoot);
    }

    // ── The chain of the signing certificate ────────────────────────────

    [Fact]
    public async Task Sign_KeyHolderWithoutTheIssuersCertificate_IsRefusedNamingTheMissingIssuer()
    {
        _service.WithoutIssuerCertificate = true;

        var ex = await RefusedAsync(Options());

        ex.Reason.ShouldBe(SigningErrorReason.UntrustedRoot);
        ex.Message.ShouldContain(_pki.Pki.IntermediateCa.Subject);
        ex.Message.ShouldContain("ChainCertificates");
    }

    [Fact]
    public async Task Sign_IssuersCertificateGivenByTheOperator_Signs()
    {
        _service.WithoutIssuerCertificate = true;
        await using var agent = await IofeSigningAgent.OpenAsync(Options() with { ChainCertificates = [_pki.Pki.IntermediateCa] });

        var signed = await agent.SignPdfAsync(TestPdfFactory.CreateMinimalPdf(), Invoice);

        await using var verifier = await VerifierAsync();
        (await verifier.VerifyAsync(signed.Document, Sender)).Accepted.ShouldBeTrue();
        _pki.IssuerDownloads.ShouldBe(0, "nothing is fetched when the operator gave the issuer");
    }

    [Fact]
    public async Task Sign_IssuersCertificateAtTheAddressTheCertificateNames_IsFetchedOnceAndSigns()
    {
        _service.WithoutIssuerCertificate = true;
        var key = RSA.Create(2048);
        _service.AddCredential("con-aia", _pki.IssueSigner(
            "CN=Con AIA, O=SimpleSign Tests", key, X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.NonRepudiation, namesItsIssuer: true), key);
        await using var agent = await IofeSigningAgent.OpenAsync(Options("con-aia"));

        var first = await agent.SignPdfAsync(TestPdfFactory.CreateMinimalPdf(), Invoice);
        await agent.SignPdfAsync(TestPdfFactory.CreateMinimalPdf(), Invoice);

        _pki.IssuerDownloads.ShouldBe(1, "the issuer fetched for the first signature is kept for the next");
        await using var verifier = await VerifierAsync();
        (await verifier.VerifyAsync(first.Document, Sender)).Accepted.ShouldBeTrue();
    }

    [Fact]
    public async Task Sign_GivenIssuerDoesNotMakeAnUntrustedRootTrusted()
    {
        using var other = new SyntheticPki();

        var ex = await RefusedAsync(Options(trust: IofeTrust.InstalledRoots([other.RootCa])) with { ChainCertificates = [_pki.Pki.IntermediateCa, _pki.Pki.RootCa] });

        ex.Reason.ShouldBe(SigningErrorReason.UntrustedRoot);
    }

    // ── An agent that does not open is recorded ─────────────────────────

    [Fact]
    [Trait("AnnexB", "F-15")]
    public async Task Open_ServiceRefusesTheAgent_IsRecordedAndThrownAsItWas()
    {
        var options = Options() with
        {
            RemoteService = FakeRemoteSigningService.Service() with
            {
                Service = new() { BaseUri = FakeRemoteSigningService.BaseUri, ClientId = FakeRemoteSigningService.ClientId, ClientSecret = "otro" },
            },
        };

        await Should.ThrowAsync<SimpleSign.Signers.Cloud.CloudSigningException>(() => IofeSigningAgent.OpenAsync(options));

        var record = _audit.Events.ShouldHaveSingleItem();
        record.Signed.ShouldBeFalse();
        record.Message.ShouldNotBeNull().ShouldStartWith("AgentNotOpened: CloudSigningException");
        record.Message.ShouldNotContain("otro");
        record.CertificateSubject.ShouldBeNull();
    }

    [Fact]
    [Trait("AnnexB", "F-15")]
    public async Task Open_IncompleteOptions_IsRecorded()
    {
        var ex = await Should.ThrowAsync<IofeAccreditationException>(() => IofeSigningAgent.OpenAsync(Options() with { Transactions = [] }));

        ex.Refusal.ShouldBe(IofeRefusal.OptionsIncomplete);
        _audit.Events.ShouldHaveSingleItem().Message.ShouldNotBeNull().ShouldStartWith("AgentNotOpened: IofeAccreditationException");
    }

    [Fact]
    public async Task Open_RefusalOfTheServiceItself_IsRecordedOnce()
    {
        _service.ReportedName = "Otro Servicio";

        await Should.ThrowAsync<IofeAccreditationException>(() => IofeSigningAgent.OpenAsync(Options()));

        _audit.Events.ShouldHaveSingleItem().Message.ShouldNotBeNull().ShouldStartWith(nameof(IofeRefusal.RemoteServiceMismatch));
    }

    // ── The reasons of a rejection, in Spanish ──────────────────────────

    [Fact]
    public async Task Verify_RevokedSignerAndChangedDocument_GiveTheirReasonsInSpanish()
    {
        byte[] received = await ReceivedPdfAsync();
        await using var verifier = await VerifierAsync();
        byte[] changed = (byte[])received.Clone();
        int at = received.AsSpan().IndexOf("/MediaBox"u8) + 12;
        changed[at] ^= 0x01;

        var tampered = await verifier.VerifyAsync(changed, Sender);
        _pki.LeafRevoked = true;
        var revoked = await verifier.VerifyAsync(received, Sender);

        tampered.Reasons.ShouldHaveSingleItem().ShouldContain("el documento fue modificado después de la firma (HashFailure)");
        revoked.Reasons.ShouldHaveSingleItem().ShouldContain("el certificado del firmante está revocado");
        revoked.Notice.ShouldNotBeNull().Text.ShouldNotContain("revocation check failed");
    }

    // ── Revocation (items 6, 7 and 9) ───────────────────────────────────

    [Fact]
    [Trait("AnnexB", "F-6")]
    public async Task Sign_CrlSignedWithAnotherKey_IsRefused()
    {
        using var other = new SyntheticPki();
        _pki.LeafCrlOverride = other.BuildLeafCrl();

        var ex = await RefusedAsync(Options());

        ex.Reason.ShouldBe(SigningErrorReason.RevocationStatusUnknown);
    }

    [Fact]
    [Trait("AnnexB", "F-7")]
    public async Task Sign_CrlExpiredOrWithoutNextUpdate_IsRefused()
    {
        _pki.LeafCrlOverride = _pki.Pki.BuildLeafCrl(DateTimeOffset.UtcNow.AddDays(-10), DateTimeOffset.UtcNow.AddDays(-1));
        (await RefusedAsync(Options())).Reason.ShouldBe(SigningErrorReason.RevocationStatusUnknown);

        _pki.LeafCrlOverride = _pki.Pki.BuildLeafCrlWithoutNextUpdate();
        (await RefusedAsync(Options())).Reason.ShouldBe(SigningErrorReason.RevocationStatusUnknown);
    }

    [Fact]
    [Trait("AnnexB", "F-9")]
    public async Task Sign_IssuingCaRevoked_IsRefused()
    {
        _pki.IntermediateRevoked = true;

        var ex = await RefusedAsync(Options());

        ex.Reason.ShouldBe(SigningErrorReason.CertificateRevoked);
    }

    [Fact]
    [Trait("AnnexB", "V-6")]
    [Trait("AnnexB", "V-7")]
    public async Task Verify_CrlSignedWithAnotherKeyOrExpired_IsRejected()
    {
        byte[] received = await ReceivedPdfAsync();
        await using var verifier = await VerifierAsync();
        using var other = new SyntheticPki();

        _pki.LeafCrlOverride = other.BuildLeafCrl();
        (await verifier.VerifyAsync(received, Sender)).Accepted.ShouldBeFalse("a CRL the CA did not sign says nothing");

        _pki.LeafCrlOverride = _pki.Pki.BuildLeafCrl(DateTimeOffset.UtcNow.AddDays(-10), DateTimeOffset.UtcNow.AddDays(-1));
        (await verifier.VerifyAsync(received, Sender)).Accepted.ShouldBeFalse("an expired CRL says nothing of today");
    }

    [Fact]
    [Trait("AnnexB", "V-9")]
    public async Task Verify_IssuingCaRevoked_IsRejected()
    {
        byte[] received = await ReceivedPdfAsync();
        await using var verifier = await VerifierAsync();
        _pki.IntermediateRevoked = true;

        (await verifier.VerifyAsync(received, Sender)).Accepted.ShouldBeFalse();
    }

    // ── Validity and algorithms (items 11 and 28) ───────────────────────

    [Fact]
    [Trait("AnnexB", "F-11")]
    public async Task Sign_ExpiredCertificate_IsRefused()
    {
        // Valid for one second, a minute after its CA began: over by now.
        var notAfter = _pki.Pki.IntermediateCa.NotBefore.ToUniversalTime().AddMinutes(1).AddSeconds(1);
        notAfter.ShouldBeLessThan(DateTime.UtcNow, "the test PKI's CA must have begun more than a minute ago");
        var key = RSA.Create(2048);
        _service.AddCredential("expirado", _pki.IssueSigner(
            "CN=Certificado expirado, O=SimpleSign Tests", key, X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.NonRepudiation, notAfter), key);

        var ex = await RefusedAsync(Options("expirado"));

        ex.Reason.ShouldBe(SigningErrorReason.CertificateExpired);
    }

    [Fact]
    [Trait("AnnexB", "F-28")]
    public async Task Sign_Rsa1024Key_IsRefused()
    {
        var key = RSA.Create(1024);
        _service.AddCredential("clave-debil", _pki.IssueSigner(
            "CN=Clave debil, O=SimpleSign Tests", key, X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.NonRepudiation), key);

        var ex = await RefusedAsync(Options("clave-debil"));

        ex.Reason.ShouldBe(SigningErrorReason.KeyTooWeak);
    }

    // ── The viewer (item 30) ────────────────────────────────────────────

    [Fact]
    [Trait("AnnexB", "F-30")]
    public async Task Viewer_DocumentTheAgentSigned_ShowsIntegrityPublicKeyAndCertificate()
    {
        await using var agent = await IofeSigningAgent.OpenAsync(Options());
        var signed = await agent.SignPdfAsync(TestPdfFactory.CreateMinimalPdf(), Invoice);

        string page = await agent.Viewer.RenderAsync(signed.Document);

        page.ShouldContain("lang=\"es\"");
        page.ShouldContain("BEGIN PUBLIC KEY");
        page.ShouldContain(_pki.Pki.Leaf.SerialNumber, Case.Insensitive);
    }

    // ── Time-stamps (section 4.4) ───────────────────────────────────────

    [Fact]
    [Trait("AnnexB", "S-1")]
    public async Task Sign_TokenOfAnotherAuthority_IsRefused()
    {
        _pki.TsaImpostor = true;

        var ex = await RefusedAsync(Options() with { Timestamp = new IofeTimestampAuthority(new Uri(IofeTestPki.TsaUrl), _pki.Tsa) }, beforeTheKeyIsUsed: false);

        ex.Reason.ShouldBe(SigningErrorReason.TimestampUntrusted);
    }

    [Fact]
    [Trait("AnnexB", "S-2")]
    public async Task Sign_TokenWithABrokenSignature_IsRefused()
    {
        _pki.TsaTampered = true;

        var ex = await RefusedAsync(Options() with { Timestamp = new IofeTimestampAuthority(new Uri(IofeTestPki.TsaUrl), _pki.Tsa) }, beforeTheKeyIsUsed: false);

        ex.Reason.ShouldBe(SigningErrorReason.TimestampInvalid, "a token that does not verify is not a failure of the network");
    }

    [Fact]
    [Trait("AnnexB", "S-3")]
    public async Task Sign_RevokedTimestampAuthority_IsRefused()
    {
        _pki.TsaRevoked = true;

        var ex = await RefusedAsync(Options() with { Timestamp = new IofeTimestampAuthority(new Uri(IofeTestPki.TsaUrl), _pki.Tsa) }, beforeTheKeyIsUsed: false);

        ex.Reason.ShouldBe(SigningErrorReason.TimestampCertificateRevoked);
    }
}
