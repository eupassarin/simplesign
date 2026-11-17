using Shouldly;
using SimpleSign.Core.Signing;
using SimpleSign.Peru.Iofe.Tests;
using SimpleSign.Signers.Cloud;
using SimpleSign.Signers.Cloud.Csc;
using SimpleSign.TestHelpers;

namespace SimpleSign.Peru.Iofe.Accredited.Tests;

/// <summary>
/// The signing agent of section 4.2 with its key in a remote signing service instead of the organization's module:
/// the same checks, the same audit, and a service that must be the declared one. The service is in memory, so these
/// run everywhere (no SoftHSM2).
/// </summary>
[Trait("Category", "Unit")]
public sealed class IofeRemoteSigningTests : IClassFixture<IofeRemoteServiceFixture>, IDisposable
{
    private static readonly IofeTransaction Invoice = new("factura", "F001-123");

    private readonly IofeTestPki _pki;
    private readonly FakeRemoteSigningService _service;
    private readonly RecordingAuditSink _audit = new();

    public IofeRemoteSigningTests(IofeRemoteServiceFixture fixture)
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

    private IofeSigningAgentOptions Options(string credential = FakeRemoteSigningService.AgentCredential, string? pin = FakeRemoteSigningService.Pin) => new()
    {
        RemoteService = FakeRemoteSigningService.Service(credential, pin),
        RemoteServiceDeclaration = FakeRemoteSigningService.Declaration,
        Audit = _audit,
        Transactions = ["factura", "constancia"],
        Trust = IofeTrust.InstalledRoots([_pki.Pki.RootCa]),
        HttpClientProvider = _pki.Provider,
    };

    private async Task<IofeVerification> VerifyAsync(IofeSignedDocument signed, byte[]? detachedContent = null)
    {
        await using var verifier = await IofeVerificationAgent.CreateAsync(new IofeVerificationAgentOptions
        {
            Audit = new RecordingVerificationAuditSink(),
            Notifier = new RecordingNotifier(),
            Trust = IofeTrust.InstalledRoots([_pki.Pki.RootCa]),
            HttpClientProvider = _pki.Provider,
        });
        return await verifier.VerifyAsync(signed.Document, new IofeSender("20123456789"), new IofeVerificationRequest { DetachedContent = detachedContent });
    }

    [Fact]
    [Trait("AnnexB", "F-15")]
    [Trait("AnnexB", "F-17")]
    [Trait("AnnexB", "F-18")]
    public async Task SignPdfAsync_KeyInARemoteService_SignsThereAndRecordsTheProvider()
    {
        await using var agent = await IofeSigningAgent.OpenAsync(Options());

        var signed = await agent.SignPdfAsync(TestPdfFactory.CreateMinimalPdf(), Invoice);

        signed.KeySource.ShouldBe(IofeKeySourceKind.RemoteService);
        signed.Level.ShouldBe(AdesBaselineLevel.Basic);
        signed.OperationId.ShouldBe("factura/F001-123");
        signed.PolicyName.ShouldBe($"{IofePolicies.AgentSigning.Name} (firma remota: Proveedor de Pruebas S.A.)");
        _service.HashesSigned.ShouldBe(1);
        agent.Module.ShouldBeNull();
        var service = agent.RemoteService.ShouldNotBeNull();
        service.BaseUri.ShouldBe(FakeRemoteSigningService.BaseUri);
        service.Name.ShouldBe(FakeRemoteSigningService.Name);
        service.CredentialId.ShouldBe(FakeRemoteSigningService.AgentCredential);
        service.AuthMode.ShouldBe("explicit");
        service.Declaration.ShouldBe(FakeRemoteSigningService.Declaration);
        var record = _audit.Events.ShouldHaveSingleItem();
        record.Signed.ShouldBeTrue();
        record.OperationId.ShouldBe("factura/F001-123");
        record.PolicyName.ShouldBe(signed.PolicyName);
        record.CertificateSha256.ShouldBe(signed.SignerCertificateSha256);
        var verification = await VerifyAsync(signed);
        verification.Accepted.ShouldBeTrue(string.Join("; ", verification.Reasons));
    }

    [Fact]
    [Trait("AnnexB", "F-31")]
    public async Task SignCmsAsyncAndSignXmlAsync_KeyInARemoteService_ProduceSignaturesTheVerifierAccepts()
    {
        await using var agent = await IofeSigningAgent.OpenAsync(Options());
        byte[] data = "constancia de pago"u8.ToArray();

        var attached = await agent.SignCmsAsync(data, new IofeTransaction("constancia", "C-1"));
        var detached = await agent.SignCmsAsync(data, new IofeTransaction("constancia", "C-2"), detached: true);
        var xml = await agent.SignXmlAsync("<factura><total>10</total></factura>"u8.ToArray(), Invoice);

        (await VerifyAsync(attached)).Accepted.ShouldBeTrue();
        (await VerifyAsync(detached, data)).Accepted.ShouldBeTrue();
        var xmlVerification = await VerifyAsync(xml);
        xmlVerification.Accepted.ShouldBeTrue(string.Join("; ", xmlVerification.Reasons));
        _service.HashesSigned.ShouldBe(3);
        _audit.Events.Select(e => e.OperationId).ShouldBe(["constancia/C-1", "constancia/C-2", "factura/F001-123"]);
    }

    [Fact]
    [Trait("AnnexB", "F-31")]
    [Trait("AnnexB", "S-1")]
    [Trait("AnnexB", "S-2")]
    [Trait("AnnexB", "S-3")]
    public async Task SignPdfAsync_WithTheTimestampAuthority_ReachesLongTermAndIsAccepted()
    {
        var options = Options() with { Timestamp = new IofeTimestampAuthority(new Uri(IofeTestPki.TsaUrl), _pki.Tsa) };
        await using var agent = await IofeSigningAgent.OpenAsync(options);

        var signed = await agent.SignPdfAsync(TestPdfFactory.CreateMinimalPdf(), Invoice);

        signed.Level.ShouldBe(AdesBaselineLevel.LongTerm);
        signed.Timestamped.ShouldBeTrue();
        (await VerifyAsync(signed)).Accepted.ShouldBeTrue();
    }

    [Fact]
    [Trait("AnnexB", "F-19")]
    public async Task OpenAsync_ServiceThatIsNotTheDeclaredOne_IsRefusedBeforeAnythingIsSentToIt()
    {
        _service.ReportedName = "Otro Servicio";

        var ex = await Should.ThrowAsync<IofeAccreditationException>(() => IofeSigningAgent.OpenAsync(Options()));

        ex.Refusal.ShouldBe(IofeRefusal.RemoteServiceMismatch);
        ex.Message.ShouldContain("Otro Servicio");
        // Neither the client secret nor the PIN went to a service that is not the declared one.
        _service.Requests.ShouldBe(["info"]);
        var record = _audit.Events.ShouldHaveSingleItem();
        record.Signed.ShouldBeFalse();
        record.Message.ShouldNotBeNull().ShouldContain(nameof(IofeRefusal.RemoteServiceMismatch));
    }

    [Fact]
    [Trait("AnnexB", "F-16")]
    public async Task OpenAsync_CredentialAPersonAuthorizes_IsRefusedAndRecorded()
    {
        var ex = await Should.ThrowAsync<IofeAccreditationException>(
            () => IofeSigningAgent.OpenAsync(Options(FakeRemoteSigningService.PersonalCredential)));

        ex.Refusal.ShouldBe(IofeRefusal.RemoteAuthorizationNotUnattended);
        ex.Message.ShouldContain("oauth2code");
        _audit.Events.ShouldHaveSingleItem().Signed.ShouldBeFalse();
        _service.HashesSigned.ShouldBe(0);
    }

    [Fact]
    [Trait("AnnexB", "F-17")]
    public async Task OpenAsync_NoKeySourceOrTwoOrNoDeclaration_IsRefused()
    {
        var none = Options() with { RemoteService = null, RemoteServiceDeclaration = null };
        var two = Options() with
        {
            Module = new() { LibraryPath = "/no/such/driver.so" },
            ModuleDeclaration = new IofeModuleDeclaration("Thales", "Luna K7", "FIPS 140-2 Level 3", "4090"),
        };
        var noDeclaration = Options() with { RemoteServiceDeclaration = null };

        foreach (var options in new[] { none, two, noDeclaration })
        {
            var ex = await Should.ThrowAsync<IofeAccreditationException>(() => IofeSigningAgent.OpenAsync(options));
            ex.Refusal.ShouldBe(IofeRefusal.OptionsIncomplete);
        }

        _service.Requests.ShouldBeEmpty();
    }

    [Fact]
    public async Task OpenAsync_DisabledKeyOrWrongClientSecret_IsNotOpened()
    {
        await Should.ThrowAsync<CloudSigningException>(() => IofeSigningAgent.OpenAsync(Options(FakeRemoteSigningService.DisabledCredential)));

        var wrongSecret = Options() with
        {
            RemoteService = FakeRemoteSigningService.Service() with
            {
                Service = new CscClientOptions
                {
                    BaseUri = FakeRemoteSigningService.BaseUri,
                    ClientId = FakeRemoteSigningService.ClientId,
                    ClientSecret = "otro",
                },
            },
        };
        await Should.ThrowAsync<CloudSigningException>(() => IofeSigningAgent.OpenAsync(wrongSecret));
        _service.HashesSigned.ShouldBe(0);
    }

    [Fact]
    public async Task SignPdfAsync_WrongPin_SignsNothing()
    {
        await using var agent = await IofeSigningAgent.OpenAsync(Options(pin: "0000"));

        var ex = await Should.ThrowAsync<Exception>(() => agent.SignPdfAsync(TestPdfFactory.CreateMinimalPdf(), Invoice));

        // The service's refusal, as it came or inside the signer's own exception.
        Causes(ex).OfType<CloudSigningException>().ShouldNotBeEmpty();
        _service.HashesSigned.ShouldBe(0);
        _audit.Events.ShouldNotContain(e => e.Signed);
    }

    [Fact]
    [Trait("AnnexB", "F-5")]
    [Trait("AnnexB", "F-8")]
    [Trait("AnnexB", "F-15")]
    public async Task SignPdfAsync_RevokedCertificate_IsRefusedBeforeTheServiceIsAskedToSign()
    {
        await using var agent = await IofeSigningAgent.OpenAsync(Options());
        _pki.LeafRevoked = true;

        var ex = await Should.ThrowAsync<SigningException>(() => agent.SignPdfAsync(TestPdfFactory.CreateMinimalPdf(), Invoice));

        ex.Reason.ShouldBe(SigningErrorReason.CertificateRevoked);
        _service.HashesSigned.ShouldBe(0);
        var record = _audit.Events.ShouldHaveSingleItem();
        record.Signed.ShouldBeFalse();
        record.Reason.ShouldBe(SigningErrorReason.CertificateRevoked);
    }

    [Fact]
    [Trait("AnnexB", "F-12")]
    public async Task SignPdfAsync_CertificateWithoutNonRepudiation_IsRefused()
    {
        await using var agent = await IofeSigningAgent.OpenAsync(Options(FakeRemoteSigningService.DigitalSignatureOnlyCredential));

        var ex = await Should.ThrowAsync<SigningException>(() => agent.SignPdfAsync(TestPdfFactory.CreateMinimalPdf(), Invoice));

        ex.Reason.ShouldBe(SigningErrorReason.KeyUsageNotPermitted);
        _service.HashesSigned.ShouldBe(0);
    }

    [Fact]
    [Trait("AnnexB", "F-8")]
    [Trait("AnnexB", "F-14")]
    public async Task SignPdfAsync_RevocationUnavailable_IsRefusedUnlessAContingencyIsInForce()
    {
        var now = DateTimeOffset.UtcNow;
        var contingency = new IofeContingency("PROC-AAC-07", now.AddHours(-1), now.AddHours(1));
        _pki.CrlsDown = true;

        await using (var strict = await IofeSigningAgent.OpenAsync(Options()))
        {
            await Should.ThrowAsync<SigningException>(() => strict.SignPdfAsync(TestPdfFactory.CreateMinimalPdf(), Invoice));
        }

        await using var agent = await IofeSigningAgent.OpenAsync(Options() with { Contingency = contingency });
        var signed = await agent.SignPdfAsync(TestPdfFactory.CreateMinimalPdf(), Invoice);

        signed.UnderContingency.ShouldBeTrue();
        signed.PolicyName.ShouldContain("firma remota: Proveedor de Pruebas S.A.");
        signed.PolicyName.ShouldContain("PROC-AAC-07");
    }

    [Fact]
    [Trait("AnnexB", "F-16")]
    public async Task SignPdfAsync_TransactionOutsideTheAgents_IsRefusedAndRecorded()
    {
        await using var agent = await IofeSigningAgent.OpenAsync(Options());

        var ex = await Should.ThrowAsync<IofeAccreditationException>(
            () => agent.SignPdfAsync(TestPdfFactory.CreateMinimalPdf(), new IofeTransaction("contrato", "X-9")));

        ex.Refusal.ShouldBe(IofeRefusal.TransactionNotAllowed);
        _service.HashesSigned.ShouldBe(0);
        var record = _audit.Events.ShouldHaveSingleItem();
        record.Signed.ShouldBeFalse();
        record.OperationId.ShouldBe("contrato/X-9");
    }

    [Fact]
    public async Task SignPdfAsync_ServiceTokenExpired_IsRenewedWithTheClientCredentials()
    {
        var clock = new ManualClock(DateTimeOffset.UtcNow);
        await using var agent = await IofeSigningAgent.OpenAsync(Options() with { TimeProvider = clock });
        await agent.SignPdfAsync(TestPdfFactory.CreateMinimalPdf(), Invoice);
        _service.TokensIssued.ShouldBe(1);

        clock.Now += TimeSpan.FromSeconds(_service.TokenLifetimeSeconds + 60);
        var signed = await agent.SignPdfAsync(TestPdfFactory.CreateMinimalPdf(), new IofeTransaction("factura", "F001-124"));

        _service.TokensIssued.ShouldBe(2);
        _service.HashesSigned.ShouldBe(2);
        signed.OperationId.ShouldBe("factura/F001-124");
    }

    private static IEnumerable<Exception> Causes(Exception? exception)
    {
        for (; exception is not null; exception = exception.InnerException)
        {
            yield return exception;
        }
    }

    [Fact]
    public void RemoteService_ToString_ShowsNeitherThePinNorTheSecret()
    {
        string text = FakeRemoteSigningService.Service().ToString();

        text.ShouldContain(FakeRemoteSigningService.BaseUri.AbsoluteUri);
        text.ShouldContain(FakeRemoteSigningService.AgentCredential);
        text.ShouldNotContain(FakeRemoteSigningService.Pin);
        text.ShouldNotContain(FakeRemoteSigningService.ClientSecret);
    }

    [Theory]
    [InlineData("Firma Remota de Pruebas", true)]
    [InlineData("  firma remota de pruebas ", true)]
    [InlineData("Firma Remota", false)]
    [InlineData("", false)]
    [InlineData(null, false)]
    public void Declaration_Matches_OnlyTheServiceThatReportsTheDeclaredName(string? reported, bool expected) =>
        FakeRemoteSigningService.Declaration.Matches(new CscInfo(reported, "2.0.0.2", [], [])).ShouldBe(expected);
}

/// <summary>The test PKI and the remote signing service on it, made once for the class: its keys take seconds to generate.</summary>
public sealed class IofeRemoteServiceFixture : IDisposable
{
    public IofeRemoteServiceFixture()
    {
        Pki = new IofeTestPki();
        Service = new FakeRemoteSigningService(Pki);
        Pki.RemoteService = Service.AnswerAsync;
    }

    internal IofeTestPki Pki { get; }

    internal FakeRemoteSigningService Service { get; }

    public void Dispose()
    {
        Service.Dispose();
        Pki.Dispose();
    }
}
