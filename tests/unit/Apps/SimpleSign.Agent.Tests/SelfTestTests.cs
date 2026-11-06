using System.Security.Cryptography.X509Certificates;
using Shouldly;
using SimpleSign.Agent.Server;
using SimpleSign.Agent.Services;

namespace SimpleSign.Agent.Tests;

[Trait("Category", "Unit")]
public sealed class SelfTestTests : IAsyncLifetime
{
    private readonly FakeDialogs _dialogs = new();
    private readonly X509Certificate2 _rsa = Fixtures.RsaCertificate();
    private readonly X509Certificate2 _ecdsa = Fixtures.EcdsaCertificate();
    private AgentController _controller = null!;
    private SelfTest _test = null!;

    public async Task InitializeAsync()
    {
        var services = Fixtures.Services(_dialogs);
        services.Settings.Current.AgentPort = Fixtures.FreePort();
        IReadOnlyList<CertificateEntry> entries = [new(CertificateSourceKind.Store, _rsa), new(CertificateSourceKind.Store, _ecdsa)];
        _controller = new AgentController(services, _ => Task.FromResult(entries));
        await _controller.StartAsync();
        _test = new SelfTest(_controller.Server.Port);
    }

    public async Task DisposeAsync()
    {
        _test.Dispose();
        await _controller.DisposeAsync();
        _rsa.Dispose();
        _ecdsa.Dispose();
    }

    [Fact]
    public async Task Health_AgentRunning_Ok()
    {
        var step = await _test.HealthAsync(CancellationToken.None);

        step.Ok.ShouldBeTrue();
        step.Status.ShouldBe(200);
        step.ResponseBody.ShouldContain("SimpleSign Agent");
        _dialogs.Asked.ShouldBeEmpty();
    }

    [Fact]
    public async Task WholeFlow_RsaAndEcdsa_SignaturesVerify()
    {
        var (list, certificates) = await _test.CertificatesAsync(CancellationToken.None);
        list.Ok.ShouldBeTrue();
        certificates.Count.ShouldBe(2);

        foreach (var certificate in certificates)
        {
            var signature = await _test.SignAsync(certificate, CancellationToken.None);

            signature.Step.Ok.ShouldBeTrue(signature.Step.Error);
            signature.Verified.ShouldBeTrue(certificate.SignatureAlgorithm);
            signature.SignatureBytes.ShouldBeGreaterThan(0);
        }

        _controller.Services.Signatures.ShouldBe(2);
    }

    [Fact]
    public async Task Sign_UserRefuses_ReportsTheRefusal()
    {
        var (_, certificates) = await _test.CertificatesAsync(CancellationToken.None);
        _dialogs.Signature = ConsentDecision.Deny;

        var signature = await _test.SignAsync(certificates[0], CancellationToken.None);

        signature.Step.Ok.ShouldBeFalse();
        signature.Step.Status.ShouldBe(403);
        signature.Step.Error.ShouldNotBeNullOrEmpty();
        signature.Verified.ShouldBeFalse();
    }

    [Fact]
    public async Task Certificates_UserDeniesAccess_NotOk()
    {
        _dialogs.Site = ConsentDecision.Deny;

        var (step, certificates) = await _test.CertificatesAsync(CancellationToken.None);

        step.Ok.ShouldBeFalse();
        step.Status.ShouldBe(403);
        certificates.ShouldBeEmpty();
    }

    [Fact]
    public async Task Health_AgentStopped_FailsWithoutThrowing()
    {
        await _controller.SetEnabledAsync(false);

        var step = await _test.HealthAsync(CancellationToken.None);

        step.Ok.ShouldBeFalse();
        step.Status.ShouldBe(0);
        step.Error.ShouldNotBeNullOrEmpty();
    }

    [Fact]
    public void Verify_SignatureOfOtherData_False()
    {
        using var key = _rsa.GetRSAPrivateKey()!;
        byte[] other = key.SignData([1, 2, 3], System.Security.Cryptography.HashAlgorithmName.SHA256, System.Security.Cryptography.RSASignaturePadding.Pkcs1);
        var certificate = new AgentCertificate { UserCertificateBase64 = Convert.ToBase64String(_rsa.RawData) };

        SelfTest.Verify(certificate, other).ShouldBeFalse();
    }

    [Fact]
    public void Pretty_IndentsAndShortensLongValues()
    {
        string pretty = SelfTest.Pretty($$"""[{"id":"1","signedHashBase64":"{{new string('A', 200)}}"}]""");

        pretty.ShouldContain("\"id\": \"1\"");
        pretty.ShouldContain("… (200)");
        pretty.ShouldNotContain(new string('A', 100));
        SelfTest.Pretty("not json").ShouldBe("not json");
    }
}
