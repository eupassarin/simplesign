using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json.Nodes;
using Shouldly;
using SimpleSign.Sandbox.Pki;

namespace SimpleSign.Sandbox.Tests;

/// <summary>The certificates of an environment show the problem they are for.</summary>
[Trait("Category", "Unit")]
public sealed class SandboxPkiTests : IDisposable
{
    private const string Sha1WithRsa = "1.2.840.113549.1.1.5";

    private const string KeyUsageOid = "2.5.29.15";

    private readonly string _directory = Path.Combine(Path.GetTempPath(), "simplesign-sandbox-pki-tests-" + Guid.NewGuid().ToString("N")[..8]);

    private static SandboxOptions Options => new() { Name = "lab", PublicBaseUrl = new Uri("http://localhost:5300/") };

    public void Dispose()
    {
        if (Directory.Exists(_directory))
        {
            Directory.Delete(_directory, recursive: true);
        }
    }

    [Fact]
    public void Certificate_ExpiredTsa_HasExpiredAndIsForTimestamping()
    {
        using var pki = SandboxPki.Open(null, Options);

        var tsa = pki.Certificate("tsa-expired");

        tsa.Problem.ShouldBe("Expired");
        tsa.Usage.ShouldBe(CertificateUsage.Timestamping);
        tsa.Certificate.NotAfter.ShouldBeLessThan(DateTime.Now);
        tsa.Certificate.Extensions.OfType<X509EnhancedKeyUsageExtension>().Single().EnhancedKeyUsages
            .Cast<Oid>().ShouldContain(o => o.Value == "1.3.6.1.5.5.7.3.8");
        tsa.IsUsable.ShouldBeFalse();
    }

    [Fact]
    public void Certificate_UnderSha1Ca_ItsIssuerIsSignedWithSha1ByTheRoot()
    {
        using var pki = SandboxPki.Open(null, Options);

        var leaf = pki.Certificate("under-sha1-ca");
        var ca = pki.Authority(SandboxPki.Sha1IntermediateId);

        leaf.IssuerId.ShouldBe(SandboxPki.Sha1IntermediateId);
        leaf.Problem.ShouldBe("Issuer signed with SHA-1");
        leaf.Certificate.Issuer.ShouldBe(ca.Certificate.Subject);
        leaf.Certificate.SignatureAlgorithm.Value.ShouldNotBe(Sha1WithRsa);
        ca.Problem.ShouldBe("Signed with SHA-1");
        ca.IssuerId.ShouldBe(SandboxPki.RootId);
        ca.Certificate.SignatureAlgorithm.Value.ShouldBe(Sha1WithRsa);
        ca.Certificate.NotAfter.ShouldBeGreaterThan(DateTime.Now);
        pki.ChainOf("under-sha1-ca").Select(c => c.Thumbprint).ShouldBe([ca.Certificate.Thumbprint, pki.Root.Thumbprint]);
    }

    [Fact]
    public void Certificate_NoKeyUsageExtension_HasNoKeyUsageAtAll()
    {
        using var pki = SandboxPki.Open(null, Options);

        var certificate = pki.Certificate("no-key-usage-extension");

        certificate.Problem.ShouldBe("No key usage extension");
        certificate.Certificate.Extensions.ShouldNotContain(e => e.Oid!.Value == KeyUsageOid);
        pki.Certificate("no-signing-key-usage").Certificate.Extensions.OfType<X509KeyUsageExtension>().Single().KeyUsages
            .ShouldBe(X509KeyUsageFlags.KeyEncipherment);
    }

    [Fact]
    public void Open_SameFolder_KeepsTheNewCertificates()
    {
        string sha1Ca, underSha1, tsaExpired, noKeyUsage;
        using (var pki = SandboxPki.Open(_directory, Options))
        {
            sha1Ca = pki.Authority(SandboxPki.Sha1IntermediateId).Certificate.Thumbprint;
            underSha1 = pki.Certificate("under-sha1-ca").Certificate.Thumbprint;
            tsaExpired = pki.Certificate("tsa-expired").Certificate.Thumbprint;
            noKeyUsage = pki.Certificate("no-key-usage-extension").Certificate.Thumbprint;
        }

        using var again = SandboxPki.Open(_directory, Options);

        again.Authority(SandboxPki.Sha1IntermediateId).Certificate.Thumbprint.ShouldBe(sha1Ca);
        again.Certificate("under-sha1-ca").Certificate.Thumbprint.ShouldBe(underSha1);
        again.Certificate("tsa-expired").Certificate.Thumbprint.ShouldBe(tsaExpired);
        again.Certificate("no-key-usage-extension").Certificate.Thumbprint.ShouldBe(noKeyUsage);
    }

    [Fact]
    public void Open_EnvironmentWithoutTheSha1Ca_AddsItAndKeepsTheRoot()
    {
        string root, rsa2048;
        using (var pki = SandboxPki.Open(_directory, Options))
        {
            root = pki.Root.Thumbprint;
            rsa2048 = pki.Certificate("rsa-2048").Certificate.Thumbprint;
        }

        // An environment written before the SHA-1 CA existed.
        string path = Path.Combine(_directory, "state.json");
        var state = JsonNode.Parse(File.ReadAllText(path))!.AsObject();
        var authorities = state["authorities"]!.AsArray();
        authorities.Remove(authorities.Single(a => (string?)a!["id"] == SandboxPki.Sha1IntermediateId));
        var certificates = state["certificates"]!.AsArray();
        certificates.Remove(certificates.Single(c => (string?)c!["id"] == "under-sha1-ca"));
        File.WriteAllText(path, state.ToJsonString());

        using var again = SandboxPki.Open(_directory, Options);

        again.Root.Thumbprint.ShouldBe(root);
        again.Certificate("rsa-2048").Certificate.Thumbprint.ShouldBe(rsa2048);
        again.Authority(SandboxPki.Sha1IntermediateId).Certificate.SignatureAlgorithm.Value.ShouldBe(Sha1WithRsa);
        again.Certificate("under-sha1-ca").IssuerId.ShouldBe(SandboxPki.Sha1IntermediateId);
    }
}
