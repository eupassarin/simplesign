using Shouldly;
using SimpleSign.Sandbox.Pki;
using SimpleSign.Sandbox.Services;

namespace SimpleSign.Sandbox.Tests;

/// <summary>An environment is kept in its folder: the same root, revocations and failures on the next start.</summary>
[Trait("Category", "Unit")]
public sealed class SandboxEnvironmentTests : IDisposable
{
    private readonly string _directory = Path.Combine(Path.GetTempPath(), "simplesign-sandbox-tests-" + Guid.NewGuid().ToString("N")[..8]);

    private static SandboxOptions Options(string name, string url) => new() { Name = name, PublicBaseUrl = new Uri(url) };

    public void Dispose()
    {
        if (Directory.Exists(_directory))
        {
            Directory.Delete(_directory, recursive: true);
        }
    }

    [Fact]
    public void Open_SameFolder_KeepsRootRevocationsFaultsAndUrl()
    {
        string thumbprint;
        using (var pki = SandboxPki.Open(_directory, Options("lab", "http://lab.example:5300/")))
        {
            thumbprint = pki.Root.Thumbprint;
            pki.Revoke("rsa-3072", "Superseded");
            pki.Faults = new SandboxFaults(Tsa: TsaFault.Slow, TsaDelayMs: 90_000);
        }

        using var again = SandboxPki.Open(_directory, Options("lab", "http://elsewhere:9999/"));

        again.Root.Thumbprint.ShouldBe(thumbprint);
        again.BaseUrl.ShouldBe(new Uri("http://lab.example:5300/"));
        again.Certificate("rsa-3072").RevocationReason.ShouldBe("Superseded");
        again.Faults.Tsa.ShouldBe(TsaFault.Slow);
        again.Faults.TsaDelayMs.ShouldBe(60_000);
        File.Exists(Path.Combine(_directory, "state.json")).ShouldBeTrue();
    }

    [Fact]
    public void Reset_PutsBackTheInitialRevocationsAndFaults()
    {
        using var pki = SandboxPki.Open(null, Options("lab", "http://localhost:5300/"));
        pki.Revoke("rsa-2048");
        pki.Unrevoke("revoked");
        pki.Faults = new SandboxFaults(Crl: CrlFault.Down);

        pki.Reset();

        pki.Certificate("rsa-2048").RevokedAt.ShouldBeNull();
        pki.Certificate("revoked").RevokedAt.ShouldNotBeNull();
        pki.Faults.Any.ShouldBeFalse();
    }

    [Fact]
    public void Certificates_PointToTheEnvironmentUrl()
    {
        using var pki = SandboxPki.Open(null, Options("lab", "http://lab.example:5300/"));

        var leaf = pki.Certificate("rsa-2048").Certificate;
        var distribution = leaf.Extensions.OfType<System.Security.Cryptography.X509Certificates.X509Extension>()
            .Single(e => e.Oid?.Value == "2.5.29.31");
        System.Text.Encoding.ASCII.GetString(distribution.RawData).ShouldContain("http://lab.example:5300/crl/intermediate.crl");
        pki.Certificate("revoked-crl-https").Certificate.Extensions.Single(e => e.Oid?.Value == "2.5.29.31").RawData.AsSpan().IndexOf("https://lab.example:5301/crl/intermediate.crl"u8).ShouldBeGreaterThan(0);
        pki.Certificate("revoked-crl-ldap").Certificate.Extensions.Single(e => e.Oid?.Value == "2.5.29.31").RawData.AsSpan().IndexOf("ldap://lab.example:5302/cn=intermediate,o=sandbox"u8).ShouldBeGreaterThan(0);
        leaf.HasPrivateKey.ShouldBeTrue();
    }

    [Theory]
    [InlineData(new[] { "--port", "5400", "--name", "lab2", "--ephemeral", "--no-browser" }, 5400, "lab2", true)]
    [InlineData(new string[0], 5300, "default", false)]
    public void Parse_CommandLine_ReadsTheOptions(string[] args, int port, string name, bool ephemeral)
    {
        var options = SandboxOptions.Parse(args);

        options.Port.ShouldBe(port);
        options.Name.ShouldBe(name);
        options.Ephemeral.ShouldBe(ephemeral);
        options.BaseUrl.ShouldBe(new Uri($"http://localhost:{port}/"));
    }

    [Fact]
    public void Parse_PublicBaseUrl_EndsWithASlash() =>
        SandboxOptions.Parse(["--public-base-url", "http://sandbox.lab:8080"]).BaseUrl.ShouldBe(new Uri("http://sandbox.lab:8080/"));
}
