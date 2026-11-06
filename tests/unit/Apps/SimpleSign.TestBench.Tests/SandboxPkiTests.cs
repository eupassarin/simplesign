using Shouldly;
using SimpleSign.TestBench.Sandbox;

namespace SimpleSign.TestBench.Tests;

/// <summary>The sandbox root is kept between runs when a store is given, so an external validator can keep trusting it.</summary>
[Trait("Category", "Unit")]
public sealed class SandboxPkiTests : IDisposable
{
    private readonly string _directory = Path.Combine(Path.GetTempPath(), "simplesign-testbench-" + Guid.NewGuid().ToString("N"));

    public void Dispose()
    {
        if (Directory.Exists(_directory))
        {
            Directory.Delete(_directory, recursive: true);
        }
    }

    [Fact]
    public void Constructor_WithRootStore_KeepsTheSameRootAndStillIssuesValidChains()
    {
        string store = Path.Combine(_directory, "sandbox-root.pem");
        string thumbprint;
        using (var first = new SandboxPki(store))
        {
            thumbprint = first.Root.Thumbprint;
        }

        using var second = new SandboxPki(store);

        File.Exists(store).ShouldBeTrue();
        second.Root.Thumbprint.ShouldBe(thumbprint);
        // The new intermediate is signed by the stored root's key.
        using var chain = new System.Security.Cryptography.X509Certificates.X509Chain();
        chain.ChainPolicy.TrustMode = System.Security.Cryptography.X509Certificates.X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.Add(second.Root);
        chain.ChainPolicy.RevocationMode = System.Security.Cryptography.X509Certificates.X509RevocationMode.NoCheck;
        chain.Build(second.Intermediate).ShouldBeTrue(string.Join("; ", chain.ChainStatus.Select(s => s.StatusInformation)));
    }

    [Fact]
    public void Constructor_WithoutRootStore_MakesANewRootEachTime()
    {
        using var first = new SandboxPki();
        using var second = new SandboxPki();

        second.Root.Thumbprint.ShouldNotBe(first.Root.Thumbprint);
    }

    [Fact]
    public void Constructor_UnreadableRootStore_FallsBackToANewRootAndRewritesIt()
    {
        Directory.CreateDirectory(_directory);
        string store = Path.Combine(_directory, "sandbox-root.pem");
        File.WriteAllText(store, "not a certificate");

        using var pki = new SandboxPki(store);

        pki.Root.Subject.ShouldContain("AC Raiz Sandbox SimpleSign");
        File.ReadAllText(store).ShouldContain("BEGIN CERTIFICATE");
    }
}
