using System.Security.Cryptography.X509Certificates;
using Shouldly;
using SimpleSign.TestHelpers;
using Xunit;

namespace SimpleSign.Core.Tests.TestHelpers;

[Trait("Category", "Unit")]
public sealed class SyntheticPkiTests
{
    [Fact(DisplayName = "SyntheticPki produces a 3-tier chain that the .NET X509Chain trusts when root is added")]
    public void Chain_BuildsValidUnderCustomRoot()
    {
        using var pki = new SyntheticPki();

        using var chain = new X509Chain();
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.Add(pki.RootCa);
        chain.ChainPolicy.ExtraStore.Add(pki.IntermediateCa);

        bool ok = chain.Build(pki.Leaf);

        ok.ShouldBeTrue($"chain build failed: [{string.Join(" | ", chain.ChainStatus.Select(s => s.StatusInformation.Trim()))}]");
        chain.ChainElements.Count().ShouldBe(3, "Leaf → Intermediate → Root");
    }

    [Fact(DisplayName = "Leaf has private key")]
    public void Leaf_HasPrivateKey()
    {
        using var pki = new SyntheticPki();
        pki.Leaf.HasPrivateKey.ShouldBeTrue();
    }

    [Fact(DisplayName = "CrlDistributionPoint and OcspResponder extensions are embedded when configured")]
    public void Aia_AndCdp_AreEmbedded()
    {
        using var pki = new SyntheticPki(
            crlDistributionPoint: "http://localhost:1/synthetic.crl",
            ocspResponder: "http://localhost:2/ocsp");

        pki.Leaf.Extensions.ShouldContain(e => e.Oid != null && e.Oid.Value == "2.5.29.31", "CRL Distribution Points");
        pki.Leaf.Extensions.ShouldContain(e => e.Oid != null && e.Oid.Value == "1.3.6.1.5.5.7.1.1", "Authority Information Access");
    }
}
