using System.Security.Cryptography.X509Certificates;
using Shouldly;
using SimpleSign.Core.Extensions;
using SimpleSign.Core.Policies;
using SimpleSign.Core.Validation;
using SimpleSign.TestHelpers;
using Xunit;

namespace SimpleSign.Core.Tests.Validation;

[Trait("Category", "Unit")]
public sealed class ConstrainedTrustTests : IDisposable
{
    private readonly SyntheticPki _pki = new();

    public void Dispose() => _pki.Dispose();

    [Fact]
    public void Refusal_NoProviderGivesAnAnchorOfTheChain_Null()
    {
        using var other = new SyntheticPki();

        ConstrainedTrust.Refusal(_pki.Chain(), [ConstrainedTrustAnchors.Refusing("no", other.RootCa)]).ShouldBeNull();
    }

    [Fact]
    public void Refusal_AnchorRefuses_GivesItsReasonAndTheChainUpToTheAnchor()
    {
        X509Certificate2? asked = null;
        IReadOnlyList<X509Certificate2>? path = null;
        var provider = new ConstrainedTrustAnchors((anchor, chain) =>
        {
            (asked, path) = (anchor, chain);
            return "the signer's certificate has none of the policies";
        }, _pki.RootCa);

        ConstrainedTrust.Refusal(_pki.Chain(), [provider]).ShouldBe("the signer's certificate has none of the policies");

        asked.ShouldBe(_pki.RootCa);
        path.ShouldBe(_pki.Chain());
    }

    [Fact]
    public void Refusal_TwoAnchorsInTheChain_TheOneNearestToTheSignerDecides()
    {
        var nearest = ConstrainedTrustAnchors.Accepting(_pki.IntermediateCa);
        var root = ConstrainedTrustAnchors.Refusing("root says no", _pki.RootCa);

        ConstrainedTrust.Refusal(_pki.Chain(), [root, nearest]).ShouldBeNull();
        ConstrainedTrust.Refusal(_pki.Chain(), [ConstrainedTrustAnchors.Refusing("intermediate says no", _pki.IntermediateCa), ConstrainedTrustAnchors.Accepting(_pki.RootCa)])
            .ShouldBe("intermediate says no");
    }

    [Fact]
    public void Refusal_TwoProvidersGiveTheAnchor_OneThatAcceptsIsEnough()
    {
        var refusing = ConstrainedTrustAnchors.Refusing("no", _pki.RootCa);
        var accepting = ConstrainedTrustAnchors.Accepting(_pki.RootCa);

        ConstrainedTrust.Refusal(_pki.Chain(), [refusing, accepting]).ShouldBeNull();
        ConstrainedTrust.Refusal(_pki.Chain(), [refusing, refusing]).ShouldBe("no");
    }

    [Fact]
    public void From_AnchorAlsoGivenWithoutConditions_IsNotRefused()
    {
        var refusing = ConstrainedTrustAnchors.Refusing("no", _pki.RootCa);

        ConstrainedTrust.Refusal(_pki.Chain(), ConstrainedTrust.From([refusing])).ShouldBe("no");
        ConstrainedTrust.Refusal(_pki.Chain(), ConstrainedTrust.From([refusing, new InMemoryTrustAnchors(_pki.RootCa)])).ShouldBeNull();
        ConstrainedTrust.From([new InMemoryTrustAnchors(_pki.RootCa)]).ShouldBeEmpty();
    }

    [Fact]
    public void TrustProfile_WithTrustFromAProfileThatGivesTheAnchorPlainly_AcceptsTheChain()
    {
        var constrained = new TrustProfile("a", "A", SigningPolicy.Default, ValidationPolicy.Default, [ConstrainedTrustAnchors.Refusing("no", _pki.RootCa)], []);
        var plain = new TrustProfile("b", "B", SigningPolicy.Default, ValidationPolicy.Default, [new InMemoryTrustAnchors(_pki.RootCa)], []);

        ConstrainedTrust.Refusal(_pki.Chain(), constrained.ConstrainedTrustAnchors).ShouldBe("no");
        ConstrainedTrust.Refusal(_pki.Chain(), constrained.WithTrustFrom(plain).ConstrainedTrustAnchors).ShouldBeNull();
        ConstrainedTrust.Refusal(_pki.Chain(), plain.WithTrustFrom(constrained).ConstrainedTrustAnchors).ShouldBeNull();
        plain.ConstrainedTrustAnchors.ShouldBeEmpty();
    }
}
