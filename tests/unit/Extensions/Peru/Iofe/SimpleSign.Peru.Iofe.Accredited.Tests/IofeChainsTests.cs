using Shouldly;
using SimpleSign.Peru.Iofe.Accredited.Internal;
using SimpleSign.TestHelpers;

namespace SimpleSign.Peru.Iofe.Accredited.Tests;

[Trait("Category", "Unit")]
public sealed class IofeChainsTests : IDisposable
{
    private readonly SyntheticPki _pki = new();

    public void Dispose() => _pki.Dispose();

    [Fact]
    public void Complete_ModuleHoldsTheIntermediateOnly_AddsTheRootFromTheTrust()
    {
        var chain = IofeChains.Complete(_pki.Leaf, [_pki.IntermediateCa], [new InMemoryTrustAnchors(_pki.RootCa)]);

        chain.Select(c => c.Thumbprint).ShouldBe([_pki.IntermediateCa.Thumbprint, _pki.RootCa.Thumbprint]);
    }

    [Fact]
    public void Complete_RootOfAnotherPkiWithTheSameNames_IsNotTakenForTheIssuer()
    {
        // Every SyntheticPki names its CAs alike; the key identifiers tell them apart.
        using var other = new SyntheticPki();

        var chain = IofeChains.Complete(_pki.Leaf, [_pki.IntermediateCa], [new InMemoryTrustAnchors(other.RootCa)]);

        chain.Select(c => c.Thumbprint).ShouldBe([_pki.IntermediateCa.Thumbprint]);
    }

    [Fact]
    public void Complete_NoIssuerKnown_IsEmpty() =>
        IofeChains.Complete(_pki.Leaf, [], [new InMemoryTrustAnchors(_pki.RootCa)]).ShouldBeEmpty();
}
