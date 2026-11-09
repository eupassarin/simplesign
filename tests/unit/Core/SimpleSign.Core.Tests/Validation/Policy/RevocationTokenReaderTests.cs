using Shouldly;
using SimpleSign.Core.Validation.Policy;
using SimpleSign.TestHelpers;
using Xunit;

namespace SimpleSign.Core.Tests.Validation.Policy;

[Trait("Category", "Unit")]
public sealed class RevocationTokenReaderTests : IDisposable
{
    private readonly SyntheticPki _pki = new();

    [Fact]
    public void Read_LeafCrl_GivesGoodWithItsDates()
    {
        var thisUpdate = DateTimeOffset.UtcNow.AddHours(-2);
        var nextUpdate = DateTimeOffset.UtcNow.AddDays(1);

        var token = RevocationTokenReader.Read(_pki.Chain(), [_pki.BuildLeafCrl(thisUpdate, nextUpdate)], []).ShouldHaveSingleItem();

        token.Kind.ShouldBe(RevocationTokenKind.Crl);
        token.Status.ShouldBe(RevocationTokenStatus.Good);
        token.SignatureValid.ShouldBeTrue();
        token.ThisUpdate!.Value.ShouldBe(thisUpdate, TimeSpan.FromSeconds(1));
        token.NextUpdate!.Value.ShouldBe(nextUpdate, TimeSpan.FromSeconds(1));
        token.Issuer.ShouldBe(_pki.IntermediateCa);
    }

    [Fact]
    public void Read_RevokingCrl_GivesRevokedWithTheTime()
    {
        var token = RevocationTokenReader.Read(_pki.Chain(), [_pki.BuildRevokedLeafCrl()], []).ShouldHaveSingleItem();

        token.Status.ShouldBe(RevocationTokenStatus.Revoked);
        token.RevocationTime.ShouldNotBeNull();
    }

    [Fact]
    public void Read_CrlOfTheRoot_IsAboutTheIntermediate()
    {
        var token = RevocationTokenReader.Read(_pki.Chain(), [_pki.BuildIntermediateCrl()], []).ShouldHaveSingleItem();

        token.Certificate.ShouldBe(_pki.IntermediateCa);
    }

    [Fact]
    public void Read_Garbage_IsIgnored() => RevocationTokenReader.Read(_pki.Chain(), [[1, 2, 3]], [[4, 5, 6]]).ShouldBeEmpty();

    public void Dispose() => _pki.Dispose();
}
