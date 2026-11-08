using System.Formats.Asn1;
using Shouldly;
using SimpleSign.Core.Revocation;
using SimpleSign.Core.Validation;
using SimpleSign.TestHelpers;
using Xunit;

namespace SimpleSign.Core.Tests.Validation;

[Trait("Category", "Unit")]
public sealed class EmbeddedRevocationValuesTests
{
    [Fact]
    public void Read_RevocationValuesWithCrls_GivesTheCrls()
    {
        using var pki = new SyntheticPki();
        byte[] leafCrl = pki.BuildLeafCrl();
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
        using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true)))
        {
            writer.WriteEncodedValue(leafCrl);
            writer.WriteEncodedValue(pki.BuildIntermediateCrl());
        }

        var (crls, ocsps) = EmbeddedRevocationValues.Read([writer.Encode()]);

        crls.Count.ShouldBe(2);
        crls[0].ShouldBe(leafCrl);
        ocsps.ShouldBeEmpty();
        CrlEvaluator.ReadThisUpdate(crls[0]).ShouldNotBeNull();
    }

    [Fact]
    public void Read_Unreadable_GivesNothing()
    {
        var (crls, ocsps) = EmbeddedRevocationValues.Read([[0x01, 0x02]]);

        crls.ShouldBeEmpty();
        ocsps.ShouldBeEmpty();
    }

    [Fact]
    public void WrapBasicResponse_GivesASuccessfulOcspResponse()
    {
        byte[] basic = [0x30, 0x00];

        var response = new AsnReader(EmbeddedRevocationValues.WrapBasicResponse(basic), AsnEncodingRules.DER).ReadSequence();
        response.ReadEnumeratedBytes().ToArray().ShouldBe([0x00]);
        var bytes = response.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0)).ReadSequence();
        bytes.ReadObjectIdentifier().ShouldBe("1.3.6.1.5.5.7.48.1.1");
        bytes.ReadOctetString().ShouldBe(basic);
    }
}
