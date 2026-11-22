using System.Formats.Asn1;
using Shouldly;
using SimpleSign.Core.Constants;
using SimpleSign.Core.Crypto;
using SimpleSign.Core.Validation.Policy;
using Xunit;

namespace SimpleSign.Core.Tests.Crypto;

/// <summary>The signed attributes <see cref="CmsAttribute"/> creates: here signer-attributes-v2 (ETSI EN 319 122-1 §5.2.6.1).</summary>
[Trait("Category", "Unit")]
public sealed class CmsAttributeTests
{
    [Fact]
    public void SignerAttributesV2_OneRole_IsARoleAttributeInClaimedAttributesUnderAnExplicitTag0()
    {
        var attribute = CmsAttribute.SignerAttributesV2(["A"]);

        // SEQUENCE { [0] EXPLICIT { SEQUENCE OF { SEQUENCE { OID id-at-role, SET { UTF8String "A" } } } } }
        attribute.Oid.ShouldBe(Oids.SignerAttributesV2);
        attribute.DerValue.ShouldBe(
        [
            0x30, 0x10, 0xA0, 0x0E, 0x30, 0x0C, 0x30, 0x0A,
            0x06, 0x03, 0x55, 0x04, 0x48, 0x31, 0x03, 0x0C, 0x01, 0x41,
        ]);
    }

    [Fact]
    public void SignerAttributesV2_AttributeCertificate_GoesInCertifiedAttributesUnderTag0()
    {
        byte[] attributeCertificate = [0x30, 0x03, 0x04, 0x01, 0xAA];

        var attribute = CmsAttribute.SignerAttributesV2([], [attributeCertificate]);

        // SEQUENCE { [1] EXPLICIT { SEQUENCE OF { [0] EXPLICIT { AttributeCertificate } } } }
        attribute.DerValue.ShouldBe([0x30, 0x0B, 0xA1, 0x09, 0x30, 0x07, 0xA0, 0x05, 0x30, 0x03, 0x04, 0x01, 0xAA]);
    }

    [Fact]
    public void SignerAttributesV2_SignedAssertionWithoutValue_IsItsOidAlone()
    {
        var attribute = CmsAttribute.SignerAttributesV2([], signedAssertions: [("1.2.3", ReadOnlyMemory<byte>.Empty)]);

        // SEQUENCE { [2] EXPLICIT { SEQUENCE OF { SEQUENCE { OID 1.2.3 } } } }
        attribute.DerValue.ShouldBe([0x30, 0x0A, 0xA2, 0x08, 0x30, 0x06, 0x30, 0x04, 0x06, 0x02, 0x2A, 0x03]);
    }

    [Fact]
    public void SignerAttributesV2_SeveralRoles_AreReadBackInOrder()
    {
        var attribute = CmsAttribute.SignerAttributesV2(["Diretor", "Testemunha"]);

        var facts = SignedAttributeFacts.FromCms(SignedAttributesWith(attribute));

        facts.ShouldNotBeNull().ClaimedRoles.ShouldBe(["Diretor", "Testemunha"]);
    }

    [Fact]
    public void SignerAttributesV2_NothingToWrite_Throws() =>
        Should.Throw<ArgumentException>(() => CmsAttribute.SignerAttributesV2([]));

    [Fact]
    public void SignerAttributesV2_BlankRole_Throws() =>
        Should.Throw<ArgumentException>(() => CmsAttribute.SignerAttributesV2(["Diretor", " "]));

    /// <summary>The DER SET OF Attribute that holds <paramref name="attribute"/> alone, as a SignerInfo's signedAttrs.</summary>
    private static byte[] SignedAttributesWith(CmsAttribute attribute)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSetOf())
        using (writer.PushSequence())
        {
            writer.WriteObjectIdentifier(attribute.Oid);
            using (writer.PushSetOf())
            {
                writer.WriteEncodedValue(attribute.DerValue);
            }
        }

        return writer.Encode();
    }
}
