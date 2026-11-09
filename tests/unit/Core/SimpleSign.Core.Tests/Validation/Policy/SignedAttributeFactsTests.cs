using System.Formats.Asn1;
using System.Security.Cryptography;
using Shouldly;
using SimpleSign.Core.Validation.Policy;
using SimpleSign.TestHelpers;
using Xunit;

namespace SimpleSign.Core.Tests.Validation.Policy;

[Trait("Category", "Unit")]
public sealed class SignedAttributeFactsTests : IDisposable
{
    private readonly SyntheticPki _pki = new();

    [Fact]
    public void FromCms_TypicalAttributes_AreRead()
    {
        byte[] attributes = SignedAttributes(writer =>
        {
            Attribute(writer, "1.2.840.113549.1.9.3", w => w.WriteObjectIdentifier("1.2.840.113549.1.7.1"));
            Attribute(writer, "1.2.840.113549.1.9.4", w => w.WriteOctetString(new byte[32]));
            Attribute(writer, "1.2.840.113549.1.9.16.2.47", w => SigningCertificateV2(w, withIssuerSerial: true));
            Attribute(writer, "1.2.840.113549.1.9.16.2.16", w =>
            {
                using (w.PushSequence())
                {
                    w.WriteObjectIdentifier("1.2.840.113549.1.9.16.6.5");
                }
            });
            Attribute(writer, "1.2.840.113549.1.9.16.2.17", w =>
            {
                using (w.PushSequence())
                {
                }
            });
        });

        var facts = SignedAttributeFacts.FromCms(attributes)!;

        facts.SigningCertificateAttributes.ShouldBe(1);
        facts.MessageDigestOrSignedPropertiesPresent.ShouldBeTrue();
        facts.ContentType.ShouldBe("1.2.840.113549.1.7.1");
        facts.CommitmentTypes.ShouldBe(["1.2.840.113549.1.9.16.6.5"]);
        facts.SignerLocation.ShouldBeTrue();
        var reference = facts.CertificateReferences.ShouldHaveSingleItem();
        reference.DigestAlgorithm.ShouldBe("SHA256");
        reference.DigestMatches(_pki.Leaf).ShouldBeTrue();
        reference.IssuerSerialMatches(_pki.Leaf).ShouldBe(true);
    }

    [Fact]
    public void FromCms_ReferenceWithoutIssuerSerial_HasNoIssuerSerialAnswer()
    {
        byte[] attributes = SignedAttributes(writer => Attribute(writer, "1.2.840.113549.1.9.16.2.47", w => SigningCertificateV2(w, withIssuerSerial: false)));

        var reference = SignedAttributeFacts.FromCms(attributes)!.CertificateReferences.ShouldHaveSingleItem();

        reference.IssuerSerialMatches(_pki.Leaf).ShouldBeNull();
    }

    [Fact]
    public void FromCms_NoSignedAttributes_IsNull() => SignedAttributeFacts.FromCms(null).ShouldBeNull();

    public void Dispose() => _pki.Dispose();

    private void SigningCertificateV2(AsnWriter writer, bool withIssuerSerial)
    {
        using (writer.PushSequence())
        {
            using (writer.PushSequence())
            {
                using (writer.PushSequence())
                {
                    // hashAlgorithm absent: SHA-256 by default.
                    writer.WriteOctetString(SHA256.HashData(_pki.Leaf.RawData));
                    if (withIssuerSerial)
                    {
                        using (writer.PushSequence())
                        {
                            using (writer.PushSequence())
                            {
                                using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 4, isConstructed: true)))
                                {
                                    writer.WriteEncodedValue(_pki.Leaf.IssuerName.RawData);
                                }
                            }

                            writer.WriteIntegerUnsigned(_pki.Leaf.SerialNumberBytes.Span);
                        }
                    }
                }
            }
        }
    }

    private static byte[] SignedAttributes(Action<AsnWriter> attributes)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSetOf())
        {
            attributes(writer);
        }

        return writer.Encode();
    }

    private static void Attribute(AsnWriter writer, string oid, Action<AsnWriter> value)
    {
        using (writer.PushSequence())
        {
            writer.WriteObjectIdentifier(oid);
            using (writer.PushSetOf())
            {
                value(writer);
            }
        }
    }
}
