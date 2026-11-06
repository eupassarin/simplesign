using System.Formats.Asn1;
using Shouldly;
using SimpleSign.Core.Crypto;
using Xunit;

namespace SimpleSign.Core.Tests.Crypto;

[Trait("Category", "Unit")]
public sealed class DerEncoderTests
{
    [Fact(DisplayName = "Simple OID produces valid and decodable DER")]
    public void EncodeOid_SimpleOid_ProducesValidDer()
    {
        // OID 1.2.840.113549.1.1.11 = SHA256withRSA
        byte[] result = DerEncoder.EncodeOid("1.2.840.113549.1.1.11");

        result[0].ShouldBe((byte)0x06);
        // Verify it can be parsed back by .NET's ASN.1 reader
        var reader = new AsnReader(result, AsnEncodingRules.DER);
        string oid = reader.ReadObjectIdentifier();
        oid.ShouldBe("1.2.840.113549.1.1.11");
    }

    [Theory(DisplayName = "Known OIDs encode and decode correctly")]
    [InlineData("1.2.840.113549.1.1.11")]   // SHA256withRSA
    [InlineData("2.16.840.1.101.3.4.2.1")]  // SHA-256
    [InlineData("1.2.840.10045.4.3.2")]      // ECDSA-SHA256
    [InlineData("2.16.76.1.3.1")]            // ICP-Brasil SAN CPF
    [InlineData("1.3.14.3.2.26")]            // SHA-1
    [InlineData("1.2.840.113549.1.9.4")]     // messageDigest
    public void EncodeOid_KnownOids_RoundTripsCorrectly(string oidStr)
    {
        byte[] encoded = DerEncoder.EncodeOid(oidStr);

        var reader = new AsnReader(encoded, AsnEncodingRules.DER);
        string decoded = reader.ReadObjectIdentifier();
        decoded.ShouldBe(oidStr);
    }

    [Fact(DisplayName = "Minimal OID (0.0) generates 3 DER bytes")]
    public void EncodeOid_MinimalOid_Works()
    {
        // Smallest valid OID: 0.0
        byte[] result = DerEncoder.EncodeOid("0.0");

        result.Length.ShouldBe(3); // tag + length(1) + content(1 byte = 0x00)
        result[0].ShouldBe((byte)0x06);
        result[1].ShouldBe((byte)1);
        result[2].ShouldBe((byte)0);
    }

    [Fact(DisplayName = "Large arcs use correct multi-byte encoding")]
    public void EncodeOid_LargeArcValues_EncodesMultiByteCorrectly()
    {
        // OID 2.16.840 has arc 840 which requires multi-byte base-128 encoding
        byte[] result = DerEncoder.EncodeOid("2.16.840");

        var reader = new AsnReader(result, AsnEncodingRules.DER);
        string decoded = reader.ReadObjectIdentifier();
        decoded.ShouldBe("2.16.840");
    }

    [Fact(DisplayName = "First two arcs follow X.690 §8.19.4 rule")]
    public void EncodeOid_FirstTwoArcsEncoding_FollowsX690Rule()
    {
        // Per X.690: first octet = 40 * arc1 + arc2
        // OID 1.2.x → first byte = 40*1 + 2 = 42 = 0x2A
        byte[] result = DerEncoder.EncodeOid("1.2.3");

        result[2].ShouldBe((byte)42);
        result[3].ShouldBe((byte)3);
    }
}
