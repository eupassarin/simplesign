using System.Formats.Asn1;
using System.Numerics;
using Shouldly;
using SimpleSign.TestBench.Reports;
using SimpleSign.TestHelpers;

namespace SimpleSign.TestBench.Tests;

/// <summary>Reading the timestamps, CRLs and OCSP responses a validation used, for the SimpleSign report.</summary>
[Trait("Category", "Unit")]
public sealed class ValidationObjectFactsTests
{
    private static readonly DateTimeOffset s_producedAt = new(2026, 11, 10, 10, 0, 0, TimeSpan.Zero);

    [Fact]
    public void Crl_RevokedLeafCrl_ReadsIssuerAndDates()
    {
        using var pki = new SyntheticPki();

        var facts = ValidationObjectFacts.Crl(pki.BuildRevokedLeafCrl());

        facts.ShouldNotBeNull();
        facts.Issuer.ShouldBe(pki.IntermediateCa.Subject);
        facts.ThisUpdate.ShouldNotBeNull();
        facts.NextUpdate.ShouldNotBeNull();
        facts.NextUpdate!.Value.ShouldBeGreaterThan(facts.ThisUpdate!.Value);
        facts.Status.ShouldBeNull();
    }

    [Fact]
    public void Crl_NotACrl_IsNull() =>
        ValidationObjectFacts.Crl(new byte[] { 0x30, 0x03, 0x02, 0x01, 0x01 }).ShouldBeNull();

    [Theory]
    [InlineData(0, "GOOD")]
    [InlineData(1, "REVOKED")]
    [InlineData(2, "UNKNOWN")]
    public void Ocsp_BasicResponse_ReadsResponderSerialAndStatus(int status, string expected)
    {
        var facts = ValidationObjectFacts.Ocsp(BasicResponse(status, serial: 4242));

        facts.ShouldNotBeNull();
        facts.Issuer.ShouldBe("CN=Responder");
        facts.ProducedAt.ShouldBe(s_producedAt);
        facts.ThisUpdate.ShouldBe(s_producedAt.AddHours(-1));
        facts.NextUpdate.ShouldBe(s_producedAt.AddDays(1));
        facts.Serial.ShouldBe(new BigInteger(4242));
        facts.Status.ShouldBe(expected);
    }

    [Fact]
    public void Ocsp_WrappedInOcspResponse_ReadsTheBasicResponse()
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            writer.WriteEnumeratedValue(OcspStatus.Successful);
            using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true)))
            using (writer.PushSequence())
            {
                writer.WriteObjectIdentifier("1.3.6.1.5.5.7.48.1.1");
                writer.WriteOctetString(BasicResponse(0, serial: 7));
            }
        }

        var facts = ValidationObjectFacts.Ocsp(writer.Encode());

        facts.ShouldNotBeNull();
        facts.Serial.ShouldBe(new BigInteger(7));
        facts.Status.ShouldBe("GOOD");
    }

    [Fact]
    public void Ocsp_Garbage_IsNull() =>
        ValidationObjectFacts.Ocsp(new byte[] { 1, 2, 3 }).ShouldBeNull();

    [Fact]
    public void TimestampSigner_NotAToken_IsNull() =>
        ValidationObjectFacts.TimestampSigner(new byte[] { 0x30, 0x00 }).ShouldBeNull();

    private enum OcspStatus
    {
        Successful = 0,
    }

    /// <summary>A BasicOCSPResponse (RFC 6960 §4.2.1) with one answer; its signature is not checked by the reader.</summary>
    private static byte[] BasicResponse(int status, long serial)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            using (writer.PushSequence())
            {
                using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 1, true)))
                {
                    writer.WriteEncodedValue(new System.Security.Cryptography.X509Certificates.X500DistinguishedName("CN=Responder").RawData);
                }

                writer.WriteGeneralizedTime(s_producedAt);
                using (writer.PushSequence())
                using (writer.PushSequence())
                {
                    using (writer.PushSequence())
                    {
                        using (writer.PushSequence())
                        {
                            writer.WriteObjectIdentifier("1.3.14.3.2.26");
                        }

                        writer.WriteOctetString(new byte[20]);
                        writer.WriteOctetString(new byte[20]);
                        writer.WriteInteger(serial);
                    }

                    if (status == 1)
                    {
                        using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 1, true)))
                        {
                            writer.WriteGeneralizedTime(s_producedAt.AddDays(-2));
                        }
                    }
                    else
                    {
                        writer.WriteNull(new Asn1Tag(TagClass.ContextSpecific, status));
                    }

                    writer.WriteGeneralizedTime(s_producedAt.AddHours(-1));
                    using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true)))
                    {
                        writer.WriteGeneralizedTime(s_producedAt.AddDays(1));
                    }
                }
            }

            using (writer.PushSequence())
            {
                writer.WriteObjectIdentifier("1.2.840.113549.1.1.11");
            }

            writer.WriteBitString(new byte[8]);
        }

        return writer.Encode();
    }
}
