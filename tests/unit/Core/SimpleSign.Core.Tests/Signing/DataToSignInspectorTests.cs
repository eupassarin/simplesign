using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Shouldly;
using SimpleSign.Core.Constants;
using SimpleSign.Core.Signing;
using Xunit;

namespace SimpleSign.Core.Tests.Signing;

[Trait("Category", "Unit")]
public sealed class DataToSignInspectorTests : IDisposable
{
    private static readonly byte[] s_digest = SHA256.HashData("document"u8);

    private readonly X509Certificate2 _certificate = Certificate("CN=Signer");

    public void Dispose() => _certificate.Dispose();

    [Fact]
    public void Inspect_SignedAttributesNamingTheCertificate_AcceptsWithDigest()
    {
        var result = DataToSignInspector.Inspect(Attributes(signingCertificateV2: _certificate), _certificate);

        result.IsAccepted.ShouldBeTrue();
        result.Kind.ShouldBe(ExternalSigningPayloadKind.CmsSignedAttributes);
        result.ContentType.ShouldBe("1.2.840.113549.1.7.1");
        result.SigningCertificateMatches.ShouldBe(true);
        var digest = result.Digests.ShouldHaveSingleItem();
        digest.Algorithm.ShouldBe(HashAlgorithmName.SHA256);
        digest.Value.ToArray().ShouldBe(s_digest);
    }

    [Fact]
    public void Inspect_SignedAttributesNamingAnotherCertificate_RefusesWithSigningCertificateMismatch()
    {
        using var other = Certificate("CN=Someone else");

        var result = DataToSignInspector.Inspect(Attributes(signingCertificateV2: other), _certificate);

        result.Refusal.ShouldBe(DataToSignRefusal.SigningCertificateMismatch);
    }

    [Fact]
    public void Inspect_SignedAttributesV1NamingTheCertificate_Accepts() =>
        DataToSignInspector.Inspect(Attributes(signingCertificateV1: _certificate), _certificate).SigningCertificateMatches.ShouldBe(true);

    [Fact]
    public void Inspect_SignedAttributesWithoutSigningCertificate_AcceptsWithMatchUnknown()
    {
        var result = DataToSignInspector.Inspect(Attributes(), _certificate);

        result.IsAccepted.ShouldBeTrue();
        result.SigningCertificateMatches.ShouldBeNull();
    }

    [Fact]
    public void Inspect_SignedAttributesWithoutCertificateGiven_SkipsTheCertificateCheck()
    {
        using var other = Certificate("CN=Someone else");

        DataToSignInspector.Inspect(Attributes(signingCertificateV2: other)).SigningCertificateMatches.ShouldBeNull();
    }

    [Fact]
    public void Inspect_NoContentType_RefusesWithMissingContentType() =>
        DataToSignInspector.Inspect(Attributes(contentType: false)).Refusal.ShouldBe(DataToSignRefusal.MissingContentType);

    [Fact]
    public void Inspect_NoMessageDigest_RefusesWithMissingMessageDigest() =>
        DataToSignInspector.Inspect(Attributes(messageDigest: false)).Refusal.ShouldBe(DataToSignRefusal.MissingMessageDigest);

    [Fact]
    public void Inspect_TrailingBytes_RefusesWithMalformedSignedAttributes() =>
        DataToSignInspector.Inspect([.. Attributes(), 0x00]).Refusal.ShouldBe(DataToSignRefusal.MalformedSignedAttributes);

    [Fact]
    public void Inspect_RawHash_RefusesWithNotRecognized() =>
        DataToSignInspector.Inspect(s_digest).Refusal.ShouldBe(DataToSignRefusal.NotRecognized);

    [Fact]
    public void Inspect_Empty_RefusesWithEmpty() =>
        DataToSignInspector.Inspect([]).Refusal.ShouldBe(DataToSignRefusal.Empty);

    [Fact]
    public void Inspect_CanonicalSignedInfo_AcceptsWithEachReferenceDigest()
    {
        var result = DataToSignInspector.Inspect(Encoding.UTF8.GetBytes(SignedInfo()));

        result.IsAccepted.ShouldBeTrue();
        result.Kind.ShouldBe(ExternalSigningPayloadKind.XmlCanonicalizedSignedInfo);
        result.SignatureMethod.ShouldBe("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
        result.Digests.Count.ShouldBe(2);
        result.Digests[0].Algorithm.ShouldBe(HashAlgorithmName.SHA256);
        result.Digests[0].Value.ToArray().ShouldBe(s_digest);
        result.Digests[1].Type.ShouldBe("http://uri.etsi.org/01903#SignedProperties");
        result.SigningCertificateMatches.ShouldBeNull();
    }

    [Fact]
    public void Inspect_SignedInfoWithXmlDeclaration_RefusesWithMalformedSignedInfo() =>
        DataToSignInspector.Inspect(Encoding.UTF8.GetBytes("<?xml version=\"1.0\"?>" + SignedInfo())).Refusal
            .ShouldBe(DataToSignRefusal.MalformedSignedInfo);

    [Fact]
    public void Inspect_XmlWithDoctype_RefusesWithMalformedSignedInfo() =>
        DataToSignInspector.Inspect(Encoding.UTF8.GetBytes("<!DOCTYPE x [<!ENTITY e \"a\">]>" + SignedInfo())).Refusal
            .ShouldBe(DataToSignRefusal.MalformedSignedInfo);

    [Fact]
    public void Inspect_OtherXmlElement_RefusesWithMalformedSignedInfo() =>
        DataToSignInspector.Inspect("<Document>sign me</Document>"u8).Refusal.ShouldBe(DataToSignRefusal.MalformedSignedInfo);

    [Fact]
    public void Inspect_SignedInfoWithoutReferences_RefusesWithNoReferences() =>
        DataToSignInspector.Inspect(Encoding.UTF8.GetBytes(SignedInfo(references: false))).Refusal.ShouldBe(DataToSignRefusal.NoReferences);

    [Fact]
    public void Inspect_ReferenceWithoutDigestValue_RefusesWithMalformedSignedInfo() =>
        DataToSignInspector.Inspect(Encoding.UTF8.GetBytes(SignedInfo().Replace("<ds:DigestValue>", "<ds:Other>", StringComparison.Ordinal)
            .Replace("</ds:DigestValue>", "</ds:Other>", StringComparison.Ordinal))).Refusal.ShouldBe(DataToSignRefusal.MalformedSignedInfo);

    [Fact]
    public void ToShortString_Sha256Digest_ShowsAlgorithmAndBothEnds()
    {
        string hex = Convert.ToHexString(s_digest);

        new DataToSignDigest(HashAlgorithmName.SHA256, s_digest).ToShortString().ShouldBe($"SHA256 {hex[..8]}…{hex[^8..]}");
    }

    private static string SignedInfo(bool references = true)
    {
        string digest = Convert.ToBase64String(s_digest);
        string refs = references
            ? $"""<ds:Reference URI=""><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"></ds:Transform></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"></ds:DigestMethod><ds:DigestValue>{digest}</ds:DigestValue></ds:Reference><ds:Reference Type="http://uri.etsi.org/01903#SignedProperties" URI="#xades"><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"></ds:DigestMethod><ds:DigestValue>{digest}</ds:DigestValue></ds:Reference>"""
            : "";
        return $"""<ds:SignedInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:CanonicalizationMethod><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"></ds:SignatureMethod>{refs}</ds:SignedInfo>""";
    }

    private static byte[] Attributes(
        bool contentType = true, bool messageDigest = true, X509Certificate2? signingCertificateV2 = null, X509Certificate2? signingCertificateV1 = null)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSetOf())
        {
            if (contentType)
            {
                Attribute(writer, Oids.ContentType, w => w.WriteObjectIdentifier("1.2.840.113549.1.7.1"));
            }

            if (messageDigest)
            {
                Attribute(writer, Oids.MessageDigest, w => w.WriteOctetString(s_digest));
            }

            if (signingCertificateV2 is not null)
            {
                Attribute(writer, Oids.SigningCertificateV2, w =>
                {
                    using (w.PushSequence())
                    using (w.PushSequence())
                    using (w.PushSequence())
                    {
                        w.WriteOctetString(signingCertificateV2.GetCertHash(HashAlgorithmName.SHA256));
                    }
                });
            }

            if (signingCertificateV1 is not null)
            {
                Attribute(writer, Oids.SigningCertificate, w =>
                {
                    using (w.PushSequence())
                    using (w.PushSequence())
                    using (w.PushSequence())
                    {
                        w.WriteOctetString(signingCertificateV1.GetCertHash());
                    }
                });
            }
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

    private static X509Certificate2 Certificate(string subject)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        return new CertificateRequest(subject, key, HashAlgorithmName.SHA256).CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
    }
}
