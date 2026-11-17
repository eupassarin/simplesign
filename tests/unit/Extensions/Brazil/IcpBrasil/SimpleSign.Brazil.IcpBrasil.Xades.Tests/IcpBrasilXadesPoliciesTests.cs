using System.Security.Cryptography;
using Shouldly;

namespace SimpleSign.Brazil.IcpBrasil.Xades.Tests;

/// <summary>The real LPA_XAdES.xml and an XML PA from the ITI repository.</summary>
[Trait("Category", "Unit")]
public sealed class IcpBrasilXadesPoliciesTests
{
    private static byte[] Fixture(string name) => File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, "Fixtures", name));

    [Fact]
    public void VerifyXmlSignature_RealLpa_SignedByTheIti()
    {
        var (signer, _) = IcpBrasilXadesPolicies.VerifyXmlSignature(Fixture("LPA_XAdES.xml"));

        IcpBrasilChainValidator.ExtractCpfCnpj(signer).Cnpj.ShouldBe("04039532000193");
    }

    [Fact]
    public void VerifyXmlSignature_TamperedLpa_Throws()
    {
        string xml = System.Text.Encoding.UTF8.GetString(Fixture("LPA_XAdES.xml"));
        byte[] tampered = System.Text.Encoding.UTF8.GetBytes(xml.Replace("2037-10-22", "2099-10-22", StringComparison.Ordinal));

        Should.Throw<CryptographicException>(() => IcpBrasilXadesPolicies.VerifyXmlSignature(tampered));
    }

    [Fact]
    public void VerifyXmlSignature_EntrySmuggledIntoTheSignature_Throws()
    {
        string xml = System.Text.Encoding.UTF8.GetString(Fixture("LPA_XAdES.xml"));
        string entry = "<ds:Object><lpa:PolicyInfo xmlns:lpa=\"http://www.iti.gov.br/LPA/v2#\"/></ds:Object></ds:Signature>";
        byte[] wrapped = System.Text.Encoding.UTF8.GetBytes(xml.Replace("</ds:Signature>", entry, StringComparison.Ordinal));

        Should.Throw<CryptographicException>(() => IcpBrasilXadesPolicies.VerifyXmlSignature(wrapped));
    }

    [Fact]
    public void ParseXml_RealLpa_ListsTheCatalogPolicies()
    {
        var lpa = IcpBrasilLpa.ParseXml(Fixture("LPA_XAdES.xml"));

        lpa.Entries.Count.ShouldBe(45);
        lpa.Entries.Where(e => !IcpBrasilSignaturePolicies.TryFind(e.Oid, out _)).ShouldBeEmpty();
        var rc = lpa.Entries.Single(e => e.Oid == "2.16.76.1.7.1.9.2.5");
        rc.Uri.ShouldBe("http://politicas.icpbrasil.gov.br/PA_AD_RC_v2_5.xml");
        Convert.ToHexString(rc.Digest.Span).ShouldBe(Convert.ToHexString(SHA256.HashData(Fixture("PA_AD_RC_v2_5.xml"))));
        lpa.Entries.First().RevokedAt.ShouldNotBeNull();
    }

    [Fact]
    public void FromXmlPolicyDocument_RealPa_MatchesTheCatalog()
    {
        var parsed = IcpBrasilSignaturePolicies.FromXmlPolicyDocument(Fixture("PA_AD_RC_v2_5.xml"), "http://politicas.icpbrasil.gov.br/PA_AD_RC_v2_5.xml");

        IcpBrasilSignaturePolicies.TryFind(parsed.Oid, out var known).ShouldBeTrue();
        parsed.PolicyHashHex.ShouldBe(known!.PolicyHashHex);
        parsed.HashAlgorithmOid.ShouldBe(known.HashAlgorithmOid);
        parsed.NotBefore.ShouldBe(known.NotBefore);
    }

    [Fact]
    public void ParseXml_RealPa_RulesMatchTheCatalog()
    {
        var parsed = IcpBrasilPolicyRules.ParseXml(Fixture("PA_AD_RC_v2_5.xml"));

        IcpBrasilSignaturePolicies.TryGetRules(parsed.Oid, out var known).ShouldBeTrue();
        parsed.MandatedSignedAttributes.ShouldBe(known!.MandatedSignedAttributes);
        parsed.MandatedUnsignedAttributes.ShouldBe(["SignatureTimeStamp", "CompleteCertificateRefs", "CompleteRevocationRefs", "SigAndRefsTimeStamp", "CertificateValues", "RevocationValues"]);
        parsed.TrustAnchorKeySha256.ShouldBe(known.TrustAnchorKeySha256);
        parsed.SignerAlgorithms.Count.ShouldBe(4);
        parsed.SignerAlgorithms.ShouldContain(a => a.Oid == "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" && a.MinKeyLength == 2048);
    }

    [Fact]
    public void ParseXml_NotAnLpa_Throws() =>
        Should.Throw<ArgumentException>(() => IcpBrasilLpa.ParseXml("<x/>"u8));
}
