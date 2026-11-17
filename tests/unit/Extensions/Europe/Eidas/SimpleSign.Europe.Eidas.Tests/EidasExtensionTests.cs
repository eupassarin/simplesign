using System.Security.Cryptography;
using Shouldly;
using SimpleSign.XAdES.TrustedLists;

namespace SimpleSign.Europe.Eidas.Tests;

[Trait("Category", "Unit")]
public sealed class EidasExtensionTests
{
    // The key that signed the EU LOTL #398 (2026-11), one of the six bundled.
    private const string Lotl398Signer = "E0A620FBB6747362BB933AC44169D676A553444716CF5F31605F12A22B8396B1";

    [Fact]
    public void LotlSigners_AreTheBundledKeysOfTheEuLotl()
    {
        var fingerprints = EidasExtension.LotlSigners.Select(c => Convert.ToHexString(c.GetCertHash(HashAlgorithmName.SHA256))).ToList();

        fingerprints.Count.ShouldBe(6);
        fingerprints.ShouldContain(Lotl398Signer);
    }

    [Fact]
    public void LotlSigners_CheckTheEuLotlAsPublished()
    {
        byte[] xml = File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, "Fixtures", "eu-lotl-398.xml"));

        var lotl = TrustedList.Load(xml, new TrustedListOptions { SignerCertificates = EidasExtension.LotlSigners, RejectExpired = false });

        lotl.Territory.ShouldBe("EU");
        lotl.SequenceNumber.ShouldBe("398");
        lotl.Pointers.Count(p => p.MimeType == "application/vnd.etsi.tsl+xml").ShouldBeGreaterThan(25);
        lotl.SchemeInformationUris.ShouldContain(u => u.EndsWith("eu-lotl-pivot-378.xml", StringComparison.Ordinal));
    }

    [Fact]
    public void SetOptionsOf_NoSigners_UsesTheBundledOnesAndTheEuLotl()
    {
        var options = EidasExtension.SetOptionsOf(new EidasExtensionOptions());

        options.LotlLocation.ShouldBe(TrustedListSetOptions.EuropeanLotl);
        options.LotlSignerCertificates.Count.ShouldBe(6);
        options.FollowPivots.ShouldBeTrue();
    }

    [Fact]
    public void Profile_CarriesThePoliciesAndTheQualifier()
    {
        byte[] xml = File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, "Fixtures", "eu-lotl-398.xml"));
        var lotl = TrustedList.Load(xml, new TrustedListOptions { SignerCertificates = EidasExtension.LotlSigners, RejectExpired = false });

        var profile = EidasProfile.Create(new EidasExtension(lotl, new EidasQualifier(() => [lotl])));

        profile.Name.ShouldBe("eidas");
        profile.SigningPolicy.ShouldBeSameAs(EidasPolicies.Signing);
        profile.ValidationPolicy.ShouldBeSameAs(EidasPolicies.Validation);
        profile.SignatureQualifiers.ShouldHaveSingleItem().ShouldBeOfType<EidasQualifier>();
    }

    [Fact]
    public void Policies_SigningWarnsOnANonQualifiedCertificateAndValidationFailsABadList()
    {
        EidasPolicies.Signing.ToJson().ShouldContain("QcCompliance");
        EidasPolicies.Validation.ToJson().ShouldContain("TLWellSigned");
    }
}
