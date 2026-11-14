using Shouldly;
using SimpleSign.Core.Policies;

namespace SimpleSign.Brazil.GovBr.Tests;

[Trait("Category", "Unit")]
public sealed class GovBrPoliciesTests
{
    [Fact]
    public void Validation_SigningCertificateKeyUsage_FailsWithoutDigitalSignatureOrNonRepudiation()
    {
        var keyUsage = GovBrPolicies.Validation.Find("SignatureConstraints/BasicSignatureConstraints/SigningCertificate/KeyUsage").ShouldNotBeNull();

        keyUsage.Level.ShouldBe(ConstraintLevel.Fail);
        keyUsage.Ids.ShouldBe(["digitalSignature", "nonRepudiation"], ignoreOrder: true);
    }

    [Theory]
    [InlineData("SignatureConstraints/SignedAttributes/SigningCertificatePresent")]
    [InlineData("SignatureConstraints/SignedAttributes/CertDigestPresent")]
    public void Validation_SigningCertificateAttributeMissing_OnlyWarns(string path) =>
        GovBrPolicies.Validation.Find(path).ShouldNotBeNull().Level.ShouldBe(ConstraintLevel.Warn);

    [Fact]
    public void Validation_SigningCertificateReference_MustStillMatch() =>
        GovBrPolicies.Validation.Find("SignatureConstraints/SignedAttributes/CertDigestMatch").ShouldNotBeNull().Level.ShouldBe(ConstraintLevel.Fail);

    [Fact]
    public void Validation_ToJson_RoundTrips() =>
        ValidationPolicy.FromJson(GovBrPolicies.Validation.ToJson()).Name.ShouldBe("Gov.br");

    [Fact]
    public void Profile_Create_ValidatesOnly()
    {
        var profile = GovBrProfile.Create();

        profile.Name.ShouldBe("gov-br");
        profile.CanSign.ShouldBeFalse();
        profile.ValidationPolicy.ShouldBeSameAs(GovBrPolicies.Validation);
        profile.TrustAnchorProviders.SelectMany(p => p.GetTrustAnchors()).ShouldNotBeEmpty();
    }
}
