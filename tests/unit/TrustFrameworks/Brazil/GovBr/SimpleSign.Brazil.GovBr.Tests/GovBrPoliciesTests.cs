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

    [Fact]
    public void Validation_ToJson_RoundTrips() =>
        ValidationPolicy.FromJson(GovBrPolicies.Validation.ToJson()).Name.ShouldBe("Gov.br");
}
