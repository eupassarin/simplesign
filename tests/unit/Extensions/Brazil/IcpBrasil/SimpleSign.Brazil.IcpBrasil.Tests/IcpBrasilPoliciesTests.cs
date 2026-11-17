using Shouldly;
using SimpleSign.Core.Policies;
using SimpleSign.Core.Signing;
using SimpleSign.PAdES;
using SimpleSign.TestHelpers;

namespace SimpleSign.Brazil.IcpBrasil.Tests;

[Trait("Category", "Unit")]
public sealed class IcpBrasilPoliciesTests : IDisposable
{
    private readonly SyntheticPki _pki = new();

    public void Dispose() => _pki.Dispose();

    [Theory]
    [InlineData("SigningCertificate/ProspectiveCertificateChain")]
    [InlineData("SigningCertificate/NotRevoked")]
    [InlineData("SigningCertificate/RevocationDataAvailable")]
    [InlineData("CACertificate/NotRevoked")]
    [InlineData("CACertificate/RevocationDataAvailable")]
    [InlineData("CACertificate/Cryptographic")]
    [InlineData("Timestamp/ProspectiveCertificateChain")]
    [InlineData("Timestamp/NotRevoked")]
    public void Signing_Constraint_IsFail(string path) =>
        IcpBrasilPolicies.Signing.Find(path).ShouldNotBeNull().Level.ShouldBe(ConstraintLevel.Fail);

    [Fact]
    public async Task Signing_RootNotAmongTheAnchors_IsRefused()
    {
        using var other = new SyntheticPki();

        var ex = await Should.ThrowAsync<SigningException>(() => PadesSigner.Document(TestPdfFactory.CreateMinimalPdf())
            .WithCertificate(_pki.Leaf, _pki.IntermediatesAndRoot())
            .WithSigningPolicy(IcpBrasilPolicies.Signing)
            .WithTrustAnchors(new InMemoryTrustAnchors(other.RootCa))
            .SignAsync());

        ex.Reason.ShouldBe(SigningErrorReason.UntrustedRoot);
    }

    [Fact]
    public void Validation_SigningCertificateKeyUsage_FailsWithoutDigitalSignatureOrNonRepudiation()
    {
        var keyUsage = IcpBrasilPolicies.Validation.Find("SignatureConstraints/BasicSignatureConstraints/SigningCertificate/KeyUsage").ShouldNotBeNull();

        keyUsage.Level.ShouldBe(ConstraintLevel.Fail);
        keyUsage.Ids.ShouldBe(["digitalSignature", "nonRepudiation"], ignoreOrder: true);
    }

    [Fact]
    public void Policies_ToJson_RoundTrip()
    {
        SigningPolicy.FromJson(IcpBrasilPolicies.Signing.ToJson()).Name.ShouldBe("ICP-Brasil");
        ValidationPolicy.FromJson(IcpBrasilPolicies.Validation.ToJson()).Name.ShouldBe("ICP-Brasil");
    }

    [Fact]
    public void Profile_Create_CarriesThePoliciesTheRootsAndTheChainValidation()
    {
        var profile = IcpBrasilProfile.Create();

        profile.Name.ShouldBe("icp-brasil");
        profile.SigningPolicy.ShouldBeSameAs(IcpBrasilPolicies.Signing);
        profile.ValidationPolicy.ShouldBeSameAs(IcpBrasilPolicies.Validation);
        profile.TrustAnchorProviders.SelectMany(p => p.GetTrustAnchors()).ShouldNotBeEmpty();
        profile.ChainValidationProviders.ShouldNotBeEmpty();
    }
}
