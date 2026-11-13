using Shouldly;
using SimpleSign.Core.Extensions;
using SimpleSign.Core.Policies;
using SimpleSign.Core.Signing;
using SimpleSign.Core.Validation;
using SimpleSign.PAdES.Validation;
using SimpleSign.TestHelpers;
using Xunit;

namespace SimpleSign.PAdES.Tests.Signing;

/// <summary>A trust profile through <c>WithProfile</c> (signing) and <c>ValidationOptions.Profile</c> (validation).</summary>
[Trait("Category", "Unit")]
public sealed class TrustProfileSigningTests : IDisposable
{
    private static readonly SigningPolicy Anchored = SigningPolicy.Default
        .With("SigningCertificate/ProspectiveCertificateChain", new PolicyConstraint(ConstraintLevel.Fail));

    private readonly SyntheticPki _pki = new();

    public void Dispose() => _pki.Dispose();

    private static TrustProfile Profile(SyntheticPki pki, SigningPolicy? signing) =>
        new("test", "Test", signing, ValidationPolicy.Default, [new InMemoryTrustAnchors(pki.RootCa)], []);

    [Fact]
    public async Task WithProfile_RootOutsideTheProfile_IsRefused()
    {
        using var other = new SyntheticPki();

        var ex = await Should.ThrowAsync<SigningException>(() => PadesSigner.Document(TestPdfFactory.CreateMinimalPdf())
            .WithCertificate(_pki.Leaf, _pki.IntermediatesAndRoot())
            .WithProfile(Profile(other, Anchored))
            .SignAsync());

        ex.Reason.ShouldBe(SigningErrorReason.UntrustedRoot);
    }

    [Fact]
    public async Task WithProfile_RootInTheProfile_SignsAndValidatesWithTheProfile()
    {
        var profile = Profile(_pki, Anchored);

        byte[] signed = await PadesSigner.Document(TestPdfFactory.CreateMinimalPdf())
            .WithCertificate(_pki.Leaf, _pki.IntermediatesAndRoot())
            .WithProfile(profile)
            .SignAsync();

        using var stream = new MemoryStream(signed);
        var result = (await new PdfSignatureValidator(new ValidationOptions { CheckRevocation = false, TrustSystemRoots = false, Profile = profile })
            .ValidateAsync(stream)).ShouldHaveSingleItem();
        result.IsCertificateChainValid.ShouldBeTrue();
    }

    [Fact]
    public async Task Validate_ProfileWithAQualifier_GivesEachSignatureItsQualification()
    {
        var qualifier = new FixedQualifier();
        var profile = Profile(_pki, Anchored) with { SignatureQualifiers = [qualifier] };
        byte[] signed = await PadesSigner.Document(TestPdfFactory.CreateMinimalPdf())
            .WithCertificate(_pki.Leaf, _pki.IntermediatesAndRoot())
            .WithProfile(profile)
            .SignAsync();

        using var stream = new MemoryStream(signed);
        var result = (await new PdfSignatureValidator(new ValidationOptions { CheckRevocation = false, TrustSystemRoots = false, Profile = profile })
            .ValidateAsync(stream)).ShouldHaveSingleItem();

        result.Qualification.ShouldNotBeNull().Level.ShouldBe("QESig");
        qualifier.Context.ShouldNotBeNull().Format.ShouldBe("PAdES");
        qualifier.Context.SignerCertificate.Thumbprint.ShouldBe(_pki.Leaf.Thumbprint);
        result.ToReportEntry().Qualification.ShouldBe(result.Qualification);
    }

    [Fact]
    public void WithTrustFrom_OtherProfileWithAQualifier_DoesNotTakeIt()
    {
        var profile = Profile(_pki, Anchored);

        var combined = profile.WithTrustFrom(profile with { SignatureQualifiers = [new FixedQualifier()] });

        combined.SignatureQualifiers.ShouldBeEmpty();
    }

    private sealed class FixedQualifier : ISignatureQualifier
    {
        public SignatureQualificationContext? Context { get; private set; }

        public SignatureQualification? Qualify(SignatureQualificationContext context)
        {
            Context = context;
            return new SignatureQualification("QESig");
        }
    }

    [Fact]
    public void WithProfile_ProfileThatDoesNotSign_Throws() =>
        Should.Throw<ArgumentException>(() => PadesSigner.Document(TestPdfFactory.CreateMinimalPdf()).WithProfile(Profile(_pki, signing: null)));
}
