using Shouldly;
using SimpleSign.Core.Extensions;
using SimpleSign.Core.Policies;
using SimpleSign.Core.Signing;
using SimpleSign.Core.Validation;
using SimpleSign.PAdES.Validation;
using SimpleSign.TestHelpers;
using Xunit;

namespace SimpleSign.PAdES.Tests.Signing;

/// <summary>Trust anchors with conditions (<see cref="IConstrainedTrustAnchorProvider"/>) in PAdES validation and before signing.</summary>
[Trait("Category", "Unit")]
public sealed class ConstrainedTrustAnchorTests : IDisposable
{
    private const string Reason = "the signer's certificate has none of the certificate policies the anchor is trusted for";

    private static readonly SigningPolicy Anchored = SigningPolicy.Default
        .With("SigningCertificate/ProspectiveCertificateChain", new PolicyConstraint(ConstraintLevel.Fail));

    private readonly SyntheticPki _pki = new();

    public void Dispose() => _pki.Dispose();

    [Fact]
    public async Task Validate_AnchorRefusesTheChain_TheChainIsNotTrusted()
    {
        var result = await ValidateAsync(Profile(ConstrainedTrustAnchors.Refusing(Reason, _pki.RootCa)));

        result.IsCertificateChainValid.ShouldBeFalse();
        result.Indication.ShouldBe(SignatureIndication.Indeterminate);
        result.Errors.ShouldContain(e => e.Contains(Reason, StringComparison.Ordinal));
    }

    [Fact]
    public async Task Validate_AnchorAcceptsTheChain_TheChainIsTrusted()
    {
        var result = await ValidateAsync(Profile(ConstrainedTrustAnchors.Accepting(_pki.RootCa)));

        result.IsCertificateChainValid.ShouldBeTrue(string.Join("; ", result.Errors));
    }

    [Fact]
    public async Task Validate_AnchorAsksAboutTheSignerCertificate_SeesTheChainFromTheSigner()
    {
        string? signer = null;
        var anchors = new ConstrainedTrustAnchors((_, chain) =>
        {
            signer = chain[0].Thumbprint;
            return null;
        }, _pki.RootCa);

        await ValidateAsync(Profile(anchors));

        signer.ShouldBe(_pki.Leaf.Thumbprint);
    }

    [Fact]
    public async Task Validate_AnchorAlsoTrustedByAnotherProfileWithoutConditions_TheChainIsTrusted()
    {
        var plain = new TrustProfile("plain", "Plain", null, ValidationPolicy.Default, [new InMemoryTrustAnchors(_pki.RootCa)], []);

        var result = await ValidateAsync(Profile(ConstrainedTrustAnchors.Refusing(Reason, _pki.RootCa)).WithTrustFrom(plain));

        result.IsCertificateChainValid.ShouldBeTrue(string.Join("; ", result.Errors));
    }

    [Fact]
    public async Task Validate_ConstrainedAnchorsInTheOptions_AreAsked()
    {
        byte[] signed = await SignAsync();
        var options = new ValidationOptions
        {
            CheckRevocation = false,
            TrustSystemRoots = false,
            TrustedRoots = [_pki.RootCa],
            ConstrainedTrustAnchors = [ConstrainedTrustAnchors.Refusing(Reason, _pki.RootCa)],
        };

        using var stream = new MemoryStream(signed);
        var result = (await new PdfSignatureValidator(options).ValidateAsync(stream)).ShouldHaveSingleItem();

        result.IsCertificateChainValid.ShouldBeFalse();
    }

    [Fact]
    public async Task Sign_AnchorRefusesTheChain_IsRefusedAsAnUntrustedRoot()
    {
        var ex = await Should.ThrowAsync<SigningException>(() => PadesSigner.Document(TestPdfFactory.CreateMinimalPdf())
            .WithCertificate(_pki.Leaf, _pki.IntermediatesAndRoot())
            .WithProfile(Profile(ConstrainedTrustAnchors.Refusing(Reason, _pki.RootCa)))
            .SignAsync());

        ex.Reason.ShouldBe(SigningErrorReason.UntrustedRoot);
        ex.Message.ShouldContain(Reason);
    }

    [Fact]
    public async Task Sign_AnchorAcceptsTheChain_Signs()
    {
        byte[] signed = await PadesSigner.Document(TestPdfFactory.CreateMinimalPdf())
            .WithCertificate(_pki.Leaf, _pki.IntermediatesAndRoot())
            .WithProfile(Profile(ConstrainedTrustAnchors.Accepting(_pki.RootCa)))
            .SignAsync();

        signed.ShouldNotBeEmpty();
    }

    private static TrustProfile Profile(ConstrainedTrustAnchors anchors) =>
        new("test", "Test", Anchored, ValidationPolicy.Default, [anchors], []);

    private Task<byte[]> SignAsync() =>
        PadesSigner.Document(TestPdfFactory.CreateMinimalPdf()).WithCertificate(_pki.Leaf, _pki.IntermediatesAndRoot()).SignAsync();

    private async Task<SignatureValidationResult> ValidateAsync(TrustProfile profile)
    {
        using var stream = new MemoryStream(await SignAsync());
        return (await new PdfSignatureValidator(new ValidationOptions { CheckRevocation = false, TrustSystemRoots = false, Profile = profile })
            .ValidateAsync(stream)).ShouldHaveSingleItem();
    }
}
