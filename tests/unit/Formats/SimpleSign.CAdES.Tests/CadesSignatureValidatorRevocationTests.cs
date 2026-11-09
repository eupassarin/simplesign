using System.Net;
using Shouldly;
using SimpleSign.Core.Revocation;
using SimpleSign.Core.Validation;
using SimpleSign.TestHelpers;
using Xunit;

namespace SimpleSign.CAdES.Tests;

[Trait("Category", "Unit")]
public sealed class CadesSignatureValidatorRevocationTests
{
    private const string LeafCrlUrl = "http://198.51.100.1/leaf.crl";
    private const string IntermediateCrlUrl = "http://198.51.100.1/intermediate.crl";
    private static readonly byte[] Content = "revocation test"u8.ToArray();

    [Fact]
    public async Task ValidateAsync_ChainNotRevoked_ValidWithChainRevocation()
    {
        using var pki = NewPki();
        byte[] cms = await Sign(pki);
        using var http = CrlServer(pki.BuildLeafCrl(), pki.BuildIntermediateCrl());

        var result = await Validator(http).ValidateAsync(cms, Content, [pki.RootCa]);

        result.Indication.ShouldBe(SignatureIndication.Valid);
        result.IsNotRevoked.ShouldBe(true);
        result.RevocationSource.ShouldBe(RevocationSource.CertificateChain);
    }

    [Fact]
    public async Task ValidateAsync_SignerRevoked_IndeterminateRevokedNoPoe()
    {
        using var pki = NewPki();
        byte[] cms = await Sign(pki);
        using var http = CrlServer(pki.BuildRevokedLeafCrl(), pki.BuildIntermediateCrl());

        var result = await Validator(http).ValidateAsync(cms, Content, [pki.RootCa]);

        // Nothing proves the signature existed before the revocation (EN 319 102-1 §5.2.6).
        result.Indication.ShouldBe(SignatureIndication.Indeterminate);
        result.SubIndication.ShouldBe(SignatureSubIndication.RevokedNoPoe);
        result.IsValid.ShouldBeFalse();
    }

    [Fact]
    public async Task ValidateAsync_StatusUnknown_IndeterminateCertificateChainGeneralFailure()
    {
        using var pki = NewPki();
        byte[] cms = await Sign(pki);
        using var http = MockHttpHandler.Failing();

        var result = await Validator(http).ValidateAsync(cms, Content, [pki.RootCa]);

        result.Indication.ShouldBe(SignatureIndication.Indeterminate);
        result.SubIndication.ShouldBe(SignatureSubIndication.CertificateChainGeneralFailure);
    }

    [Fact]
    public async Task ValidateAsync_RevocationOff_NotChecked()
    {
        using var pki = NewPki();
        byte[] cms = await Sign(pki);
        using var http = MockHttpHandler.Failing();
        var validator = new CadesSignatureValidator(
            new ValidationOptions { CheckRevocation = false }, chainRevocationChecker: new ChainRevocationChecker(http));

        var result = await validator.ValidateAsync(cms, Content, [pki.RootCa]);

        result.Indication.ShouldBe(SignatureIndication.Valid);
        result.IsNotRevoked.ShouldBeNull();
    }

    [Fact]
    public async Task ValidateAsync_UntrustedChain_IsNotCheckedUnlessAsked()
    {
        using var pki = NewPki();
        // The whole chain in the signature, but its root is not trusted.
        byte[] cms = await CadesSigner.Document(Content).WithCertificate(pki.Leaf, [pki.IntermediateCa, pki.RootCa]).SignAsync();
        int requests = 0;
        using var http = new HttpClient(new MockHttpHandler(_ =>
        {
            Interlocked.Increment(ref requests);
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
        }));

        var untrusted = await Validator(http).ValidateAsync(cms, Content, trustAnchors: []);
        requests.ShouldBe(0);
        untrusted.IsNotRevoked.ShouldBeNull();

        var asked = new CadesSignatureValidator(
            new ValidationOptions
            {
                CheckRevocation = true,
                TrustSystemRoots = false,
                Verifier = new VerifierOptions { CheckRevocationForUntrustedChains = true },
            },
            chainRevocationChecker: new ChainRevocationChecker(http));
        (await asked.ValidateAsync(cms, Content, trustAnchors: [])).IsNotRevoked.ShouldNotBeNull();
        requests.ShouldBeGreaterThan(0);
    }

    [Fact]
    public async Task ValidateAsync_LevelBelowLongTermData_DoesNotCheckRevocation()
    {
        using var pki = NewPki();
        byte[] cms = await Sign(pki);
        using var http = MockHttpHandler.Failing();
        var validator = new CadesSignatureValidator(
            new ValidationOptions { CheckRevocation = true, TrustSystemRoots = false, Level = ValidationLevel.Timestamps },
            chainRevocationChecker: new ChainRevocationChecker(http));

        var result = await validator.ValidateAsync(cms, Content, [pki.RootCa]);

        result.Indication.ShouldBe(SignatureIndication.Valid);
        result.IsNotRevoked.ShouldBeNull();
    }

    private static CadesSignatureValidator Validator(HttpClient http) =>
        new(new ValidationOptions { CheckRevocation = true, TrustSystemRoots = false },
            chainRevocationChecker: new ChainRevocationChecker(http));

    private static Task<byte[]> Sign(SyntheticPki pki) =>
        CadesSigner.Document(Content).WithCertificate(pki.Leaf, [pki.IntermediateCa]).SignAsync();

    private static SyntheticPki NewPki() =>
        new(crlDistributionPoint: LeafCrlUrl, intermediateCrlDistributionPoint: IntermediateCrlUrl);

    private static HttpClient CrlServer(byte[] leafCrl, byte[] intermediateCrl) =>
        new(new MockHttpHandler(request => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new ByteArrayContent(request.RequestUri!.AbsoluteUri == LeafCrlUrl ? leafCrl : intermediateCrl),
        })));
}
