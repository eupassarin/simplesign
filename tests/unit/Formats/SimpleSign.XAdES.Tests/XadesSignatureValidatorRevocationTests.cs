using System.Net;
using Shouldly;
using SimpleSign.XAdES;
using SimpleSign.Core.Revocation;
using SimpleSign.Core.Validation;
using SimpleSign.TestHelpers;
using Xunit;

namespace SimpleSign.XAdES.Tests;

[Trait("Category", "Unit")]
public sealed class XadesSignatureValidatorRevocationTests
{
    private const string LeafCrlUrl = "http://198.51.100.1/leaf.crl";
    private const string IntermediateCrlUrl = "http://198.51.100.1/intermediate.crl";
    private static readonly byte[] Content = "<doc><a>revocation test</a></doc>"u8.ToArray();

    [Fact]
    public async Task ValidateAsync_ChainNotRevoked_ValidWithChainRevocation()
    {
        using var pki = NewPki();
        byte[] cms = await Sign(pki);
        using var http = CrlServer(pki.BuildLeafCrl(), pki.BuildIntermediateCrl());

        var result = await Validator(http).ValidateAsync(cms, [pki.RootCa]);

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

        var result = await Validator(http).ValidateAsync(cms, [pki.RootCa]);

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

        var result = await Validator(http).ValidateAsync(cms, [pki.RootCa]);

        result.Indication.ShouldBe(SignatureIndication.Indeterminate);
        result.SubIndication.ShouldBe(SignatureSubIndication.CertificateChainGeneralFailure);
    }

    [Fact]
    public async Task ValidateAsync_RevocationOff_NotChecked()
    {
        using var pki = NewPki();
        byte[] cms = await Sign(pki);
        using var http = MockHttpHandler.Failing();
        var validator = new XadesSignatureValidator(
            new ValidationOptions { CheckRevocation = false }, chainRevocationChecker: new ChainRevocationChecker(http));

        var result = await validator.ValidateAsync(cms, [pki.RootCa]);

        result.Indication.ShouldBe(SignatureIndication.Valid);
        result.IsNotRevoked.ShouldBeNull();
    }

    private static XadesSignatureValidator Validator(HttpClient http) =>
        new(new ValidationOptions { CheckRevocation = true, TrustSystemRoots = false },
            chainRevocationChecker: new ChainRevocationChecker(http));

    private static Task<byte[]> Sign(SyntheticPki pki) =>
        XadesSigner.Document(Content).WithCertificate(pki.Leaf, [pki.IntermediateCa]).SignAsync();

    private static SyntheticPki NewPki() =>
        new(crlDistributionPoint: LeafCrlUrl, intermediateCrlDistributionPoint: IntermediateCrlUrl);

    private static HttpClient CrlServer(byte[] leafCrl, byte[] intermediateCrl) =>
        new(new MockHttpHandler(request => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new ByteArrayContent(request.RequestUri!.AbsoluteUri == LeafCrlUrl ? leafCrl : intermediateCrl),
        })));
}
